#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 模型客户端抽象模块

功能：
1. 提供统一的 AI 模型接口
2. 支持多种 AI 模型（DeepSeek、Claude、OpenAI 等）
3. 集成 LangChain 增强功能
4. 处理 API 调用、错误处理和重试机制
5. 提供标准化的响应格式
"""

import os
import sys
import time
import logging
from typing import Dict, Any, List, Optional, Union
from abc import ABC, abstractmethod

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

from utils.config_manager import ConfigManager
from utils.api_client import ApiClient, ApiResponse, ApiClientFactory
from utils.ai_structured_response_parser import ai_structured_response_parser
from pydantic import BaseModel, Field
from typing import List, Optional

# 导入 LangChain 相关模块
try:
    from langchain_openai import ChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser, JsonOutputParser
    from langchain_core.messages import HumanMessage, SystemMessage
    try:
        from langchain_deepseek import ChatDeepSeek
        logger.info("成功导入 LangChain DeepSeek 模块")
    except ImportError as e:
        logger.warning(f"LangChain DeepSeek 模块导入失败，将使用 OpenAI 作为默认: {e}")
        ChatDeepSeek = None
    LANGCHAIN_AVAILABLE = True
    logger.info("LangChain 模块导入成功")
except ImportError as e:
    logger.warning(f"LangChain 模块未安装，将使用原始 API 调用: {e}")
    LANGCHAIN_AVAILABLE = False


class AIModelError(Exception):
    """AI 模型异常"""
    pass


class SecurityFinding(BaseModel):
    """安全漏洞发现"""
    file: str
    line: int
    severity: str
    category: str
    description: str
    exploit_scenario: str
    recommendation: str
    confidence: float


class AnalysisSummary(BaseModel):
    """分析摘要"""
    files_reviewed: int
    high_severity: int
    medium_severity: int
    low_severity: int
    review_completed: bool


class SecurityAnalysisResult(BaseModel):
    """安全分析结果"""
    findings: List[SecurityFinding]
    analysis_summary: AnalysisSummary


class AIModelClient(ABC):
    """AI 模型客户端抽象基类"""
    
    def __init__(self, config: Dict[str, Any]):
        """初始化 AI 模型客户端
        
        Args:
            config: AI 模型配置
        """
        self.config = config
        self.api_key = config.get('api_key')
        self.model = config.get('model')
        self.timeout = config.get('timeout', 30)
        self.max_tokens = config.get('max_tokens', 2000)
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """生成 AI 响应
        
        Args:
            prompt: 提示词
            **kwargs: 额外参数
            
        Returns:
            生成的响应
        """
        pass
    
    @abstractmethod
    def analyze_security(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """分析代码安全性
        
        Args:
            code: 代码内容
            context: 上下文信息
            
        Returns:
            安全分析结果
        """
        pass
    
    @abstractmethod
    def validate_api_access(self) -> tuple[bool, str]:
        """验证 API 访问
        
        Returns:
            (是否成功, 错误信息)
        """
        pass


class DeepSeekClient(AIModelClient):
    """DeepSeek 模型客户端"""
    
    def __init__(self, config: Dict[str, Any]):
        """初始化 DeepSeek 客户端
        
        Args:
            config: AI 模型配置
        """
        super().__init__(config)
        self.base_url = "https://api.deepseek.com"
        self.client = ApiClientFactory.create_client('authenticated_http', 
                                                  base_url=self.base_url,
                                                  auth_type='api_key',
                                                  auth_credentials=self.api_key)
    
    def generate(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """生成 AI 响应
        
        Args:
            prompt: 提示词
            **kwargs: 额外参数
            
        Returns:
            生成的响应
        """
        max_retries = 3
        base_delay = 0.5
        
        for attempt in range(max_retries):
            try:
                endpoint = "/v1/chat/completions"
                data = {
                    "model": self.model or "deepseek-coder",
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "max_tokens": kwargs.get('max_tokens', self.max_tokens),
                    "temperature": kwargs.get('temperature', 0.2),
                    "top_p": kwargs.get('top_p', 0.95)
                }
                
                # 设置超时
                timeout = kwargs.get('timeout', self.timeout)
                response = self.client.post(endpoint, json=data, timeout=timeout)
                response.raise_for_status()
                result = response.json()
                
                return {
                    "success": True,
                    "content": result['choices'][0]['message']['content'],
                    "usage": result.get('usage', {})
                }
            except Exception as e:
                logger.warning(f"DeepSeek API 调用失败 (尝试 {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.info(f"{delay:.2f} 秒后重试...")
                    time.sleep(delay)
                else:
                    logger.error(f"DeepSeek API 调用失败，已达到最大重试次数: {str(e)}")
                    return {
                        "success": False,
                        "error": str(e)
                    }
    
    def analyze_security(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """分析代码安全性
        
        Args:
            code: 代码内容
            context: 上下文信息
            
        Returns:
            安全分析结果
        """
        prompt = f"""
        你是一个专业的安全代码审查工具，负责分析以下代码的安全问题：

        ```
        {code}
        ```

        请按照以下要求进行分析：
        1. 识别所有潜在的安全漏洞
        2. 对每个漏洞提供严重程度（HIGH、MEDIUM、LOW）
        3. 提供详细的漏洞描述和可能的攻击场景
        4. 提供具体的修复建议
        5. 输出格式为 JSON，包含以下字段：
           - findings: 漏洞列表
           - analysis_summary: 分析摘要

        JSON 输出示例：
        {
          "findings": [
            {
              "file": "path/to/file.py",
              "line": 42,
              "severity": "HIGH",
              "category": "sql_injection",
              "description": "User input passed to SQL query without parameterization",
              "exploit_scenario": "Attacker could extract database contents by manipulating the 'search' parameter",
              "recommendation": "Replace string formatting with parameterized queries",
              "confidence": 0.95
            }
          ],
          "analysis_summary": {
            "files_reviewed": 1,
            "high_severity": 1,
            "medium_severity": 0,
            "low_severity": 0,
            "review_completed": true
          }
        }
        """
        
        result = self.generate(prompt, max_tokens=4000)
        if not result['success']:
            return result
        
        # 使用结构化响应解析器解析
        try:
            analysis_result = ai_structured_response_parser.parse(result['content'], SecurityAnalysisResult)
            return {
                "success": True,
                "analysis": analysis_result.model_dump()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"解析 AI 响应失败: {str(e)}",
                "raw_content": result['content']
            }
    
    def validate_api_access(self) -> tuple[bool, str]:
        """验证 API 访问
        
        Returns:
            (是否成功, 错误信息)
        """
        try:
            test_prompt = "Hello, are you working?"
            result = self.generate(test_prompt, max_tokens=50)
            if result['success']:
                return True, ""
            else:
                return False, result.get('error', 'Unknown error')
        except Exception as e:
            return False, str(e)


class ClaudeClient(AIModelClient):
    """Claude 模型客户端"""
    
    def __init__(self, config: Dict[str, Any]):
        """初始化 Claude 客户端
        
        Args:
            config: AI 模型配置
        """
        super().__init__(config)
        self.base_url = "https://api.anthropic.com"
        self.client = ApiClientFactory.create_client('authenticated_http', 
                                                  base_url=self.base_url,
                                                  auth_type='api_key',
                                                  auth_credentials=self.api_key)
    
    def generate(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """生成 AI 响应
        
        Args:
            prompt: 提示词
            **kwargs: 额外参数
            
        Returns:
            生成的响应
        """
        max_retries = 3
        base_delay = 0.5
        
        for attempt in range(max_retries):
            try:
                endpoint = "/v1/messages"
                data = {
                    "model": self.model or "claude-3-opus-20240229",
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "max_tokens": kwargs.get('max_tokens', self.max_tokens),
                    "temperature": kwargs.get('temperature', 0.2)
                }
                
                headers = {
                    "Content-Type": "application/json",
                    "X-API-Key": self.api_key
                }
                
                # 设置超时
                timeout = kwargs.get('timeout', self.timeout)
                response = self.client.post(endpoint, json=data, headers=headers, timeout=timeout)
                response.raise_for_status()
                result = response.json()
                
                return {
                    "success": True,
                    "content": result['content'][0]['text'],
                    "usage": result.get('usage', {})
                }
            except Exception as e:
                logger.warning(f"Claude API 调用失败 (尝试 {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.info(f"{delay:.2f} 秒后重试...")
                    time.sleep(delay)
                else:
                    logger.error(f"Claude API 调用失败，已达到最大重试次数: {str(e)}")
                    return {
                        "success": False,
                        "error": str(e)
                    }
    
    def analyze_security(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """分析代码安全性
        
        Args:
            code: 代码内容
            context: 上下文信息
            
        Returns:
            安全分析结果
        """
        prompt = f"""
        You are a senior security engineer conducting a focused security review.

        Analyze the following code for security vulnerabilities:

        ```
        {code}
        ```

        Please follow these requirements:
        1. Identify all potential security vulnerabilities
        2. Provide severity for each issue (HIGH, MEDIUM, LOW)
        3. Provide detailed vulnerability descriptions and possible attack scenarios
        4. Provide specific fix recommendations
        5. Output in JSON format with the following structure:
           - findings: list of vulnerabilities
           - analysis_summary: analysis summary

        JSON output example:
        {
          "findings": [
            {
              "file": "path/to/file.py",
              "line": 42,
              "severity": "HIGH",
              "category": "sql_injection",
              "description": "User input passed to SQL query without parameterization",
              "exploit_scenario": "Attacker could extract database contents by manipulating the 'search' parameter",
              "recommendation": "Replace string formatting with parameterized queries",
              "confidence": 0.95
            }
          ],
          "analysis_summary": {
            "files_reviewed": 1,
            "high_severity": 1,
            "medium_severity": 0,
            "low_severity": 0,
            "review_completed": true
          }
        }
        """
        
        result = self.generate(prompt, max_tokens=4000)
        if not result['success']:
            return result
        
        # 使用结构化响应解析器解析
        try:
            analysis_result = ai_structured_response_parser.parse(result['content'], SecurityAnalysisResult)
            return {
                "success": True,
                "analysis": analysis_result.model_dump()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"解析 AI 响应失败: {str(e)}",
                "raw_content": result['content']
            }
    
    def validate_api_access(self) -> tuple[bool, str]:
        """验证 API 访问
        
        Returns:
            (是否成功, 错误信息)
        """
        try:
            test_prompt = "Hello, are you working?"
            result = self.generate(test_prompt, max_tokens=50)
            if result['success']:
                return True, ""
            else:
                return False, result.get('error', 'Unknown error')
        except Exception as e:
            return False, str(e)


class OpenAIClient(AIModelClient):
    """OpenAI 模型客户端"""
    
    def __init__(self, config: Dict[str, Any]):
        """初始化 OpenAI 客户端
        
        Args:
            config: AI 模型配置
        """
        super().__init__(config)
        self.base_url = "https://api.openai.com"
        self.client = ApiClientFactory.create_client('authenticated_http', 
                                                  base_url=self.base_url,
                                                  auth_type='api_key',
                                                  auth_credentials=self.api_key)
    
    def generate(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """生成 AI 响应
        
        Args:
            prompt: 提示词
            **kwargs: 额外参数
            
        Returns:
            生成的响应
        """
        max_retries = 3
        base_delay = 0.5
        
        for attempt in range(max_retries):
            try:
                endpoint = "/v1/chat/completions"
                data = {
                    "model": self.model or "gpt-4",
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "max_tokens": kwargs.get('max_tokens', self.max_tokens),
                    "temperature": kwargs.get('temperature', 0.2),
                    "response_format": kwargs.get('response_format', {"type": "json_object"})
                }
                
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}"
                }
                
                # 设置超时
                timeout = kwargs.get('timeout', self.timeout)
                response = self.client.post(endpoint, json=data, headers=headers, timeout=timeout)
                response.raise_for_status()
                result = response.json()
                
                return {
                    "success": True,
                    "content": result['choices'][0]['message']['content'],
                    "usage": result.get('usage', {})
                }
            except Exception as e:
                logger.warning(f"OpenAI API 调用失败 (尝试 {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.info(f"{delay:.2f} 秒后重试...")
                    time.sleep(delay)
                else:
                    logger.error(f"OpenAI API 调用失败，已达到最大重试次数: {str(e)}")
                    return {
                        "success": False,
                        "error": str(e)
                    }
    
    def analyze_security(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """分析代码安全性
        
        Args:
            code: 代码内容
            context: 上下文信息
            
        Returns:
            安全分析结果
        """
        prompt = f"""
        You are a senior security engineer conducting a focused security review.

        Analyze the following code for security vulnerabilities:

        ```
        {code}
        ```

        Please follow these requirements:
        1. Identify all potential security vulnerabilities
        2. Provide severity for each issue (HIGH, MEDIUM, LOW)
        3. Provide detailed vulnerability descriptions and possible attack scenarios
        4. Provide specific fix recommendations
        5. Output in JSON format with the following structure:
           - findings: list of vulnerabilities
           - analysis_summary: analysis summary

        JSON output example:
        {
          "findings": [
            {
              "file": "path/to/file.py",
              "line": 42,
              "severity": "HIGH",
              "category": "sql_injection",
              "description": "User input passed to SQL query without parameterization",
              "exploit_scenario": "Attacker could extract database contents by manipulating the 'search' parameter",
              "recommendation": "Replace string formatting with parameterized queries",
              "confidence": 0.95
            }
          ],
          "analysis_summary": {
            "files_reviewed": 1,
            "high_severity": 1,
            "medium_severity": 0,
            "low_severity": 0,
            "review_completed": true
          }
        }
        """
        
        result = self.generate(prompt, max_tokens=4000, response_format={"type": "json_object"})
        if not result['success']:
            return result
        
        # 使用结构化响应解析器解析
        try:
            analysis_result = ai_structured_response_parser.parse(result['content'], SecurityAnalysisResult)
            return {
                "success": True,
                "analysis": analysis_result.model_dump()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"解析 AI 响应失败: {str(e)}",
                "raw_content": result['content']
            }
    
    def validate_api_access(self) -> tuple[bool, str]:
        """验证 API 访问
        
        Returns:
            (是否成功, 错误信息)
        """
        try:
            test_prompt = "Hello, are you working?"
            result = self.generate(test_prompt, max_tokens=50)
            if result['success']:
                return True, ""
            else:
                return False, result.get('error', 'Unknown error')
        except Exception as e:
            return False, str(e)


class AIModelClientFactory:
    """AI 模型客户端工厂类"""
    
    @staticmethod
    def create_client(model_type: str, config: Dict[str, Any]) -> AIModelClient:
        """创建 AI 模型客户端
        
        Args:
            model_type: 模型类型 ('deepseek', 'claude', 'openai')
            config: AI 模型配置
            
        Returns:
            AIModelClient: AI 模型客户端实例
        """
        if model_type == 'deepseek':
            return DeepSeekClient(config)
        elif model_type == 'claude':
            return ClaudeClient(config)
        elif model_type == 'openai':
            return OpenAIClient(config)
        else:
            raise ValueError(f"不支持的模型类型: {model_type}")


class AIModelManager:
    """AI 模型管理器"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化 AI 模型管理器
        
        Args:
            config: AI 模型配置
        """
        self.config = config or ConfigManager().get_ai_config()
        self.clients = {}
        self.langchain_clients = {}
    
    def get_client(self, model_type: Optional[str] = None) -> AIModelClient:
        """获取 AI 模型客户端
        
        Args:
            model_type: 模型类型 (可选，默认使用配置中的模型)
            
        Returns:
            AIModelClient: AI 模型客户端实例
        """
        # 获取模型类型，如果没有提供则从配置中获取
        model_type = model_type or self.config.get('model', 'deepseek')
        
        # 提取模型类型（从具体模型名称中）
        if '-' in model_type:
            base_model_type = model_type.split('-')[0]
            if base_model_type in ['deepseek', 'claude', 'openai']:
                model_type_key = base_model_type
            else:
                model_type_key = model_type
        else:
            model_type_key = model_type
        
        # 检查客户端是否已存在
        if model_type_key not in self.clients:
            # 使用基础模型类型创建客户端
            base_model_type = model_type_key.split('-')[0] if '-' in model_type_key else model_type_key
            if base_model_type not in ['deepseek', 'claude', 'openai']:
                base_model_type = 'deepseek'  # 默认使用 deepseek
            
            client = AIModelClientFactory.create_client(base_model_type, self.config)
            self.clients[model_type_key] = client
        
        return self.clients[model_type_key]
    
    def get_langchain_client(self, model_type: Optional[str] = None):
        """获取 LangChain 客户端
        
        Args:
            model_type: 模型类型
            
        Returns:
            LangChain 客户端实例
        """
        if not LANGCHAIN_AVAILABLE:
            return None
        
        model_type = model_type or self.config.get('model', 'deepseek')
        model_type_key = model_type.split('-')[0] if '-' in model_type else model_type
        
        if model_type_key not in self.langchain_clients:
            api_key = self.config.get('api_key')
            model_name = self.config.get('model', 'deepseek-coder')
            
            if model_type_key == 'openai':
                self.langchain_clients[model_type_key] = ChatOpenAI(
                    api_key=api_key,
                    model_name=model_name,
                    temperature=0.2
                )
            elif model_type_key == 'deepseek' and ChatDeepSeek is not None:
                self.langchain_clients[model_type_key] = ChatDeepSeek(
                    api_key=api_key,
                    model_name=model_name,
                    temperature=0.2
                )
            else:
                # 对于其他模型或 ChatDeepSeek 不可用的情况，使用 OpenAI 作为默认
                self.langchain_clients[model_type_key] = ChatOpenAI(
                    api_key=api_key,
                    model_name=model_name,
                    temperature=0.2
                )
        
        return self.langchain_clients[model_type_key]
    
    def analyze_security(self, code: str, model_type: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """分析代码安全性
        
        Args:
            code: 代码内容
            model_type: 模型类型
            context: 上下文信息
            
        Returns:
            安全分析结果
        """
        # 优先使用 LangChain 进行分析
        langchain_client = self.get_langchain_client(model_type)
        if langchain_client:
            try:
                return self._analyze_security_with_langchain(langchain_client, code, context)
            except Exception as e:
                logger.warning(f"LangChain 分析失败，回退到原始 API 调用：{e}")
        
        # 回退到原始 API 调用
        client = self.get_client(model_type)
        return client.analyze_security(code, context)
    
    def _analyze_security_with_langchain(self, langchain_client, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """使用 LangChain 分析代码安全性
        
        Args:
            langchain_client: LangChain 客户端
            code: 代码内容
            context: 上下文信息
            
        Returns:
            安全分析结果
        """
        # 转义代码中的大括号，避免LangChain模板解析错误
        escaped_code = code.replace('{', '{{').replace('}', '}}')
        
        # 创建系统提示
        system_prompt = """你是一个专业的安全代码审查工具，负责分析代码中的安全漏洞。
        请按照以下要求进行分析：
        1. 识别所有潜在的安全漏洞
        2. 对每个漏洞提供严重程度（HIGH、MEDIUM、LOW）
        3. 提供详细的漏洞描述和可能的攻击场景
        4. 提供具体的修复建议
        5. 严格按照JSON格式输出，不要包含任何额外的文本
        6. JSON格式必须包含以下字段：
           - findings: 漏洞列表
           - analysis_summary: 分析摘要
        """
        
        # 创建人类提示
        human_prompt = """请分析以下代码的安全问题，并严格按照JSON格式输出：
        ```
        {escaped_code}
        ```
        
        输出示例：
        {{
          "findings": [
            {{
              "file": "test.py",
              "line": 1,
              "severity": "HIGH",
              "category": "prompt_injection",
              "description": "Prompt injection vulnerability",
              "exploit_scenario": "Attacker can bypass security restrictions",
              "recommendation": "Implement input validation",
              "confidence": 0.9
            }}
          ],
          "analysis_summary": {{
            "files_reviewed": 1,
            "high_severity": 1,
            "medium_severity": 0,
            "low_severity": 0,
            "review_completed": true
          }}
        }}
        """
        
        # 替换转义后的代码
        human_prompt = human_prompt.replace('{escaped_code}', escaped_code)
        
        # 创建提示模板
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", human_prompt)
        ])
        
        # 创建输出解析器
        output_parser = StrOutputParser()
        
        # 创建链
        chain = prompt | langchain_client | output_parser
        
        # 执行分析
        try:
            result = chain.invoke({})
            # 尝试解析JSON
            import json
            try:
                json_result = json.loads(result)
                return {
                    "success": True,
                    "analysis": json_result,
                    "content": result
                }
            except json.JSONDecodeError:
                # 如果不是JSON，返回原始内容
                return {
                    "success": True,
                    "content": result
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"LangChain 分析失败：{str(e)}"
            }
    
    def generate(self, prompt: str, model_type: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """生成 AI 响应
        
        Args:
            prompt: 提示词
            model_type: 模型类型
            **kwargs: 额外参数
            
        Returns:
            生成的响应
        """
        # 优先使用 LangChain 生成响应
        langchain_client = self.get_langchain_client(model_type)
        if langchain_client:
            try:
                logger.info("使用 LangChain 生成响应")
                result = self._generate_with_langchain(langchain_client, prompt, **kwargs)
                # 添加 LangChain 使用标记
                result['langchain_used'] = True
                return result
            except Exception as e:
                logger.warning(f"LangChain 生成失败，回退到原始 API 调用：{e}")
        
        # 回退到原始 API 调用
        logger.info("使用原始 API 调用")
        client = self.get_client(model_type)
        result = client.generate(prompt, **kwargs)
        result['langchain_used'] = False
        return result
    
    def _generate_with_langchain(self, langchain_client, prompt: str, **kwargs) -> Dict[str, Any]:
        """使用 LangChain 生成 AI 响应
        
        Args:
            langchain_client: LangChain 客户端
            prompt: 提示词
            **kwargs: 额外参数
            
        Returns:
            生成的响应
        """
        # 转义提示词中的大括号，避免LangChain模板解析错误
        escaped_prompt = prompt.replace('{', '{{').replace('}', '}}')
        
        # 创建提示模板
        prompt_template = ChatPromptTemplate.from_template(escaped_prompt)
        
        # 创建输出解析器
        output_parser = StrOutputParser()
        
        # 创建链
        chain = prompt_template | langchain_client | output_parser
        
        # 执行生成
        try:
            result = chain.invoke({})
            return {
                "success": True,
                "content": result
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"LangChain 生成失败：{str(e)}"
            }


if __name__ == '__main__':
    # 测试 AI 模型客户端
    print("测试 AI 模型客户端...")
    
    # 加载配置
    config = ConfigManager().get_ai_config()
    
    # 创建 AI 模型管理器
    manager = AIModelManager(config)
    
    # 测试代码
    test_code = """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()
"""
    
    # 测试安全分析
    print("\n测试安全分析:")
    result = manager.analyze_security(test_code)
    if result['success']:
        print("分析成功:")
        print(result['analysis'])
    else:
        print(f"分析失败: {result['error']}")
