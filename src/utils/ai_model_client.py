#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 模型客户端抽象模块

功能：
1. 提供统一的 AI 模型接口
2. 支持多种 AI 模型（DeepSeek、Claude、OpenAI 等）
3. 处理 API 调用、错误处理和重试机制
4. 提供标准化的响应格式
"""

import os
import sys
import time
import logging
from typing import Dict, Any, List, Optional, Union
from abc import ABC, abstractmethod

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config_manager import ConfigManager
from utils.api_client import ApiClient, ApiResponse, ApiClientFactory
from utils.ai_structured_response_parser import ai_structured_response_parser
from pydantic import BaseModel, Field
from typing import List, Optional

logger = logging.getLogger(__name__)


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
            
            response = self.client.post(endpoint, json=data)
            response.raise_for_status()
            result = response.json()
            
            return {
                "success": True,
                "content": result['choices'][0]['message']['content'],
                "usage": result.get('usage', {})
            }
        except Exception as e:
            logger.error(f"DeepSeek API 调用失败: {str(e)}")
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
            
            response = self.client.post(endpoint, json=data, headers=headers)
            response.raise_for_status()
            result = response.json()
            
            return {
                "success": True,
                "content": result['content'][0]['text'],
                "usage": result.get('usage', {})
            }
        except Exception as e:
            logger.error(f"Claude API 调用失败: {str(e)}")
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
            
            response = self.client.post(endpoint, json=data, headers=headers)
            response.raise_for_status()
            result = response.json()
            
            return {
                "success": True,
                "content": result['choices'][0]['message']['content'],
                "usage": result.get('usage', {})
            }
        except Exception as e:
            logger.error(f"OpenAI API 调用失败: {str(e)}")
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
    
    def analyze_security(self, code: str, model_type: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """分析代码安全性
        
        Args:
            code: 代码内容
            model_type: 模型类型
            context: 上下文信息
            
        Returns:
            安全分析结果
        """
        client = self.get_client(model_type)
        return client.analyze_security(code, context)
    
    def generate(self, prompt: str, model_type: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """生成 AI 响应
        
        Args:
            prompt: 提示词
            model_type: 模型类型
            **kwargs: 额外参数
            
        Returns:
            生成的响应
        """
        client = self.get_client(model_type)
        return client.generate(prompt, **kwargs)


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
