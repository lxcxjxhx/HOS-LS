#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI语义引擎 v2.0 (协议修复版)

功能：
1. 分析代码文件中的漏洞（函数级、文件级、项目级）
2. 使用强制JSON协议与AI交互
3. 支持攻击链分析
4. AI输出100%可解析
"""

import os
import json
from typing import List, Dict, Any, Optional, Tuple

from .context_builder import ContextBuilder
from utils.ai_output_models import (
    AIVulnerabilityAnalysis,
    AIAttackChainAnalysis,
    AI_VULNERABILITY_PROMPT_TEMPLATE,
    AI_ATTACK_CHAIN_PROMPT_TEMPLATE
)
from utils.ai_structured_response_parser import ai_structured_response_parser, AIResponseParseError
from utils.config_manager import ConfigManager
from utils.ai_model_client import AIModelManager


class AISemanticEngine:
    """AI语义分析引擎 v2.0"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        初始化AI语义分析引擎
        
        Args:
            api_key: API密钥，如果不提供则使用配置管理器中的配置
        """
        # 使用配置管理器获取AI配置
        config_manager = ConfigManager()
        ai_config = config_manager.get_ai_config()
        
        self.api_key = api_key or ai_config.get('api_key')
        self.model = ai_config.get('model', 'deepseek-chat')
        
        if not self.api_key:
            raise ValueError("API key is required")
        
        # 使用AI模型管理器
        self.ai_model_manager = AIModelManager({
            'api_key': self.api_key,
            'model': self.model
        })
        self.context_builder = ContextBuilder()
    
    def analyze(self, files: List[str]) -> Dict[str, Any]:
        """
        分析代码文件
        
        Args:
            files: 要分析的文件列表
            
        Returns:
            分析结果
        """
        # 构建上下文
        context = self.context_builder.build(files)
        
        # 分层分析
        function_level_results = self._analyze_function_level(files)
        file_level_results = self._analyze_file_level(files)
        project_level_results = self._analyze_project_level(files, context)
        
        return {
            "context": context,
            "function_level": function_level_results,
            "file_level": file_level_results,
            "project_level": project_level_results
        }
    
    def _analyze_function_level(self, files: List[str]) -> List[Dict[str, Any]]:
        """
        函数级分析
        """
        results = []
        for file_path in files:
            if file_path.endswith('.py'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # 简单的函数提取，实际项目中可以使用AST更精确地提取函数
                    functions = self._extract_functions(content)
                    for func_name, func_code in functions.items():
                        # 风险驱动分析：只分析包含危险模式的函数
                        if self._has_danger_patterns(func_code):
                            analysis = self._analyze_function(func_code, func_name, file_path)
                            results.append(analysis)
                except Exception as e:
                    print(f"Error analyzing function level in {file_path}: {e}")
        return results
    
    def _analyze_file_level(self, files: List[str]) -> List[Dict[str, Any]]:
        """
        文件级分析
        """
        results = []
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 风险驱动分析：只分析包含危险模式的文件
                if self._has_danger_patterns(content):
                    analysis = self._analyze_file(content, file_path)
                    results.append(analysis)
            except Exception as e:
                print(f"Error analyzing file level in {file_path}: {e}")
        return results
    
    def _analyze_project_level(self, files: List[str], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        项目级分析
        """
        try:
            # 构建项目级上下文
            project_context = {
                "entry_points": context.get("entry_points", []),
                "danger_calls": context.get("danger_calls", []),
                "data_flow": context.get("data_flow", [])
            }
            
            # 分析攻击链
            attack_chain_analysis = self._analyze_attack_chains(project_context)
            
            return {
                "attack_chains": attack_chain_analysis,
                "overall_risk": self._calculate_overall_risk(attack_chain_analysis)
            }
        except Exception as e:
            print(f"Error analyzing project level: {e}")
            return {"error": str(e)}
    
    def _extract_functions(self, content: str) -> Dict[str, str]:
        """
        提取Python文件中的函数
        """
        import ast
        try:
            tree = ast.parse(content)
            functions = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # 提取函数代码
                    start_line = node.lineno - 1
                    end_line = node.end_lineno
                    lines = content.split('\n')
                    func_code = '\n'.join(lines[start_line:end_line])
                    functions[node.name] = func_code
            return functions
        except Exception:
            return {}
    
    def _has_danger_patterns(self, code: str) -> bool:
        """
        检查代码是否包含危险模式
        """
        danger_patterns = [
            'exec(', 'eval(', 'input(', 'open(',
            'cursor.execute', 'db.execute', 'conn.execute',
            'os.system', 'subprocess', 'shell=True'
        ]
        
        for pattern in danger_patterns:
            if pattern in code:
                return True
        return False
    
    def _analyze_function(self, func_code: str, func_name: str, file_path: str) -> Dict[str, Any]:
        """
        分析单个函数 - 使用强制JSON协议
        """
        try:
            # 构建提示词
            prompt = AI_VULNERABILITY_PROMPT_TEMPLATE.format(
                vulnerability_type="安全漏洞",
                code_context=func_code
            )
            
            # 调用AI
            result = self.ai_model_manager.generate(prompt, max_tokens=2000)
            
            if not result['success']:
                return {
                    "function": func_name,
                    "file": file_path,
                    "error": f"AI调用失败: {result.get('error', 'Unknown error')}",
                    "parsed": False
                }
            
            # 使用结构化解析器解析响应
            parse_success, parsed_result, error_msg = ai_structured_response_parser.parse_strict(
                result['content'], AIVulnerabilityAnalysis
            )
            
            if parse_success:
                return {
                    "function": func_name,
                    "file": file_path,
                    "analysis": parsed_result.dict(),
                    "parsed": True
                }
            else:
                return {
                    "function": func_name,
                    "file": file_path,
                    "error": f"解析失败: {error_msg}",
                    "raw_response": result['content'],
                    "parsed": False
                }
                
        except Exception as e:
            return {
                "function": func_name,
                "file": file_path,
                "error": str(e),
                "parsed": False
            }
    
    def _analyze_file(self, content: str, file_path: str) -> Dict[str, Any]:
        """
        分析单个文件 - 使用强制JSON协议
        """
        try:
            # 构建提示词
            prompt = AI_VULNERABILITY_PROMPT_TEMPLATE.format(
                vulnerability_type="安全漏洞",
                code_context=content[:4000]  # 限制长度
            )
            
            # 调用AI
            result = self.ai_model_manager.generate(prompt, max_tokens=4000)
            
            if not result['success']:
                return {
                    "file": file_path,
                    "error": f"AI调用失败: {result.get('error', 'Unknown error')}",
                    "parsed": False
                }
            
            # 使用结构化解析器解析响应
            parse_success, parsed_result, error_msg = ai_structured_response_parser.parse_strict(
                result['content'], AIVulnerabilityAnalysis
            )
            
            if parse_success:
                return {
                    "file": file_path,
                    "analysis": parsed_result.dict(),
                    "parsed": True
                }
            else:
                return {
                    "file": file_path,
                    "error": f"解析失败: {error_msg}",
                    "raw_response": result['content'],
                    "parsed": False
                }
                
        except Exception as e:
            return {
                "file": file_path,
                "error": str(e),
                "parsed": False
            }
    
    def _analyze_attack_chains(self, project_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        分析攻击链 - 使用强制JSON协议
        """
        try:
            entry_points_str = json.dumps(project_context.get("entry_points", []), ensure_ascii=False)
            danger_calls_str = json.dumps(project_context.get("danger_calls", []), ensure_ascii=False)
            
            # 构建提示词
            prompt = AI_ATTACK_CHAIN_PROMPT_TEMPLATE.format(
                code_context="Project code analysis",
                entry_points=entry_points_str,
                danger_calls=danger_calls_str
            )
            
            # 调用AI
            result = self.ai_model_manager.generate(prompt, max_tokens=2000)
            
            if not result['success']:
                print(f"攻击链分析失败: {result.get('error', 'Unknown error')}")
                return []
            
            # 使用结构化解析器解析响应
            parse_success, parsed_result, error_msg = ai_structured_response_parser.parse_strict(
                result['content'], AIAttackChainAnalysis
            )
            
            if parse_success:
                return [chain.dict() for chain in parsed_result.attack_chains]
            else:
                print(f"攻击链解析失败: {error_msg}")
                return []
                
        except Exception as e:
            print(f"Error analyzing attack chains: {e}")
            return []
    
    def _calculate_overall_risk(self, attack_chains: List[Dict[str, Any]]) -> str:
        """
        计算整体风险等级
        """
        if not attack_chains:
            return "Low"
        
        high_risk_count = sum(1 for chain in attack_chains if chain.get("risk", "").lower() == "high")
        medium_risk_count = sum(1 for chain in attack_chains if chain.get("risk", "").lower() == "medium")
        
        if high_risk_count > 0:
            return "High"
        elif medium_risk_count > 0:
            return "Medium"
        else:
            return "Low"
