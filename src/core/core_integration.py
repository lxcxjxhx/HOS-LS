#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
核心技术集成模块

功能：
1. 集成LLM能力
2. 实现Embedding
3. 优化AST解析
4. 增强污点分析
"""

import os
import re
import json
import logging
import requests
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class LLMResponse:
    """LLM响应"""
    content: str
    model: str
    token_count: int
    response_time: float
    error: Optional[str] = None

@dataclass
class EmbeddingResult:
    """Embedding结果"""
    embedding: List[float]
    model: str
    token_count: int
    response_time: float

class CoreIntegration:
    """核心技术集成"""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "deepseek-chat"):
        """初始化核心技术集成
        
        Args:
            api_key: API密钥
            model: 模型名称
        """
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY")
        self.model = model
        self.base_url = "https://api.deepseek.com/v1"
        
    def call_llm(self, prompt: str, temperature: float = 0.7, max_tokens: int = 1000) -> LLMResponse:
        """调用LLM
        
        Args:
            prompt: 提示词
            temperature: 温度参数
            max_tokens: 最大 token 数
            
        Returns:
            LLMResponse: LLM响应
        """
        import time
        start_time = time.time()
        
        if not self.api_key:
            return LLMResponse(
                content="",
                model=self.model,
                token_count=0,
                response_time=time.time() - start_time,
                error="API key not provided"
            )
        
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            data = {
                "model": self.model,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=data,
                timeout=30
            )
            
            response.raise_for_status()
            result = response.json()
            
            content = result["choices"][0]["message"]["content"]
            token_count = result.get("usage", {}).get("total_tokens", 0)
            
            return LLMResponse(
                content=content,
                model=self.model,
                token_count=token_count,
                response_time=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"LLM调用失败：{e}")
            return LLMResponse(
                content="",
                model=self.model,
                token_count=0,
                response_time=time.time() - start_time,
                error=str(e)
            )
    
    def generate_embedding(self, text: str, model: str = "deepseek-embed") -> EmbeddingResult:
        """生成Embedding
        
        Args:
            text: 文本
            model: 模型名称
            
        Returns:
            EmbeddingResult: Embedding结果
        """
        import time
        start_time = time.time()
        
        if not self.api_key:
            return EmbeddingResult(
                embedding=[],
                model=model,
                token_count=0,
                response_time=time.time() - start_time
            )
        
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            data = {
                "model": model,
                "input": text
            }
            
            response = requests.post(
                f"{self.base_url}/embeddings",
                headers=headers,
                json=data,
                timeout=30
            )
            
            response.raise_for_status()
            result = response.json()
            
            embedding = result["data"][0]["embedding"]
            token_count = result.get("usage", {}).get("total_tokens", 0)
            
            return EmbeddingResult(
                embedding=embedding,
                model=model,
                token_count=token_count,
                response_time=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Embedding生成失败：{e}")
            return EmbeddingResult(
                embedding=[],
                model=model,
                token_count=0,
                response_time=time.time() - start_time
            )
    
    def optimize_ast_parsing(self, code: str) -> Dict[str, Any]:
        """优化AST解析
        
        Args:
            code: 代码内容
            
        Returns:
            Dict[str, Any]: 优化后的AST解析结果
        """
        try:
            import ast
            
            # 解析代码
            tree = ast.parse(code)
            
            # 提取函数定义
            functions = []
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    function_info = {
                        'name': node.name,
                        'args': [arg.arg for arg in node.args.args],
                        'line_number': node.lineno,
                        'docstring': ast.get_docstring(node)
                    }
                    functions.append(function_info)
            
            # 提取类定义
            classes = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_info = {
                        'name': node.name,
                        'bases': [base.id for base in node.bases if isinstance(base, ast.Name)],
                        'line_number': node.lineno,
                        'docstring': ast.get_docstring(node)
                    }
                    classes.append(class_info)
            
            # 提取导入
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append({
                            'type': 'import',
                            'module': alias.name,
                            'alias': alias.asname
                        })
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        imports.append({
                            'type': 'from_import',
                            'module': node.module,
                            'name': alias.name,
                            'alias': alias.asname
                        })
            
            # 提取危险函数调用
            dangerous_calls = []
            dangerous_functions = [
                'eval', 'exec', 'execfile', 'input', 'raw_input',
                'os.system', 'os.popen', 'subprocess.call', 'subprocess.run',
                'subprocess.Popen', 'open', 'file', 'compile'
            ]
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in dangerous_functions:
                        dangerous_calls.append({
                            'function': node.func.id,
                            'line_number': node.lineno
                        })
                    elif isinstance(node.func, ast.Attribute):
                        full_name = f"{node.func.value.id}.{node.func.attr}"
                        if full_name in dangerous_functions:
                            dangerous_calls.append({
                                'function': full_name,
                                'line_number': node.lineno
                            })
            
            return {
                'functions': functions,
                'classes': classes,
                'imports': imports,
                'dangerous_calls': dangerous_calls
            }
            
        except Exception as e:
            logger.error(f"AST解析失败：{e}")
            return {
                'functions': [],
                'classes': [],
                'imports': [],
                'dangerous_calls': []
            }
    
    def enhance_taint_analysis(self, code: str) -> List[Dict[str, Any]]:
        """增强污点分析
        
        Args:
            code: 代码内容
            
        Returns:
            List[Dict[str, Any]]: 污点分析结果
        """
        try:
            import ast
            
            # 解析代码
            tree = ast.parse(code)
            
            # 污点分析结果
            taint_issues = []
            
            # 追踪用户输入
            user_input_sources = {
                'input': 'input()',
                'raw_input': 'raw_input()',
                'sys.stdin.read': 'sys.stdin.read()',
                'request.get': 'request.get()',
                'request.post': 'request.post()',
                'argv': 'sys.argv',
                'form': 'request.form',
                'args': 'request.args',
                'cookies': 'request.cookies',
                'headers': 'request.headers',
                'json': 'request.json'
            }
            
            # 危险函数
            dangerous_sinks = {
                'eval': 'eval()',
                'exec': 'exec()',
                'execfile': 'execfile()',
                'compile': 'compile()',
                'os.system': 'os.system()',
                'os.popen': 'os.popen()',
                'subprocess.call': 'subprocess.call()',
                'subprocess.run': 'subprocess.run()',
                'subprocess.Popen': 'subprocess.Popen()',
                'open': 'open()',
                'file': 'file()',
                'socket.connect': 'socket.connect()'
            }
            
            # 变量追踪
            variable_taints = {}
            
            class TaintAnalyzer(ast.NodeVisitor):
                def visit_Assign(self, node):
                    # 检查赋值语句
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            # 检查是否是用户输入
                            if isinstance(node.value, ast.Call):
                                if isinstance(node.value.func, ast.Name) and node.value.func.id in user_input_sources:
                                    variable_taints[target.id] = {
                                        'source': user_input_sources[node.value.func.id],
                                        'line': node.lineno
                                    }
                                elif isinstance(node.value.func, ast.Attribute):
                                    attr_name = f"{node.value.func.value.id}.{node.value.func.attr}"
                                    if attr_name in user_input_sources:
                                        variable_taints[target.id] = {
                                            'source': user_input_sources[attr_name],
                                            'line': node.lineno
                                        }
                            # 检查是否是已污染的变量
                            elif isinstance(node.value, ast.Name) and node.value.id in variable_taints:
                                variable_taints[target.id] = variable_taints[node.value.id]
                    self.generic_visit(node)
                
                def visit_Call(self, node):
                    # 检查函数调用
                    # 检查函数是否是危险函数
                    if isinstance(node.func, ast.Name) and node.func.id in dangerous_sinks:
                        # 检查参数是否被污染
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id in variable_taints:
                                taint_issues.append({
                                    'type': 'taint_analysis',
                                    'severity': 'high',
                                    'message': f"Potential taint vulnerability: {variable_taints[arg.id]['source']} -> {dangerous_sinks[node.func.id]}",
                                    'source_line': variable_taints[arg.id]['line'],
                                    'sink_line': node.lineno,
                                    'taint_chain': [variable_taints[arg.id]['source'], dangerous_sinks[node.func.id]]
                                })
                    elif isinstance(node.func, ast.Attribute):
                        attr_name = f"{node.func.value.id}.{node.func.attr}"
                        if attr_name in dangerous_sinks:
                            # 检查参数是否被污染
                            for arg in node.args:
                                if isinstance(arg, ast.Name) and arg.id in variable_taints:
                                    taint_issues.append({
                                        'type': 'taint_analysis',
                                        'severity': 'high',
                                        'message': f"Potential taint vulnerability: {variable_taints[arg.id]['source']} -> {dangerous_sinks[attr_name]}",
                                        'source_line': variable_taints[arg.id]['line'],
                                        'sink_line': node.lineno,
                                        'taint_chain': [variable_taints[arg.id]['source'], dangerous_sinks[attr_name]]
                                    })
                    self.generic_visit(node)
            
            # 执行污点分析
            analyzer = TaintAnalyzer()
            analyzer.visit(tree)
            
            return taint_issues
            
        except Exception as e:
            logger.error(f"污点分析失败：{e}")
            return []

if __name__ == '__main__':
    # 测试核心技术集成
    integration = CoreIntegration()
    
    # 测试LLM调用
    print("测试LLM调用...")
    response = integration.call_llm("What is SQL injection?")
    print(f"LLM响应: {response.content[:100]}...")
    print(f"响应时间: {response.response_time:.2f}秒")
    
    # 测试Embedding生成
    print("\n测试Embedding生成...")
    embedding = integration.generate_embedding("SQL injection is a code injection technique")
    print(f"Embedding维度: {len(embedding.embedding)}")
    print(f"响应时间: {embedding.response_time:.2f}秒")
    
    # 测试AST解析优化
    print("\n测试AST解析优化...")
    test_code = """
def vulnerable_function(user_input):
    eval(user_input)
    
class TestClass:
    def __init__(self):
        pass
"""
    ast_result = integration.optimize_ast_parsing(test_code)
    print(f"函数数量: {len(ast_result['functions'])}")
    print(f"类数量: {len(ast_result['classes'])}")
    print(f"危险函数调用: {len(ast_result['dangerous_calls'])}")
    
    # 测试污点分析增强
    print("\n测试污点分析增强...")
    taint_code = """
def vulnerable_function():
    user_input = input("Enter something: ")
    eval(user_input)
"""
    taint_result = integration.enhance_taint_analysis(taint_code)
    print(f"污点分析问题: {len(taint_result)}")
    for issue in taint_result:
        print(f"  - {issue['message']}")
