#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试用例生成系统

功能：
1. 使用 LLM Agent 分析文件功能
2. 生成针对性单元测试
3. 生成安全模糊测试用例
4. 支持 Pytest + 自定义安全断言
"""

import os
import json
import time
from typing import List, Dict, Any, Optional

from utils.config_manager import ConfigManager
from utils.ai_model_client import AIModelManager


class TestCaseGenerator:
    def __init__(self, api_key: Optional[str] = None):
        """
        初始化测试用例生成器
        
        Args:
            api_key: API 密钥
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
        
        self._setup_prompts()
    
    def _setup_prompts(self):
        """
        设置测试用例生成提示词
        """
        # 单元测试生成提示词
        self.unit_test_prompt = """你是高级测试工程师，请为以下代码生成完整的单元测试：

文件路径：{file_path}

代码：
{code_content}

请输出：
1. 完整的 Python 单元测试代码，使用 pytest 框架
2. 测试覆盖主要功能和边界情况
3. 包含适当的测试断言
4. 测试文件名建议：test_{file_name}.py

输出格式：仅输出测试代码，不要包含其他说明"""
        
        # 安全测试生成提示词
        self.security_test_prompt = """你是高级安全测试工程师，请为以下代码生成安全测试用例：

文件路径：{file_path}

代码：
{code_content}

请输出：
1. 针对以下安全漏洞的测试用例：
   - SQL 注入
   - XSS 攻击
   - 命令注入
   - 权限绕过
   - 逻辑炸弹
   - 敏感信息泄露
   - 认证绕过
2. 使用 pytest 框架
3. 包含自定义安全断言
4. 测试文件名建议：test_security_{file_name}.py

输出格式：仅输出测试代码，不要包含其他说明"""
        
        # 模糊测试生成提示词
        self.fuzz_test_prompt = """你是高级安全测试工程师，请为以下代码生成模糊测试用例：

文件路径：{file_path}

代码：
{code_content}

请输出：
1. 使用 pytest-fuzz 或自定义模糊测试框架
2. 针对输入参数的边界情况和异常值
3. 测试代码的健壮性和安全性
4. 测试文件名建议：test_fuzz_{file_name}.py

输出格式：仅输出测试代码，不要包含其他说明"""
    
    def generate_unit_test(self, file_path: str) -> str:
        """
        生成单元测试
        
        Args:
            file_path: 文件路径
            
        Returns:
            测试代码
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            
            # 生成测试代码
            file_name = os.path.basename(file_path)
            base_name = os.path.splitext(file_name)[0]
            
            prompt = self.unit_test_prompt.format(
                code_content=code_content,
                file_path=file_path,
                file_name=base_name
            )
            
            result = self.ai_model_manager.generate(prompt, max_tokens=3000)
            
            if result['success']:
                return result['content']
            else:
                print(f"生成单元测试失败：{result.get('error', 'Unknown error')}")
                return ""
                
        except Exception as e:
            print(f"生成单元测试失败：{e}")
            return ""
    
    def generate_security_test(self, file_path: str) -> str:
        """
        生成安全测试
        
        Args:
            file_path: 文件路径
            
        Returns:
            测试代码
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            
            # 生成测试代码
            file_name = os.path.basename(file_path)
            base_name = os.path.splitext(file_name)[0]
            
            prompt = self.security_test_prompt.format(
                code_content=code_content,
                file_path=file_path,
                file_name=base_name
            )
            
            result = self.ai_model_manager.generate(prompt, max_tokens=4000)
            
            if result['success']:
                return result['content']
            else:
                print(f"生成安全测试失败：{result.get('error', 'Unknown error')}")
                return ""
                
        except Exception as e:
            print(f"生成安全测试失败：{e}")
            return ""
    
    def generate_fuzz_test(self, file_path: str) -> str:
        """
        生成模糊测试
        
        Args:
            file_path: 文件路径
            
        Returns:
            测试代码
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            
            # 生成测试代码
            file_name = os.path.basename(file_path)
            base_name = os.path.splitext(file_name)[0]
            
            prompt = self.fuzz_test_prompt.format(
                code_content=code_content,
                file_path=file_path,
                file_name=base_name
            )
            
            result = self.ai_model_manager.generate(prompt, max_tokens=3000)
            
            if result['success']:
                return result['content']
            else:
                print(f"生成模糊测试失败：{result.get('error', 'Unknown error')}")
                return ""
                
        except Exception as e:
            print(f"生成模糊测试失败：{e}")
            return ""
    
    def generate_all_tests(self, file_path: str, output_dir: Optional[str] = None) -> Dict[str, str]:
        """
        生成所有类型的测试
        
        Args:
            file_path: 文件路径
            output_dir: 输出目录
            
        Returns:
            测试代码字典
        """
        tests = {}
        
        # 生成单元测试
        unit_test = self.generate_unit_test(file_path)
        if unit_test:
            tests['unit_test'] = unit_test
        
        # 生成安全测试
        security_test = self.generate_security_test(file_path)
        if security_test:
            tests['security_test'] = security_test
        
        # 生成模糊测试
        fuzz_test = self.generate_fuzz_test(file_path)
        if fuzz_test:
            tests['fuzz_test'] = fuzz_test
        
        # 保存测试文件
        if output_dir and tests:
            os.makedirs(output_dir, exist_ok=True)
            
            # 生成测试文件名
            file_name = os.path.basename(file_path)
            base_name = os.path.splitext(file_name)[0]
            
            # 保存单元测试
            if 'unit_test' in tests:
                unit_test_path = os.path.join(output_dir, f'test_{base_name}.py')
                with open(unit_test_path, 'w', encoding='utf-8') as f:
                    f.write(tests['unit_test'])
                print(f"单元测试已保存到：{unit_test_path}")
            
            # 保存安全测试
            if 'security_test' in tests:
                security_test_path = os.path.join(output_dir, f'test_security_{base_name}.py')
                with open(security_test_path, 'w', encoding='utf-8') as f:
                    f.write(tests['security_test'])
                print(f"安全测试已保存到：{security_test_path}")
            
            # 保存模糊测试
            if 'fuzz_test' in tests:
                fuzz_test_path = os.path.join(output_dir, f'test_fuzz_{base_name}.py')
                with open(fuzz_test_path, 'w', encoding='utf-8') as f:
                    f.write(tests['fuzz_test'])
                print(f"模糊测试已保存到：{fuzz_test_path}")
        
        return tests
    
    def generate_tests_for_files(self, files: List[str], output_dir: Optional[str] = None) -> Dict[str, Dict[str, str]]:
        """
        为多个文件生成测试
        
        Args:
            files: 文件列表
            output_dir: 输出目录
            
        Returns:
            每个文件的测试代码字典
        """
        all_tests = {}
        
        for file_path in files:
            print(f"为文件生成测试：{file_path}")
            tests = self.generate_all_tests(file_path, output_dir)
            if tests:
                all_tests[file_path] = tests
        
        return all_tests
