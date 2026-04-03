#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AST 分析检测模块

功能：
1. 使用 Python AST 模块解析代码
2. 识别危险函数调用
3. 追踪数据流
4. 检测变量赋值和使用
5. 提供比正则更精确的检测
6. 构建语义图
7. 支持 AgentFlow 框架语义节点
"""

import ast
import os
import logging
from typing import List, Dict, Any, Optional

from scanners.semantic_graph import semantic_graph_builder

logger = logging.getLogger(__name__)


class SecurityVisitor(ast.NodeVisitor):
    """AST 安全访问者"""
    
    def __init__(self, filename: str, source_code: str):
        self.filename = filename
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.issues = []
        self.dangerous_functions = {
            'eval': '使用 eval() 可能导致代码注入',
            'exec': '使用 exec() 可能导致代码注入',
            'compile': '使用 compile() 可能执行动态代码',
            'open': '文件操作需要验证路径',
            'input': '用户输入需要验证',
            '__import__': '动态导入可能存在风险',
        }
        self.dangerous_methods = {
            'system': 'os.system() 可能执行系统命令',
            'popen': 'os.popen() 可能执行系统命令',
            'spawn': 'os.spawn* 可能执行系统命令',
            'call': 'subprocess.call 可能执行系统命令',
            'run': 'subprocess.run 可能执行系统命令',
            'Popen': 'subprocess.Popen 可能执行系统命令',
            'load': 'pickle.load 可能反序列化恶意数据',
            'loads': 'pickle.loads 可能反序列化恶意数据',
        }
        self.dangerous_modules = ['pickle', 'marshal', 'shelve', 'commands']
        self.ai_sensitive_patterns = {
            'prompt': '提示词处理需要验证',
            'user_input': '用户输入需要验证',
            'chat_input': '聊天输入需要验证',
            'query': '查询输入需要验证',
            'user_message': '用户消息需要验证',
        }
        self.data_flow = {}
        self.variable_assignments = {}
        self.function_definitions = {}
        self.class_definitions = {}
        self.imports = []
        self.business_logic_issues = []
        self.access_control_issues = []
        self.control_flow = []
        self.sensitive_data_flow = []
    
    def visit_Call(self, node):
        """访问函数调用节点"""
        # 检查危险函数
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.dangerous_functions:
                self._report_issue(
                    node.lineno,
                    'HIGH' if func_name in ['eval', 'exec', 'compile'] else 'MEDIUM',
                    f"危险函数调用：{func_name}()",
                    self.dangerous_functions[func_name],
                    self._get_code_snippet(node.lineno)
                )
            
            # 检查输入函数
            if func_name == 'input':
                # 检查是否有验证
                if not self._has_validation_nearby(node.lineno):
                    self._report_issue(
                        node.lineno,
                        'MEDIUM',
                        '用户输入缺少验证',
                        'input() 获取的用户输入应该进行验证和过滤',
                        self._get_code_snippet(node.lineno)
                    )
        
        # 检查危险方法调用
        elif isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            
            # 检查 os.system, os.popen 等
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                if module_name in ['os', 'subprocess', 'pickle', 'marshal', 'commands']:
                    if method_name in self.dangerous_methods:
                        # 特殊检查：subprocess 的 shell=True
                        if method_name in ['call', 'run', 'Popen']:
                            if self._has_shell_true(node):
                                self._report_issue(
                                    node.lineno,
                                    'HIGH',
                                    f'危险方法调用：{module_name}.{method_name}() with shell=True',
                                    'subprocess 使用 shell=True 可能导致命令注入',
                                    self._get_code_snippet(node.lineno)
                                )
                        else:
                            self._report_issue(
                                node.lineno,
                                'HIGH' if module_name in ['os', 'commands'] else 'MEDIUM',
                                f'危险方法调用：{module_name}.{method_name}()',
                                self.dangerous_methods[method_name],
                                self._get_code_snippet(node.lineno)
                            )
            
            # 检查 requests 调用
            if method_name in ['get', 'post', 'put', 'delete', 'patch', 'request']:
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'requests':
                    # 检查是否有 timeout 和 verify
                    has_timeout = any(
                        isinstance(kw, ast.keyword) and kw.arg == 'timeout'
                        for kw in node.keywords
                    )
                    has_verify = any(
                        isinstance(kw, ast.keyword) and kw.arg == 'verify'
                        for kw in node.keywords
                    )
                    
                    if not has_timeout:
                        self._report_issue(
                            node.lineno,
                            'LOW',
                            '网络请求缺少超时设置',
                            'requests 请求应该设置 timeout 参数',
                            self._get_code_snippet(node.lineno)
                        )
                    
                    if not has_verify:
                        self._report_issue(
                            node.lineno,
                            'MEDIUM',
                            '网络请求缺少 SSL 验证',
                            'requests 请求应该设置 verify=True',
                            self._get_code_snippet(node.lineno)
                        )
        
        self.generic_visit(node)
    
    def visit_Import(self, node):
        """访问导入语句"""
        for alias in node.names:
            self.imports.append({
                'module': alias.name,
                'alias': alias.asname,
                'lineno': node.lineno
            })
            if alias.name in self.dangerous_modules:
                self._report_issue(
                    node.lineno,
                    'MEDIUM',
                    f'导入危险模块：{alias.name}',
                    f'{alias.name} 模块可能带来安全风险，请谨慎使用',
                    self._get_code_snippet(node.lineno)
                )
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """访问 from 导入语句"""
        self.imports.append({
            'module': node.module,
            'names': [n.name for n in node.names],
            'lineno': node.lineno
        })
        if node.module in self.dangerous_modules:
            self._report_issue(
                node.lineno,
                'MEDIUM',
                f'从危险模块导入：{node.module}',
                f'{node.module} 模块可能带来安全风险',
                self._get_code_snippet(node.lineno)
            )
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node):
        """访问函数定义"""
        self.function_definitions[node.name] = {
            'lineno': node.lineno,
            'args': [arg.arg for arg in node.args.args],
            'defaults': len(node.args.defaults),
            'body': node.body
        }
        # 检查函数参数中的敏感信息
        for arg in node.args.args:
            arg_name = arg.arg.lower()
            if any(pattern in arg_name for pattern in self.ai_sensitive_patterns.keys()):
                self._report_issue(
                    node.lineno,
                    'MEDIUM',
                    f'函数参数包含敏感输入：{arg.arg}',
                    '敏感输入参数需要验证和过滤',
                    self._get_code_snippet(node.lineno)
                )
        self.generic_visit(node)
    
    def visit_ClassDef(self, node):
        """访问类定义"""
        self.class_definitions[node.name] = {
            'lineno': node.lineno,
            'bases': [base.id for base in node.bases if isinstance(base, ast.Name)],
            'body': node.body
        }
        self.generic_visit(node)
    
    def visit_Assign(self, node):
        """访问赋值语句"""
        # 检查敏感信息赋值
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                # 检查敏感变量名
                if any(secret in var_name for secret in ['password', 'passwd', 'pwd', 'secret', 'api_key', 'token', 'private_key']):
                    # 检查是否是字符串字面量赋值
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        # 排除示例和占位符
                        value = node.value.value
                        if not self._is_placeholder(value):
                            self._report_issue(
                                node.lineno,
                                'HIGH',
                                f'硬编码敏感信息：{target.id}',
                                '敏感信息应该存储在环境变量或配置文件中',
                                self._get_code_snippet(node.lineno)
                            )
                # 检查AI相关变量
                elif any(pattern in var_name for pattern in self.ai_sensitive_patterns.keys()):
                    # 记录变量赋值
                    self.variable_assignments[target.id] = {
                        'value': node.value,
                        'lineno': node.lineno
                    }
                    # 检查是否有验证
                    if not self._has_validation_nearby(node.lineno):
                        self._report_issue(
                            node.lineno,
                            'MEDIUM',
                            f'AI输入变量缺少验证：{target.id}',
                            'AI输入应该进行验证和过滤',
                            self._get_code_snippet(node.lineno)
                        )
        self.generic_visit(node)
    

    
    def visit_BinOp(self, node):
        """访问二元操作（检测字符串拼接）"""
        # 检查 SQL 查询拼接
        if isinstance(node.op, (ast.Add, ast.Mod)):
            if self._is_sql_query(node):
                self._report_issue(
                    node.lineno,
                    'HIGH',
                    'SQL 查询字符串拼接',
                    '使用参数化查询替代字符串拼接',
                    self._get_code_snippet(node.lineno)
                )
            # 检查提示词拼接
            elif self._is_prompt_concatenation(node):
                self._report_issue(
                    node.lineno,
                    'HIGH',
                    '提示词拼接风险',
                    '避免直接拼接用户输入到提示词，使用模板或隔离上下文',
                    self._get_code_snippet(node.lineno)
                )
        self.generic_visit(node)
    
    def visit_Subscript(self, node):
        """访问下标操作（检测字典访问）"""
        # 检查敏感配置访问
        if isinstance(node.value, ast.Name) and node.value.id.lower() in ['config', 'settings', 'env']:
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                key = node.slice.value.lower()
                if any(secret in key for secret in ['password', 'passwd', 'pwd', 'secret', 'api_key', 'token', 'private_key']):
                    self._report_issue(
                        node.lineno,
                        'MEDIUM',
                        '敏感配置访问',
                        '敏感配置应该通过安全的方式访问',
                        self._get_code_snippet(node.lineno)
                    )
        self.generic_visit(node)
    
    def _is_sql_query(self, node) -> bool:
        """检查是否是 SQL 查询"""
        # 检查左操作数是否包含 SQL 关键字
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE']
            return any(kw in node.left.value.upper() for kw in sql_keywords)
        return False
    
    def _is_prompt_concatenation(self, node) -> bool:
        """检查是否是提示词拼接"""
        # 检查是否包含提示词相关的变量
        prompt_patterns = ['prompt', 'system_prompt', 'base_prompt', 'user_input', 'chat_input', 'query']
        
        # 检查左操作数
        if isinstance(node.left, ast.Name):
            if any(pattern in node.left.id.lower() for pattern in prompt_patterns):
                return True
        elif isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            if any(pattern in node.left.value.lower() for pattern in prompt_patterns):
                return True
        
        # 检查右操作数
        if isinstance(node.right, ast.Name):
            if any(pattern in node.right.id.lower() for pattern in prompt_patterns):
                return True
        elif isinstance(node.right, ast.Constant) and isinstance(node.right.value, str):
            if any(pattern in node.right.value.lower() for pattern in prompt_patterns):
                return True
        
        return False
    
    def _has_shell_true(self, node) -> bool:
        """检查 subprocess 调用是否有 shell=True"""
        for kw in node.keywords:
            if kw.arg == 'shell':
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
                elif isinstance(kw.value, ast.Name) and kw.value.id == 'True':
                    return True
        return False
    
    def _has_validation_nearby(self, lineno: int) -> bool:
        """检查附近是否有验证代码"""
        start = max(0, lineno - 5)
        end = min(len(self.source_lines), lineno + 5)
        context = '\n'.join(self.source_lines[start:end])
        
        validation_patterns = [
            'validate', 'check', 'verify', 'sanitize', 'filter',
            'if len', 'isinstance', 'try:', 'except'
        ]
        
        return any(pattern in context.lower() for pattern in validation_patterns)
    
    def _is_placeholder(self, value: str) -> bool:
        """检查是否是占位符值"""
        placeholders = [
            'your_', 'example', 'placeholder', 'xxx', 'change_me',
            'todo', 'fixme', 'test', 'demo', 'sample'
        ]
        return any(p in value.lower() for p in placeholders)
    
    def _get_code_snippet(self, lineno: int) -> str:
        """获取代码片段"""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ''
    
    def _report_issue(self, lineno: int, severity: str, issue: str, 
                     details: str, code_snippet: str):
        """报告问题"""
        self.issues.append({
            'line_number': lineno,
            'severity': severity,
            'issue': issue,
            'details': details,
            'code_snippet': code_snippet,
            'category': 'ast_analysis'
        })
    
    def _track_data_flow(self, node, variable_name, value):
        """追踪数据流"""
        if variable_name not in self.data_flow:
            self.data_flow[variable_name] = []
        
        self.data_flow[variable_name].append({
            'lineno': node.lineno,
            'value': value,
            'type': type(node).__name__
        })
    
    def _analyze_business_logic(self):
        """分析业务逻辑漏洞"""
        # 检查认证绕过
        for func_name, func_info in self.function_definitions.items():
            func_body = func_info['body']
            for node in ast.walk(ast.Module(body=func_body)):
                if isinstance(node, ast.If):
                    # 检查简单的认证绕过
                    if self._is_auth_bypass(node):
                        self._report_issue(
                            node.lineno,
                            'HIGH',
                            '认证绕过风险',
                            '检测到可能的认证绕过逻辑',
                            self._get_code_snippet(node.lineno)
                        )
    
    def _is_auth_bypass(self, node) -> bool:
        """检查是否存在认证绕过"""
        if not isinstance(node.test, ast.Compare):
            return False
        
        # 检查常见的认证绕过模式
        auth_patterns = ['auth', 'authenticated', 'logged_in', 'user_id', 'session']
        
        # 检查条件是否过于宽松
        if isinstance(node.test, ast.Compare):
            # 检查是否使用了简单的字符串比较
            if isinstance(node.test.left, ast.Name):
                if any(pattern in node.test.left.id.lower() for pattern in auth_patterns):
                    # 检查是否使用了 == '' 或类似的宽松条件
                    if isinstance(node.test.comparators[0], ast.Constant):
                        if node.test.comparators[0].value in ['', None, False]:
                            return True
        
        return False
    
    def _analyze_access_control(self):
        """分析访问控制缺陷"""
        # 检查权限检查缺失
        for func_name, func_info in self.function_definitions.items():
            # 检查常见的需要权限控制的函数
            protected_funcs = ['admin', 'delete', 'update', 'create', 'modify']
            if any(pattern in func_name.lower() for pattern in protected_funcs):
                # 检查函数体内是否有权限检查
                if not self._has_permission_check(func_info['body']):
                    self._report_issue(
                        func_info['lineno'],
                        'HIGH',
                        '访问控制缺失',
                        f'函数 {func_name} 可能缺少权限检查',
                        self._get_code_snippet(func_info['lineno'])
                    )
    
    def _has_permission_check(self, body) -> bool:
        """检查是否有权限检查"""
        permission_patterns = ['check_permission', 'has_permission', 'require_permission', 'is_admin', 'role']
        
        for node in ast.walk(ast.Module(body=body)):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if any(pattern in node.func.id.lower() for pattern in permission_patterns):
                        return True
                elif isinstance(node.func, ast.Attribute):
                    if any(pattern in node.func.attr.lower() for pattern in permission_patterns):
                        return True
        
        return False
    
    def _analyze_sensitive_data_flow(self):
        """分析敏感数据流"""
        # 检查敏感数据是否被泄露
        for var_name, assignments in self.variable_assignments.items():
            if any(secret in var_name.lower() for secret in ['password', 'secret', 'api_key', 'token']):
                # 检查变量是否被打印或记录
                for node in ast.walk(ast.parse(self.source_code)):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name) and node.func.id in ['print', 'logging.info', 'logging.debug', 'logging.warning']:
                            for arg in node.args:
                                if isinstance(arg, ast.Name) and arg.id == var_name:
                                    self._report_issue(
                                        node.lineno,
                                        'HIGH',
                                        '敏感信息泄露',
                                        f'敏感变量 {var_name} 被记录或打印',
                                        self._get_code_snippet(node.lineno)
                                    )
    
    def analyze(self):
        """执行完整分析"""
        # 分析业务逻辑
        self._analyze_business_logic()
        # 分析访问控制
        self._analyze_access_control()
        # 分析敏感数据流
        self._analyze_sensitive_data_flow()


def safe_parse(source_code: str) -> Optional[ast.AST]:
    """安全解析 Python 代码
    
    Args:
        source_code: 源代码
        
    Returns:
        Optional[ast.AST]: 解析后的 AST，如果失败返回 None
    """
    try:
        return ast.parse(source_code)
    except SyntaxError:
        return None


def is_valid_python_code(source_code: str) -> bool:
    """检查代码是否是有效的 Python 代码
    
    Args:
        source_code: 源代码
        
    Returns:
        bool: 是否是有效的 Python 代码
    """
    # 检查是否为空
    if not source_code or not source_code.strip():
        return False
    
    # 检查是否包含明显的非 Python 代码特征
    stripped = source_code.strip()
    
    # 跳过 HTML/XML
    if stripped.startswith('<') and not stripped.startswith('<' * 10):  # 允许 <<< 这样的 Python 操作符
        return False
    
    # 跳过 JSON
    if stripped.startswith('{') and '"' in stripped[:100]:
        try:
            import json
            json.loads(stripped)
            return False  # 是有效的 JSON
        except:
            pass
    
    # 跳过 JavaScript/TypeScript 文件内容（简单启发式）
    js_patterns = [
        'function ',
        'const ',
        'let ',
        'var ',
        '=> {',
        'export default',
        'import {',
        'require(',
    ]
    first_lines = '\n'.join(stripped.split('\n')[:10])
    if any(pattern in first_lines for pattern in js_patterns):
        return False
    
    return True


class ASTScanner:
    """AST 扫描器类"""
    
    def __init__(self):
        self.results = []
        self.semantic_graph = None
        self.stats = {
            'files_scanned': 0,
            'files_skipped': 0,
            'parse_errors': 0,
            'issues_found': 0
        }
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """扫描单个文件"""
        try:
            # 检查文件类型，支持 Python 和 TypeScript 文件
            supported_extensions = ['.py', '.ts', '.js']
            if not any(file_path.endswith(ext) for ext in supported_extensions):
                logger.debug(f"跳过不支持的文件类型: {file_path}")
                self.stats['files_skipped'] += 1
                return []
                
            # 检查文件是否存在且可读
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                logger.debug(f"文件不存在或不是文件: {file_path}")
                self.stats['files_skipped'] += 1
                return []
                
            # 检查文件大小，避免处理过大的文件
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB
                logger.debug(f"文件过大，跳过: {file_path} ({file_size / 1024 / 1024:.2f}MB)")
                self.stats['files_skipped'] += 1
                return []
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            
            # 检查文件内容是否为空
            if not source_code.strip():
                logger.debug(f"文件内容为空: {file_path}")
                self.stats['files_skipped'] += 1
                return []
            
            self.stats['files_scanned'] += 1
            
            issues = []
            
            # 对于 Python 文件，使用 AST 解析
            if file_path.endswith('.py'):
                # 预检查代码内容
                if not is_valid_python_code(source_code):
                    logger.debug(f"跳过非 Python 代码内容: {file_path}")
                    self.stats['files_skipped'] += 1
                    return []
                
                # 解析 AST
                tree = safe_parse(source_code)
                if tree is None:
                    logger.warning(f"AST 解析失败 {file_path}: 语法错误")
                    self.stats['parse_errors'] += 1
                    return []
                
                # 创建访问者并遍历
                visitor = SecurityVisitor(file_path, source_code)
                visitor.visit(tree)
                
                # 执行完整分析
                visitor.analyze()
                
                # 构建语义图
                self.semantic_graph = semantic_graph_builder.build_from_file(file_path)
                
                # 分析语义图
                graph_issues = self._analyze_semantic_graph(file_path)
                visitor.issues.extend(graph_issues)
                
                issues = visitor.issues
            else:
                # 对于 TypeScript 和 JavaScript 文件，使用基于模式的分析
                ts_issues = self._analyze_typescript_file(file_path, source_code)
                issues.extend(ts_issues)
            
            # 添加文件信息到每个问题
            for issue in issues:
                issue['file'] = file_path
            
            self.stats['issues_found'] += len(issues)
            
            return issues
        
        except Exception as e:
            logger.error(f"AST 扫描文件 {file_path} 时出错：{e}")
            return []
    
    def _analyze_typescript_file(self, file_path: str, source_code: str) -> List[Dict[str, Any]]:
        """分析 TypeScript 和 JavaScript 文件"""
        import re
        issues = []
        lines = source_code.splitlines()
        
        # 危险函数调用模式
        dangerous_patterns = [
            (r'eval\s*\(', 'eval() 可能导致代码注入', 'HIGH'),
            (r'exec\s*\(', 'exec() 可能导致代码注入', 'HIGH'),
            (r'new\s+Function\s*\(', 'new Function() 可能导致代码注入', 'HIGH'),
            (r'child_process\.exec\s*\(', 'child_process.exec 可能执行系统命令', 'HIGH'),
            (r'child_process\.execSync\s*\(', 'child_process.execSync 可能执行系统命令', 'HIGH'),
            (r'child_process\.spawn\s*\(', 'child_process.spawn 可能执行系统命令', 'HIGH'),
            (r'child_process\.spawnSync\s*\(', 'child_process.spawnSync 可能执行系统命令', 'HIGH'),
            (r'fs\.writeFile\s*\(', '文件写入操作需要验证路径', 'MEDIUM'),
            (r'fs\.writeFileSync\s*\(', '文件写入操作需要验证路径', 'MEDIUM'),
            (r'fs\.appendFile\s*\(', '文件追加操作需要验证路径', 'MEDIUM'),
            (r'fs\.appendFileSync\s*\(', '文件追加操作需要验证路径', 'MEDIUM'),
            (r'fs\.open\s*\(', '文件打开操作需要验证路径', 'MEDIUM'),
            (r'fs\.openSync\s*\(', '文件打开操作需要验证路径', 'MEDIUM'),
        ]
        
        # 敏感信息模式
        sensitive_patterns = [
            (r'password\s*[:=]', '硬编码密码', 'HIGH'),
            (r'api[_-]?key\s*[:=]', '硬编码 API 密钥', 'HIGH'),
            (r'secret\s*[:=]', '硬编码密钥', 'HIGH'),
            (r'token\s*[:=]', '硬编码令牌', 'HIGH'),
            (r'private[_-]?key\s*[:=]', '硬编码私钥', 'HIGH'),
        ]
        
        # 提示词拼接模式
        prompt_patterns = [
            (r'prompt\s*[+]', '提示词拼接风险', 'HIGH'),
            (r'system[_-]?prompt\s*[+]', '系统提示词拼接风险', 'HIGH'),
            (r'user[_-]?input\s*[+]', '用户输入拼接风险', 'HIGH'),
            (r'chat[_-]?input\s*[+]', '聊天输入拼接风险', 'HIGH'),
        ]
        
        # 网络请求模式
        network_patterns = [
            (r'fetch\s*\(', '网络请求需要验证 URL', 'MEDIUM'),
            (r'axios\.get\s*\(', '网络请求需要验证 URL', 'MEDIUM'),
            (r'axios\.post\s*\(', '网络请求需要验证 URL', 'MEDIUM'),
            (r'axios\.put\s*\(', '网络请求需要验证 URL', 'MEDIUM'),
            (r'axios\.delete\s*\(', '网络请求需要验证 URL', 'MEDIUM'),
        ]
        
        # 遍历所有模式
        all_patterns = dangerous_patterns + sensitive_patterns + prompt_patterns + network_patterns
        
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in all_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        'line_number': i,
                        'severity': severity,
                        'issue': description,
                        'details': f'在 {file_path} 中检测到安全问题',
                        'code_snippet': line.strip(),
                        'category': 'ts_js_analysis'
                    })
        
        return issues
    
    def _analyze_semantic_graph(self, file_path: str) -> List[Dict[str, Any]]:
        """分析语义图"""
        issues = []
        
        if not self.semantic_graph:
            return issues
        
        # 分析 AgentFlow 框架节点
        agentflow_nodes = self.semantic_graph.get_nodes_by_type("agentflow_tool_call")
        for node in agentflow_nodes:
            issues.append({
                'line_number': node.line,
                'severity': 'MEDIUM',
                'issue': 'AgentFlow 工具调用',
                'details': '检测到 AgentFlow 工具调用，需要验证工具参数',
                'code_snippet': f"tool.call()",
                'category': 'agentflow_analysis'
            })
        
        agent_execute_nodes = self.semantic_graph.get_nodes_by_type("agentflow_agent_execute")
        for node in agent_execute_nodes:
            issues.append({
                'line_number': node.line,
                'severity': 'MEDIUM',
                'issue': 'AgentFlow 代理执行',
                'details': '检测到 AgentFlow 代理执行，需要验证执行参数',
                'code_snippet': f"agent.execute()",
                'category': 'agentflow_analysis'
            })
        
        prompt_template_nodes = self.semantic_graph.get_nodes_by_type("agentflow_prompt_template")
        for node in prompt_template_nodes:
            issues.append({
                'line_number': node.line,
                'severity': 'HIGH',
                'issue': 'AgentFlow 提示词模板',
                'details': '检测到 AgentFlow 提示词模板，需要验证模板内容',
                'code_snippet': f"prompt.template",
                'category': 'agentflow_analysis'
            })
        
        # 分析函数调用链
        call_nodes = self.semantic_graph.get_nodes_by_type("call")
        for node in call_nodes:
            # 分析危险函数调用
            if node.name in ['eval', 'exec', 'compile']:
                issues.append({
                    'line_number': node.line,
                    'severity': 'HIGH',
                    'issue': f'危险函数调用：{node.name}()',
                    'details': f'{node.name}() 可能导致代码注入',
                    'code_snippet': f"{node.name}()",
                    'category': 'semantic_analysis'
                })
            elif node.name in ['os.system', 'subprocess.call', 'subprocess.run', 'subprocess.Popen']:
                issues.append({
                    'line_number': node.line,
                    'severity': 'HIGH',
                    'issue': f'危险系统调用：{node.name}',
                    'details': f'{node.name} 可能执行系统命令',
                    'code_snippet': f"{node.name}",
                    'category': 'semantic_analysis'
                })
        
        return issues
    
    def scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict[str, Any]]:
        """扫描目录"""
        if extensions is None:
            extensions = ['.py', '.pyw', '.ts', '.js']
        
        results = []
        
        for root, dirs, files in os.walk(directory):
            # 跳过常见忽略目录
            dirs[:] = [d for d in dirs if d not in [
                'node_modules', 'venv', '.venv', '__pycache__',
                '.git', 'dist', 'build', 'target'
            ]]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    issues = self.scan_file(file_path)
                    results.extend(issues)
        
        return results
    
    def analyze(self, target: str) -> List[Dict[str, Any]]:
        """分析目标（文件或目录）"""
        if os.path.isfile(target):
            return self.scan_file(target)
        elif os.path.isdir(target):
            return self.scan_directory(target)
        else:
            logger.warning(f"目标不存在：{target}")
            return []


def scan_with_ast(target: str) -> List[Dict[str, Any]]:
    """便捷函数：使用 AST 扫描目标"""
    scanner = ASTScanner()
    return scanner.analyze(target)


if __name__ == '__main__':
    # 测试 AST 扫描器
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = '.'
    
    print(f"开始 AST 安全扫描：{target}")
    results = scan_with_ast(target)
    
    if results:
        print(f"\n发现 {len(results)} 个潜在安全问题:\n")
        for issue in results:
            print(f"[{issue['severity']}] {issue['file']}:{issue['line_number']}")
            print(f"  问题：{issue['issue']}")
            print(f"  详情：{issue['details']}")
            print(f"  代码：{issue['code_snippet']}\n")
    else:
        print("\n未发现 AST 级别的安全问题")
