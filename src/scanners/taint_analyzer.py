#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据流分析模块（污点追踪）

功能：
1. 标记污点源（用户输入）
2. 追踪污点传播（赋值、拼接、函数调用）
3. 检测污点汇聚点（危险函数）
4. 生成数据流路径
5. 支持跨文件污点追踪
6. 集成语义图分析
"""

import ast
import logging
import os
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict

from scanners.semantic_graph import semantic_graph_builder

logger = logging.getLogger(__name__)


class TaintAnalyzer:
    """污点分析器"""
    
    def __init__(self):
        # 污点源（用户输入）
        self.taint_sources = {
            'input': '用户输入',
            'raw_input': 'Python2 输入',
            'request': 'HTTP 请求',
            'argv': '命令行参数',
            'stdin': '标准输入',
            'file_read': '文件读取',
            'network': '网络数据',
            'os.environ': '环境变量',
        }
        
        # 危险汇聚点
        self.dangerous_sinks = {
            'eval': '代码执行',
            'exec': '代码执行',
            'compile': '代码编译',
            'open': '文件操作',
            'os.system': '系统命令',
            'subprocess.call': '子进程',
            'subprocess.run': '子进程',
            'subprocess.Popen': '子进程',
            '__import__': '动态导入',
            'execfile': '文件执行',
        }
        
        # 污点传播函数
        self.propagation_functions = {
            'str': '字符串转换',
            'repr': '表示转换',
            'format': '格式化',
            'join': '字符串连接',
        }
    
    def analyze_file(self, file_path: str, source_code: str) -> List[Dict[str, Any]]:
        """分析单个文件的数据流"""
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            logger.debug(f"AST 解析失败 {file_path}: {e}")
            return []
        
        issues = []
        
        # 第一次遍历：标记污点源
        taint_map = self._mark_taint_sources(tree)
        
        # 第二次遍历：追踪污点传播
        propagation_chain = self._track_propagation(tree, taint_map)
        
        # 第三次遍历：检测危险汇聚
        sink_issues = self._detect_sinks(tree, propagation_chain, file_path, source_code)
        
        issues.extend(sink_issues)
        
        return issues
    
    def _mark_taint_sources(self, tree: ast.AST) -> Dict[str, Set[int]]:
        """标记污点源"""
        taint_map = defaultdict(set)
        
        for node in ast.walk(tree):
            # 检查赋值语句
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        
                        # 检查右侧是否包含污点源
                        if self._is_taint_source(node.value):
                            taint_map[var_name].add(node.lineno)
            
            # 检查函数参数
            elif isinstance(node, ast.FunctionDef):
                for arg in node.args.args:
                    # 函数参数视为潜在污点
                    taint_map[arg.arg].add(node.lineno)
        
        return taint_map
    
    def _is_taint_source(self, node: ast.AST) -> bool:
        """检查是否是污点源"""
        if isinstance(node, ast.Call):
            # 检查函数调用
            if isinstance(node.func, ast.Name):
                return node.func.id in self.taint_sources
            
            if isinstance(node.func, ast.Attribute):
                # 检查方法调用
                if node.func.attr in ['get', 'post', 'form', 'args']:
                    return True
        
        return False
    
    def _track_propagation(self, tree: ast.AST, taint_map: Dict[str, Set[int]]) -> Dict[str, Set[str]]:
        """追踪污点传播"""
        propagation_chain = defaultdict(set)
        
        for node in ast.walk(tree):
            # 检查赋值传播
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        target_var = target.id
                        
                        # 检查右侧是否使用了已污染的变量
                        for var_name in self._get_variables_in_node(node.value):
                            if var_name in taint_map:
                                propagation_chain[target_var].add(var_name)
            
            # 检查字符串拼接
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                # 字符串拼接传播
                left_vars = self._get_variables_in_node(node.left)
                right_vars = self._get_variables_in_node(node.right)
                
                for var in left_vars:
                    if var in taint_map:
                        for new_var in right_vars:
                            propagation_chain[new_var].add(var)
                
                for var in right_vars:
                    if var in taint_map:
                        for new_var in left_vars:
                            propagation_chain[new_var].add(var)
        
        return propagation_chain
    
    def _get_variables_in_node(self, node: ast.AST) -> Set[str]:
        """获取节点中的所有变量名"""
        variables = set()
        
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                variables.add(child.id)
        
        return variables
    
    def _detect_sinks(self, tree: ast.AST, propagation_chain: Dict[str, Set[str]], 
                     file_path: str, source_code: str) -> List[Dict[str, Any]]:
        """检测危险汇聚点"""
        issues = []
        source_lines = source_code.splitlines()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # 检查危险函数调用
                func_name = self._get_func_name(node)
                
                if func_name in self.dangerous_sinks:
                    # 检查参数是否被污染
                    for arg in node.args:
                        tainted_vars = self._get_variables_in_node(arg)
                        
                        for var in tainted_vars:
                            # 检查变量是否在污染链中
                            if self._is_tainted(var, propagation_chain):
                                issue = {
                                    'file': file_path,
                                    'line_number': node.lineno,
                                    'severity': 'HIGH',
                                    'issue': f'数据流漏洞：{func_name}',
                                    'details': f'用户输入流向危险函数 {func_name}',
                                    'code_snippet': source_lines[node.lineno - 1] if node.lineno <= len(source_lines) else '',
                                    'taint_chain': self._build_taint_chain(var, propagation_chain),
                                    'category': 'taint_analysis'
                                }
                                issues.append(issue)
        
        return issues
    
    def _is_tainted(self, var_name: str, propagation_chain: Dict[str, Set[str]]) -> bool:
        """检查变量是否被污染"""
        # 直接污染
        if var_name in propagation_chain:
            return True
        
        # 间接污染（递归检查）
        for source_var in propagation_chain.get(var_name, set()):
            if self._is_tainted(source_var, propagation_chain):
                return True
        
        return False
    
    def _build_taint_chain(self, var_name: str, propagation_chain: Dict[str, Set[str]]) -> str:
        """构建污染链"""
        chain = [var_name]
        visited = set()
        
        def trace(var):
            if var in visited:
                return
            visited.add(var)
            
            for source in propagation_chain.get(var, set()):
                chain.append(source)
                trace(source)
        
        trace(var_name)
        return ' <- '.join(chain)
    
    def _get_func_name(self, node: ast.Call) -> str:
        """获取函数名"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return ''
    
    def analyze(self, target: str) -> List[Dict[str, Any]]:
        """分析目标（支持文件和目录）"""
        import os
        
        if os.path.isfile(target):
            with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
            return self.analyze_file(target, source)
        elif os.path.isdir(target):
            return self.analyze_directory(target)
        return []
    
    def analyze_directory(self, directory: str) -> List[Dict[str, Any]]:
        """分析目录，支持跨文件污点追踪"""
        all_issues = []
        semantic_graph = None
        
        # 构建整个目录的语义图
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        file_graph = semantic_graph_builder.build_from_file(file_path)
                        if semantic_graph is None:
                            semantic_graph = file_graph
                        else:
                            semantic_graph.merge(file_graph)
                    except Exception as e:
                        logger.error(f"构建语义图失败 {file_path}: {e}")
        
        # 分析每个文件
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            source = f.read()
                        issues = self.analyze_file(file_path, source, semantic_graph)
                        all_issues.extend(issues)
                    except Exception as e:
                        logger.error(f"分析文件失败 {file_path}: {e}")
        
        return all_issues
    
    def analyze_file(self, file_path: str, source_code: str, semantic_graph=None) -> List[Dict[str, Any]]:
        """分析单个文件的数据流"""
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            logger.debug(f"AST 解析失败 {file_path}: {e}")
            return []
        
        issues = []
        
        # 第一次遍历：标记污点源
        taint_map = self._mark_taint_sources(tree)
        
        # 第二次遍历：追踪污点传播
        propagation_chain = self._track_propagation(tree, taint_map)
        
        # 第三次遍历：检测危险汇聚
        sink_issues = self._detect_sinks(tree, propagation_chain, file_path, source_code)
        
        issues.extend(sink_issues)
        
        # 分析语义图（如果提供）
        if semantic_graph:
            graph_issues = self._analyze_semantic_graph(semantic_graph, file_path, source_code)
            issues.extend(graph_issues)
        
        return issues
    
    def _analyze_semantic_graph(self, semantic_graph, file_path: str, source_code: str) -> List[Dict[str, Any]]:
        """分析语义图，检测跨文件污点传播"""
        issues = []
        source_lines = source_code.splitlines()
        
        # 获取文件中的所有节点
        file_nodes = semantic_graph.get_nodes_by_file(file_path)
        
        # 分析函数调用和依赖关系
        for node in file_nodes:
            if node.node_type == "call":
                # 检查危险函数调用
                if node.name in self.dangerous_sinks:
                    # 检查调用的依赖节点
                    dependencies = semantic_graph.get_dependencies(node.node_id)
                    for dep_node in dependencies:
                        # 检查依赖节点是否是污点源
                        if dep_node.node_type in ["parameter", "name"]:
                            issues.append({
                                'file': file_path,
                                'line_number': node.line,
                                'severity': 'HIGH',
                                'issue': f'跨文件数据流漏洞：{node.name}',
                                'details': f'通过语义依赖，污点可能流向危险函数 {node.name}',
                                'code_snippet': source_lines[node.line - 1] if node.line and node.line <= len(source_lines) else '',
                                'category': 'cross_file_taint_analysis'
                            })
        
        return issues


if __name__ == '__main__':
    # 测试污点分析
    test_code = """
def process_input(user_input):
    cmd = "ping " + user_input
    os.system(cmd)
    
def safe_process(input):
    validated = validate(input)
    return validated
"""
    
    analyzer = TaintAnalyzer()
    issues = analyzer.analyze_file('test.py', test_code)
    
    for issue in issues:
        print(f"[{issue['severity']}] {issue['file']}:{issue['line_number']}")
        print(f"问题：{issue['issue']}")
        print(f"详情：{issue['details']}")
        print(f"污染链：{issue.get('taint_chain', 'N/A')}")
        print()
