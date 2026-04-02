import ast
import os
import libcst
from typing import List, Dict, Any

class ContextBuilder:
    def __init__(self):
        self.entry_points = []
        self.danger_calls = []
        self.data_flow = []
        
    def build(self, files: List[str]) -> Dict[str, Any]:
        """
        构建代码上下文
        
        Args:
            files: 要分析的文件列表
            
        Returns:
            包含入口点、危险调用和数据流的上下文字典
        """
        for file_path in files:
            if file_path.endswith('.py'):
                self._analyze_python_file(file_path)
            elif file_path.endswith('.js') or file_path.endswith('.ts'):
                self._analyze_javascript_file(file_path)
        
        return {
            "entry_points": self.entry_points,
            "danger_calls": self.danger_calls,
            "data_flow": self.data_flow
        }
    
    def _analyze_python_file(self, file_path: str):
        """
        分析Python文件
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 使用AST分析
            tree = ast.parse(content, filename=file_path)
            self._analyze_ast(tree, file_path)
            
            # 使用libcst进行更详细的分析
            cst = libcst.parse_module(content)
            self._analyze_cst(cst, file_path)
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
    
    def _analyze_javascript_file(self, file_path: str):
        """
        分析JavaScript/TypeScript文件
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 简单的模式匹配，后续可以使用更专业的JavaScript解析器
            self._analyze_javascript_patterns(content, file_path)
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
    
    def _analyze_ast(self, tree: ast.AST, file_path: str):
        """
        分析AST树，识别入口点和危险调用
        """
        class ASTAnalyzer(ast.NodeVisitor):
            def __init__(self, builder):
                self.builder = builder
                self.current_function = None
            
            def visit_FunctionDef(self, node):
                # 识别可能的入口点
                if node.name in ['main', 'app', 'run', 'handler', 'lambda_handler']:
                    self.builder.entry_points.append({
                        'type': 'function',
                        'name': node.name,
                        'file': file_path,
                        'line': node.lineno
                    })
                
                # 记录当前函数
                old_function = self.current_function
                self.current_function = node.name
                self.generic_visit(node)
                self.current_function = old_function
            
            def visit_Call(self, node):
                # 识别危险调用
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in ['exec', 'eval', 'execfile', 'open', 'input', 'raw_input']:
                        self.builder.danger_calls.append({
                            'type': 'danger_call',
                            'function': func_name,
                            'file': file_path,
                            'line': node.lineno,
                            'in_function': self.current_function
                        })
                
                # 识别SQL相关调用
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id in ['cursor', 'db', 'conn'] and node.func.attr in ['execute', 'executemany']:
                            self.builder.danger_calls.append({
                                'type': 'sql_call',
                                'function': f"{node.func.value.id}.{node.func.attr}",
                                'file': file_path,
                                'line': node.lineno,
                                'in_function': self.current_function
                            })
                
                self.generic_visit(node)
        
        analyzer = ASTAnalyzer(self)
        analyzer.visit(tree)
    
    def _analyze_cst(self, cst: libcst.Module, file_path: str):
        """
        使用libcst进行更详细的代码分析
        """
        class CSTAnalyzer(libcst.CSTVisitor):
            def __init__(self, builder):
                self.builder = builder
                self.current_function = None
            
            def visit_FunctionDef(self, node):
                # 记录当前函数
                old_function = self.current_function
                self.current_function = node.name.value
                self.visit_children(node)
                self.current_function = old_function
            
            def visit_Call(self, node):
                # 识别危险调用
                if isinstance(node.func, libcst.Name):
                    func_name = node.func.value
                    if func_name in ['exec', 'eval', 'open']:
                        self.builder.danger_calls.append({
                            'type': 'danger_call',
                            'function': func_name,
                            'file': file_path,
                            'line': node.lineno,
                            'in_function': self.current_function
                        })
                
                self.visit_children(node)
        
        analyzer = CSTAnalyzer(self)
        analyzer.visit(cst)
    
    def _analyze_javascript_patterns(self, content: str, file_path: str):
        """
        分析JavaScript文件中的模式
        """
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            # 识别危险调用
            if 'eval(' in line or 'exec(' in line or 'new Function(' in line:
                self.danger_calls.append({
                    'type': 'danger_call',
                    'function': 'eval/exec',
                    'file': file_path,
                    'line': i
                })
            
            # 识别SQL相关调用
            if 'execute(' in line or 'query(' in line:
                self.danger_calls.append({
                    'type': 'sql_call',
                    'function': 'execute/query',
                    'file': file_path,
                    'line': i
                })
            
            # 识别可能的入口点
            if 'function ' in line and ('main' in line or 'app' in line or 'handler' in line):
                self.entry_points.append({
                    'type': 'function',
                    'name': line.split('function ')[1].split('(')[0].strip(),
                    'file': file_path,
                    'line': i
                })
    
    def _analyze_data_flow(self, files: List[str]):
        """
        分析数据流，识别从用户输入到危险调用的路径
        """
        # 这里可以实现更复杂的数据流分析
        # 暂时简单实现
        for file_path in files:
            if file_path.endswith('.py'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # 简单的模式匹配，识别用户输入到危险调用的路径
                    if 'input(' in content and ('exec(' in content or 'eval(' in content):
                        self.data_flow.append({
                            'type': 'data_flow',
                            'source': 'input()',
                            'sink': 'exec/eval',
                            'file': file_path
                        })
                    
                except Exception as e:
                    print(f"Error analyzing data flow in {file_path}: {e}")
