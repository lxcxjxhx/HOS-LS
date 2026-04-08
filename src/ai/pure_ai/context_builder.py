import os
import ast
from pathlib import Path
from typing import Dict, List, Optional, Any

class ContextBuilder:
    """上下文构建器（伪RAG）
    
    在不使用embedding的情况下构建代码分析上下文
    """
    
    def __init__(self, config: Optional[Any] = None):
        """初始化上下文构建器
        
        Args:
            config: 配置参数
        """
        self.config = config
        # 尝试从配置中获取max_related_files，如果不存在则使用默认值3
        if hasattr(config, 'get'):
            # 配置是字典
            self.max_related_files = config.get('max_related_files', 3)
        else:
            # 配置是对象
            self.max_related_files = getattr(config, 'max_related_files', 3)
    
    def build_context(self, file_path: str) -> Dict[str, Any]:
        """构建文件的分析上下文
        
        Args:
            file_path: 文件路径
            
        Returns:
            包含上下文信息的字典
        """
        context = {
            'current_file': file_path,
            'file_content': self._read_file(file_path),
            'imports': [],
            'related_files': [],
            'function_calls': [],
            'file_structure': {}
        }
        
        # 提取导入信息
        context['imports'] = self._extract_imports(file_path)
        
        # 提取函数调用
        context['function_calls'] = self._extract_function_calls(file_path)
        
        # 加载相关文件
        context['related_files'] = self._load_related_files(file_path)
        
        # 提取文件结构
        context['file_structure'] = self._extract_file_structure(file_path)
        
        return context
    
    def _read_file(self, file_path: str) -> str:
        """读取文件内容
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件内容
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            return ''
    
    def _extract_imports(self, file_path: str) -> List[str]:
        """提取文件中的导入语句
        
        Args:
            file_path: 文件路径
            
        Returns:
            导入语句列表
        """
        imports = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(f"import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    for alias in node.names:
                        imports.append(f"from {module} import {alias.name}")
        except Exception:
            pass
        return imports
    
    def _extract_function_calls(self, file_path: str) -> List[str]:
        """提取文件中的函数调用
        
        Args:
            file_path: 文件路径
            
        Returns:
            函数调用列表
        """
        function_calls = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        function_calls.append(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        function_calls.append(f"{node.func.attr}")
        except Exception:
            pass
        return function_calls
    
    def _load_related_files(self, file_path: str) -> List[Dict[str, str]]:
        """加载相关文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            相关文件列表，每个文件包含路径和内容
        """
        related_files = []
        try:
            # 获取当前文件所在目录
            current_dir = os.path.dirname(file_path)
            
            # 获取当前文件的导入模块
            imports = self._extract_imports(file_path)
            
            # 查找相关文件
            for imp in imports:
                if len(related_files) >= self.max_related_files:
                    break
                
                # 尝试解析导入路径
                imp_parts = imp.split()
                if len(imp_parts) >= 2:
                    if imp_parts[0] == 'from':
                        # 处理 from module import ...
                        module_path = imp_parts[1].replace('.', '/')
                        for ext in ['.py', '.pyw']:
                            potential_path = os.path.join(current_dir, f"{module_path}{ext}")
                            if os.path.exists(potential_path):
                                related_files.append({
                                    'path': potential_path,
                                    'content': self._read_file(potential_path)
                                })
                                break
                            # 尝试目录下的 __init__.py
                            potential_init = os.path.join(current_dir, module_path, '__init__.py')
                            if os.path.exists(potential_init):
                                related_files.append({
                                    'path': potential_init,
                                    'content': self._read_file(potential_init)
                                })
                                break
            
            # 如果相关文件不足，添加同目录下的其他Python文件
            if len(related_files) < self.max_related_files:
                for file in os.listdir(current_dir):
                    if len(related_files) >= self.max_related_files:
                        break
                    if file.endswith('.py') and file != os.path.basename(file_path):
                        potential_path = os.path.join(current_dir, file)
                        related_files.append({
                            'path': potential_path,
                            'content': self._read_file(potential_path)
                        })
        except Exception:
            pass
        
        return related_files
    
    def _extract_file_structure(self, file_path: str) -> Dict[str, Any]:
        """提取文件结构
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件结构信息
        """
        structure = {
            'functions': [],
            'classes': [],
            'variables': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    structure['functions'].append({
                        'name': node.name,
                        'args': [arg.arg for arg in node.args.args],
                        'line': node.lineno
                    })
                elif isinstance(node, ast.ClassDef):
                    structure['classes'].append({
                        'name': node.name,
                        'line': node.lineno
                    })
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            structure['variables'].append({
                                'name': target.id,
                                'line': node.lineno
                            })
        except Exception:
            pass
        
        return structure
