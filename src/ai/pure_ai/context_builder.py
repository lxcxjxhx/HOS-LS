import ast
import os
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
        print(f"[DEBUG] 开始构建上下文: {file_path}")
        
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
        print(f"[DEBUG] 提取到 {len(context['imports'])} 个导入语句")
        
        # 提取函数调用
        context['function_calls'] = self._extract_function_calls(file_path)
        print(f"[DEBUG] 提取到 {len(context['function_calls'])} 个函数调用")
        
        # 加载相关文件
        context['related_files'] = self._load_related_files(file_path)
        print(f"[DEBUG] 加载了 {len(context['related_files'])} 个相关文件")
        
        # 提取文件结构
        context['file_structure'] = self._extract_file_structure(file_path)
        print(f"[DEBUG] 提取文件结构完成")
        
        print(f"[DEBUG] 上下文构建完成，文件内容长度: {len(context['file_content'])} 字符")
        return context
    
    def _read_file(self, file_path: str, max_size: int = 1048576) -> str:
        """读取文件内容

        Args:
            file_path: 文件路径
            max_size: 最大读取大小（字节），默认1MB

        Returns:
            文件内容
        """
        try:
            # 检查文件大小
            file_size = os.path.getsize(file_path)
            print(f"[DEBUG] 读取文件: {file_path}, 大小: {file_size} 字节")
            
            if file_size > max_size:
                # 文件过大，只读取前max_size字节
                print(f"[DEBUG] 文件过大，截断为 {max_size} 字节")
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read(max_size)
                return content + "\n... [文件过大，已截断]"
            else:
                # 文件大小正常，读取全部内容
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                print(f"[DEBUG] 成功读取文件，内容长度: {len(content)} 字符")
                return content
        except Exception as e:
            print(f"[DEBUG] 读取文件失败: {file_path}, 错误: {e}")
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
            current_path = Path(file_path)
            current_dir = current_path.parent
            
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
                        # 尝试不同的文件扩展名
                        for ext in ['.py', '.pyw', '.pyc']:
                            # 尝试直接文件路径
                            potential_path = current_dir / f"{module_path}{ext}"
                            if potential_path.exists():
                                related_files.append({
                                    'path': str(potential_path),
                                    'content': self._read_file(str(potential_path), max_size=524288)  # 限制为512KB
                                })
                                break
                            # 尝试目录下的 __init__.py
                            potential_init = current_dir / module_path / '__init__.py'
                            if potential_init.exists():
                                related_files.append({
                                    'path': str(potential_init),
                                    'content': self._read_file(str(potential_init), max_size=524288)  # 限制为512KB
                                })
                                break
                    elif imp_parts[0] == 'import':
                        # 处理 import module
                        module_name = imp_parts[1]
                        # 尝试不同的文件扩展名
                        for ext in ['.py', '.pyw', '.pyc']:
                            # 尝试直接文件路径
                            potential_path = current_dir / f"{module_name.replace('.', '/')}{ext}"
                            if potential_path.exists():
                                related_files.append({
                                    'path': str(potential_path),
                                    'content': self._read_file(str(potential_path), max_size=524288)  # 限制为512KB
                                })
                                break
                            # 尝试目录下的 __init__.py
                            potential_init = current_dir / module_name.replace('.', '/') / '__init__.py'
                            if potential_init.exists():
                                related_files.append({
                                    'path': str(potential_init),
                                    'content': self._read_file(str(potential_init), max_size=524288)  # 限制为512KB
                                })
                                break
            
            # 如果相关文件不足，添加同目录下的其他Python文件
            if len(related_files) < self.max_related_files:
                # 按文件大小排序，优先添加较大的文件（可能包含更多相关信息）
                python_files = []
                for file in current_dir.iterdir():
                    if file.suffix == '.py' and file.name != current_path.name:
                        try:
                            file_size = file.stat().st_size
                            python_files.append((file_size, file))
                        except Exception:
                            pass
                
                # 按文件大小降序排序
                python_files.sort(reverse=True, key=lambda x: x[0])
                
                # 添加排序后的文件
                for _, file in python_files:
                    if len(related_files) >= self.max_related_files:
                        break
                    potential_path = current_dir / file
                    related_files.append({
                        'path': str(potential_path),
                        'content': self._read_file(str(potential_path), max_size=524288)  # 限制为512KB
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
            'variables': [],
            'imports': [],
            'class_methods': {},
            'function_calls': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=file_path)
            
            # 提取导入语句
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(f"import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    for alias in node.names:
                        imports.append(f"from {module} import {alias.name}")
            structure['imports'] = imports
            
            # 提取函数调用
            function_calls = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        function_calls.append(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        function_calls.append(f"{node.func.attr}")
            structure['function_calls'] = function_calls
            
            # 提取类和函数
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # 提取函数参数
                    args = []
                    for arg in node.args.args:
                        args.append(arg.arg)
                    # 提取默认参数
                    defaults = []
                    for default in node.args.defaults:
                        if isinstance(default, ast.Constant):
                            defaults.append(default.value)
                        else:
                            defaults.append(None)
                    # 提取函数文档字符串
                    docstring = ast.get_docstring(node, clean=False)
                    structure['functions'].append({
                        'name': node.name,
                        'args': args,
                        'defaults': defaults,
                        'line': node.lineno,
                        'docstring': docstring
                    })
                elif isinstance(node, ast.ClassDef):
                    # 提取类文档字符串
                    docstring = ast.get_docstring(node, clean=False)
                    structure['classes'].append({
                        'name': node.name,
                        'line': node.lineno,
                        'docstring': docstring
                    })
                    # 提取类方法
                    class_methods = []
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            method_args = []
                            for arg in item.args.args:
                                method_args.append(arg.arg)
                            method_docstring = ast.get_docstring(item, clean=False)
                            class_methods.append({
                                'name': item.name,
                                'args': method_args,
                                'line': item.lineno,
                                'docstring': method_docstring
                            })
                    structure['class_methods'][node.name] = class_methods
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            # 尝试提取变量值
                            value = None
                            if isinstance(node.value, ast.Constant):
                                value = node.value.value
                            structure['variables'].append({
                                'name': target.id,
                                'line': node.lineno,
                                'value': value
                            })
        except Exception:
            pass
        
        return structure
