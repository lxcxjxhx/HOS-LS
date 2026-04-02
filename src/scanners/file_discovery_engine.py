import os
from pathlib import Path
from typing import List, Set, Optional

class FileDiscoveryEngine:
    _instance = None
    _default_extensions = ['.py', '.yaml', '.yml', '.toml', '.json', '.md', '.txt']

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(FileDiscoveryEngine, cls).__new__(cls)
        return cls._instance

    def discover_files(self, root_dir: str, extensions: Optional[List[str]] = None, 
                      include_patterns: Optional[List[str]] = None, 
                      exclude_patterns: Optional[List[str]] = None) -> List[str]:
        """发现并返回符合条件的文件列表
        
        Args:
            root_dir: 根目录路径
            extensions: 文件扩展名列表，默认包含常见配置和代码文件
            include_patterns: 包含的文件模式列表
            exclude_patterns: 排除的文件模式列表
            
        Returns:
            符合条件的文件路径列表
        """
        if extensions is None:
            extensions = self._default_extensions
        
        include_patterns = include_patterns or []
        exclude_patterns = exclude_patterns or []
        
        discovered_files = []
        
        for root, dirs, files in os.walk(root_dir):
            # 过滤目录
            dirs[:] = [d for d in dirs if not self._should_exclude(d, exclude_patterns)]
            
            for file in files:
                if self._should_include(file, extensions, include_patterns, exclude_patterns):
                    file_path = str(Path(root) / file)
                    discovered_files.append(file_path)
        
        return discovered_files

    def _should_exclude(self, name: str, exclude_patterns: List[str]) -> bool:
        """判断是否应该排除某个文件或目录
        
        Args:
            name: 文件或目录名称
            exclude_patterns: 排除模式列表
            
        Returns:
            是否应该排除
        """
        # 默认排除隐藏目录和文件
        if name.startswith('.'):
            return True
        
        # 排除常见的无关目录
        exclude_dirs = ['__pycache__', 'node_modules', 'venv', '.venv', 'dist', 'build']
        if name in exclude_dirs:
            return True
        
        # 根据排除模式判断
        for pattern in exclude_patterns:
            if pattern in name:
                return True
        
        return False

    def _should_include(self, file: str, extensions: List[str], 
                       include_patterns: List[str], exclude_patterns: List[str]) -> bool:
        """判断是否应该包含某个文件
        
        Args:
            file: 文件名
            extensions: 允许的扩展名列表
            include_patterns: 包含模式列表
            exclude_patterns: 排除模式列表
            
        Returns:
            是否应该包含
        """
        # 检查是否应该排除
        if self._should_exclude(file, exclude_patterns):
            return False
        
        # 检查扩展名
        file_ext = os.path.splitext(file)[1]
        if file_ext not in extensions:
            return False
        
        # 检查包含模式
        if include_patterns:
            for pattern in include_patterns:
                if pattern in file:
                    return True
            return False
        
        return True

    def get_file_count(self, root_dir: str, extensions: Optional[List[str]] = None) -> int:
        """获取符合条件的文件数量
        
        Args:
            root_dir: 根目录路径
            extensions: 文件扩展名列表
            
        Returns:
            文件数量
        """
        files = self.discover_files(root_dir, extensions)
        return len(files)

    def get_file_types(self, root_dir: str) -> Set[str]:
        """获取目录中所有文件类型
        
        Args:
            root_dir: 根目录路径
            
        Returns:
            文件类型集合
        """
        file_types = set()
        
        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                ext = os.path.splitext(file)[1]
                if ext:
                    file_types.add(ext)
        
        return file_types

file_discovery_engine = FileDiscoveryEngine()
