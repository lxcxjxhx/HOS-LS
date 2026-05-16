"""
模块依赖分析器 - 解析Maven多模块项目结构

功能：
1. 解析pom.xml提取模块定义和依赖关系
2. 构建模块间的依赖图
3. 支持根据文件路径识别所属模块
"""

import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional

NS_MAP = {
    '': 'http://maven.apache.org/POM/4.0.0',
    'maven': 'http://maven.apache.org/POM/4.0.0'
}


class ModuleAnalyzer:
    def __init__(self, project_root: str):
        """
        初始化模块分析器
        
        Args:
            project_root: 项目根目录路径
        """
        self.project_root = Path(project_root)
        self.modules: Dict[str, 'ModuleInfo'] = {}  # 模块名 -> 模块信息
        self.dependencies: Dict[str, Set[str]] = {}  # 模块名 -> 依赖模块集合
        self.path_to_module: Dict[str, str] = {}  # 文件路径 -> 模块名
        
    def parse_project(self) -> bool:
        """
        解析整个项目结构
        
        Returns:
            bool: 是否成功解析
        """
        pom_path = self.project_root / 'pom.xml'
        if not pom_path.exists():
            print(f"[WARN] 未找到项目根pom.xml: {pom_path}")
            return False
        
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()
            
            # 解析模块列表
            self._parse_modules(root)
            
            # 解析依赖关系
            self._parse_dependencies(root)
            
            # 构建路径映射
            self._build_path_mapping()
            
            print(f"[INFO] 成功解析 {len(self.modules)} 个模块")
            return True
        except Exception as e:
            print(f"[ERROR] 解析pom.xml失败: {e}")
            return False
    
    def _parse_modules(self, root: ET.Element) -> None:
        """解析<modules>标签"""
        modules_elem = root.find('modules', NS_MAP)
        if not modules_elem:
            return
            
        for module_elem in modules_elem.findall('module', NS_MAP):
            module_name = module_elem.text.strip()
            if module_name:
                module_path = self.project_root / module_name
                module_info = ModuleInfo(
                    name=module_name,
                    path=str(module_path),
                    parent=None
                )
                self.modules[module_name] = module_info
                
                # 递归解析子模块
                self._parse_submodule(module_name, module_path)
    
    def _parse_submodule(self, parent_name: str, parent_path: Path) -> None:
        """递归解析子模块"""
        sub_pom = parent_path / 'pom.xml'
        if not sub_pom.exists():
            return
            
        try:
            tree = ET.parse(sub_pom)
            root = tree.getroot()
            
            # 解析子模块列表
            modules_elem = root.find('modules', NS_MAP)
            if modules_elem:
                for module_elem in modules_elem.findall('module', NS_MAP):
                    submodule_name = module_elem.text.strip()
                    if submodule_name:
                        full_name = f"{parent_name}/{submodule_name}"
                        submodule_path = parent_path / submodule_name
                        module_info = ModuleInfo(
                            name=full_name,
                            path=str(submodule_path),
                            parent=parent_name
                        )
                        self.modules[full_name] = module_info
                        
                        # 继续递归
                        self._parse_submodule(full_name, submodule_path)
                        
            # 解析依赖
            self._parse_module_dependencies(parent_name, root)
            
        except Exception as e:
            print(f"[WARN] 解析子模块pom.xml失败 {sub_pom}: {e}")
    
    def _parse_module_dependencies(self, module_name: str, root: ET.Element) -> None:
        """解析单个模块的依赖"""
        dependencies_elem = root.find('dependencies', NS_MAP)
        if not dependencies_elem:
            return
            
        if module_name not in self.dependencies:
            self.dependencies[module_name] = set()
            
        for dep_elem in dependencies_elem.findall('dependency', NS_MAP):
            group_id = self._get_text(dep_elem, 'groupId')
            artifact_id = self._get_text(dep_elem, 'artifactId')
            
            if group_id and artifact_id:
                # 尝试匹配模块名
                for module in self.modules:
                    if artifact_id.replace('-', '') == module.replace('-', '').replace('/', ''):
                        self.dependencies[module_name].add(module)
                        break
                    elif artifact_id in module or module in artifact_id:
                        self.dependencies[module_name].add(module)
                        break
    
    def _parse_dependencies(self, root: ET.Element) -> None:
        """解析根pom的依赖管理"""
        dep_mgmt = root.find('dependencyManagement', NS_MAP)
        if dep_mgmt:
            dependencies_elem = dep_mgmt.find('dependencies', NS_MAP)
            if dependencies_elem:
                for dep_elem in dependencies_elem.findall('dependency', NS_MAP):
                    group_id = self._get_text(dep_elem, 'groupId')
                    artifact_id = self._get_text(dep_elem, 'artifactId')
                    
                    # 记录可能的依赖关系
                    if group_id and artifact_id:
                        for module in self.modules:
                            if artifact_id in module or module in artifact_id:
                                if module not in self.dependencies:
                                    self.dependencies[module] = set()
    
    def _build_path_mapping(self) -> None:
        """构建文件路径到模块的映射"""
        for module_name, module_info in self.modules.items():
            module_path = Path(module_info.path)
            if module_path.exists():
                # 添加模块根目录
                self.path_to_module[str(module_path)] = module_name
                
                # 添加源码目录
                src_dir = module_path / 'src' / 'main' / 'java'
                if src_dir.exists():
                    for java_file in src_dir.rglob('*.java'):
                        self.path_to_module[str(java_file)] = module_name
    
    def _get_text(self, elem: ET.Element, tag_name: str) -> Optional[str]:
        """获取标签文本"""
        child = elem.find(tag_name, NS_MAP)
        return child.text.strip() if child is not None else None
    
    def get_module_by_path(self, file_path: str) -> Optional[str]:
        """
        根据文件路径获取所属模块
        
        Args:
            file_path: 文件绝对路径
            
        Returns:
            str: 模块名，如果未找到返回None
        """
        file_path_str = str(file_path)
        
        # 精确匹配
        if file_path_str in self.path_to_module:
            return self.path_to_module[file_path_str]
        
        # 模糊匹配（查找最长匹配路径）
        longest_match = ''
        for path, module in self.path_to_module.items():
            if file_path_str.startswith(path) and len(path) > len(longest_match):
                longest_match = path
                
        return self.path_to_module.get(longest_match)
    
    def get_dependencies(self, module_name: str, recursive: bool = False) -> Set[str]:
        """
        获取模块的依赖模块
        
        Args:
            module_name: 模块名
            recursive: 是否递归获取传递依赖
            
        Returns:
            Set[str]: 依赖模块集合
        """
        if module_name not in self.dependencies:
            return set()
            
        if not recursive:
            return self.dependencies[module_name].copy()
            
        # 递归获取所有依赖
        result = set()
        visited = set()
        self._get_dependencies_recursive(module_name, result, visited)
        return result
    
    def _get_dependencies_recursive(self, module_name: str, result: Set[str], visited: Set[str]) -> None:
        """递归获取依赖"""
        if module_name in visited:
            return
            
        visited.add(module_name)
        
        if module_name in self.dependencies:
            for dep in self.dependencies[module_name]:
                result.add(dep)
                self._get_dependencies_recursive(dep, result, visited)
    
    def get_module_info(self, module_name: str) -> Optional['ModuleInfo']:
        """获取模块信息"""
        return self.modules.get(module_name)
    
    def list_modules(self) -> List[str]:
        """列出所有模块"""
        return list(self.modules.keys())
    
    def print_summary(self) -> None:
        """打印模块摘要"""
        print("\n=== 模块依赖分析摘要 ===")
        print(f"总模块数: {len(self.modules)}")
        print("\n模块列表:")
        for name, info in self.modules.items():
            deps = self.dependencies.get(name, set())
            print(f"  {name}")
            print(f"    路径: {info.path}")
            print(f"    依赖: {', '.join(deps) if deps else '无'}")


class ModuleInfo:
    """模块信息"""
    
    def __init__(self, name: str, path: str, parent: Optional[str]):
        self.name = name
        self.path = path
        self.parent = parent
        self.source_files: List[str] = []
        
    def __repr__(self):
        return f"ModuleInfo(name={self.name}, parent={self.parent})"