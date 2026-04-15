"""规则加载器模块

提供规则的自动发现、加载和管理功能。
"""

import importlib
import inspect
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from src.rules.base import BaseRule
from src.rules.registry import RuleRegistry, get_registry


class RuleLoader:
    """规则加载器
    
    负责从不同来源加载安全规则。
    """
    
    def __init__(self, registry: Optional[RuleRegistry] = None) -> None:
        self._registry = registry or get_registry()
        self._loaded_modules: Dict[str, Any] = {}
    
    def load_builtin_rules(self) -> int:
        """加载内置规则
        
        Returns:
            加载的规则数量
        """
        try:
            from src.rules.builtin import load_all_rules
            rules = load_all_rules()
            count = 0
            for rule in rules:
                if not self._registry.has(rule.id):
                    self._registry.register(rule)
                    count += 1
            return count
        except ImportError as e:
            print(f"加载内置规则失败: {e}")
            return 0
    
    def load_from_module(self, module_path: str) -> int:
        """从模块加载规则
        
        Args:
            module_path: 模块路径，如 'src.rules.custom.my_rules'
            
        Returns:
            加载的规则数量
        """
        count = 0
        
        try:
            if module_path in self._loaded_modules:
                module = self._loaded_modules[module_path]
            else:
                module = importlib.import_module(module_path)
                self._loaded_modules[module_path] = module
            
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BaseRule) and 
                    obj is not BaseRule):
                    try:
                        rule_instance = obj()
                        if not self._registry.has(rule_instance.id):
                            self._registry.register(rule_instance)
                            count += 1
                    except Exception as e:
                        print(f"实例化规则 {name} 失败: {e}")
                        
        except ImportError as e:
            print(f"导入模块 {module_path} 失败: {e}")
        
        return count
    
    def load_from_directory(self, directory: Path) -> int:
        """从目录加载规则
        
        Args:
            directory: 规则目录路径
            
        Returns:
            加载的规则数量
        """
        count = 0
        directory = Path(directory)
        
        if not directory.exists():
            return count
        
        for py_file in directory.rglob("*.py"):
            if py_file.name.startswith("_"):
                continue
            
            module_path = self._path_to_module(py_file)
            count += self.load_from_module(module_path)
        
        return count
    
    def _path_to_module(self, file_path: Path) -> str:
        """将文件路径转换为模块路径"""
        parts = list(file_path.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts)
    
    def load_from_config(self, config: Dict[str, Any]) -> int:
        """从配置加载规则
        
        Args:
            config: 配置字典
            
        Returns:
            加载的规则数量
        """
        count = 0
        
        enabled_rules = config.get("enabled", [])
        for rule_path in enabled_rules:
            if ":" in rule_path:
                module_path, class_name = rule_path.rsplit(":", 1)
                count += self._load_single_rule(module_path, class_name)
            else:
                count += self.load_from_module(rule_path)
        
        return count
    
    def _load_single_rule(self, module_path: str, class_name: str) -> int:
        """加载单个规则类
        
        Args:
            module_path: 模块路径
            class_name: 规则类名
            
        Returns:
            加载的规则数量 (0 或 1)
        """
        try:
            module = importlib.import_module(module_path)
            rule_class = getattr(module, class_name)
            
            if issubclass(rule_class, BaseRule):
                rule_instance = rule_class()
                if not self._registry.has(rule_instance.id):
                    self._registry.register(rule_instance)
                    return 1
        except (ImportError, AttributeError) as e:
            print(f"加载规则 {module_path}:{class_name} 失败: {e}")
        
        return 0
    
    def reload_rules(self) -> int:
        """重新加载所有规则
        
        Returns:
            加载的规则数量
        """
        self._registry.clear()
        return self.load_builtin_rules()
    
    def get_loaded_modules(self) -> List[str]:
        """获取已加载的模块列表"""
        return list(self._loaded_modules.keys())


def load_rules_from_directory(directory: Path) -> int:
    """从目录加载规则的便捷函数
    
    Args:
        directory: 规则目录路径
        
    Returns:
        加载的规则数量
    """
    loader = RuleLoader()
    return loader.load_from_directory(directory)


def load_rules_from_config(config: Dict[str, Any]) -> int:
    """从配置加载规则的便捷函数
    
    Args:
        config: 配置字典
        
    Returns:
        加载的规则数量
    """
    loader = RuleLoader()
    return loader.load_from_config(config)
