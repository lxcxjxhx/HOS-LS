"""规则加载器模块

提供规则的自动发现、加载和管理功能。
"""

import importlib
import inspect
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from src.rules.base import BaseRule, RuleDefinition
from src.rules.registry import RuleRegistry, get_registry


class SourceSinkMatcher:
    """Source/Sink 模式匹配器

    用于检测代码中的 source 和 sink 模式。
    """

    def __init__(self):
        self._source_patterns: Dict[str, List[re.Pattern]] = {}
        self._sink_patterns: Dict[str, List[re.Pattern]] = {}
        self._sanitizer_patterns: Dict[str, List[re.Pattern]] = {}

    def load_rules(self, rules: List[RuleDefinition]) -> None:
        for rule in rules:
            if not rule.enabled:
                continue

            for lang in rule.languages:
                if lang not in self._source_patterns:
                    self._source_patterns[lang] = []
                    self._sink_patterns[lang] = []
                    self._sanitizer_patterns[lang] = []

                for source in rule.sources:
                    try:
                        pattern = re.compile(self._wildcard_to_regex(source))
                        self._source_patterns[lang].append(pattern)
                    except re.error:
                        pass

                for sink in rule.sinks:
                    try:
                        pattern = re.compile(self._wildcard_to_regex(sink))
                        self._sink_patterns[lang].append(pattern)
                    except re.error:
                        pass

                for sanitizer in rule.sanitizers:
                    try:
                        pattern = re.compile(self._wildcard_to_regex(sanitizer))
                        self._sanitizer_patterns[lang].append(pattern)
                    except re.error:
                        pass

    def _wildcard_to_regex(self, pattern: str) -> str:
        regex = re.escape(pattern)
        regex = regex.replace(r"\*\*", ".*")
        regex = regex.replace(r"\*", "[^.]*")
        return regex

    def match_source(self, code: str, language: str) -> List[str]:
        matches = []
        patterns = self._source_patterns.get(language, [])
        for pattern in patterns:
            for match in pattern.finditer(code):
                matches.append(match.group())
        return matches

    def match_sink(self, code: str, language: str) -> List[str]:
        matches = []
        patterns = self._sink_patterns.get(language, [])
        for pattern in patterns:
            for match in pattern.finditer(code):
                matches.append(match.group())
        return matches

    def match_sanitizer(self, code: str, language: str) -> List[str]:
        matches = []
        patterns = self._sanitizer_patterns.get(language, [])
        for pattern in patterns:
            for match in pattern.finditer(code):
                matches.append(match.group())
        return matches

    def has_sanitizer(self, code: str, language: str) -> bool:
        return len(self.match_sanitizer(code, language)) > 0


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

    def load_from_json(self, json_path: Path) -> int:
        """从 JSON 文件加载规则

        Args:
            json_path: JSON 规则文件路径

        Returns:
            加载的规则数量
        """
        count = 0

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"加载 JSON 规则失败: {e}")
            return 0

        rules_data = data if isinstance(data, list) else data.get("rules", [])

        for rule_data in rules_data:
            try:
                rule_def = RuleDefinition.from_dict(rule_data)
                if not self._registry.has(rule_def.id):
                    self._registry.register(rule_def)
                    count += 1
            except Exception as e:
                print(f"解析规则失败: {e}")

        return count

    def load_json_rules(self, rules_dir: Path) -> int:
        """从目录加载所有 JSON 规则文件

        Args:
            rules_dir: 规则目录路径

        Returns:
            加载的规则数量
        """
        count = 0
        rules_dir = Path(rules_dir)

        if not rules_dir.exists():
            return 0

        for json_file in rules_dir.rglob("*.json"):
            count += self.load_from_json(json_file)

        return count


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
