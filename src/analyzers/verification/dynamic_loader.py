"""动态验证加载器模块

支持扫描、加载、选择和热更新验证器。
"""

import os
import sys
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Type, Any
import yaml

from .interfaces import Validator, ValidationResult, VulnContext


_VALIDATOR_REGISTRY: Dict[str, Type[Validator]] = {}


def register_validator(cls: Type[Validator]) -> Type[Validator]:
    """验证器注册装饰器

    将验证器类注册到全局注册表。
    验证器可以通过此装饰器注册自己。

    Args:
        cls: 验证器类

    Returns:
        原始验证器类
    """
    if hasattr(cls, 'name') and cls.name:
        _VALIDATOR_REGISTRY[cls.name] = cls
    return cls


class DynamicLoader:
    """动态验证加载器

    职责：
    - 扫描 dynamic_code/validators/ 目录
    - 加载验证器模块
    - 根据漏洞类型选择合适的验证器
    - 管理验证器注册表
    - 支持验证器热更新
    """

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.dynamic_code_path = self.project_root / "dynamic_code"
        self.validators_dir = self.dynamic_code_path / "validators"
        self.config_path = self.dynamic_code_path / "config.yaml"

        self._init_import_path()

        self.validators: Dict[str, Validator] = {}
        self.rules: Dict[str, Any] = {}
        self._validator_modules: Dict[str, Type] = {}

        self._load_config()

    def _init_import_path(self) -> None:
        """初始化导入路径，确保 src 模块可导入"""
        src_path = self.project_root / 'src'
        parent_path = self.project_root

        if str(parent_path) not in sys.path:
            sys.path.insert(0, str(parent_path))

        verification_path = self.project_root / 'src' / 'analyzers' / 'verification'
        if str(verification_path) not in sys.path:
            sys.path.insert(0, str(verification_path))

    def _load_config(self) -> None:
        """加载配置文件"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    self.rules = config.get('rules', {}) if config else {}
            except Exception as e:
                print(f"Failed to load config from {self.config_path}: {e}")
                self.rules = {}
        else:
            self.rules = {}

    def reload_config(self) -> None:
        """重新加载配置"""
        self._load_config()

    def scan_validators(self) -> List[str]:
        """扫描 validators 目录，加载所有验证器

        Returns:
            加载的验证器名称列表
        """
        loaded = []

        if not self.validators_dir.exists():
            print(f"Validators directory does not exist: {self.validators_dir}")
            return loaded

        for category_dir in self.validators_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith('_'):
                for validator_file in category_dir.glob("*.py"):
                    if validator_file.name.startswith('_'):
                        continue
                    try:
                        name = self.load_validator(str(validator_file))
                        if name:
                            loaded.append(name)
                    except Exception as e:
                        print(f"Failed to load {validator_file}: {e}")
        return loaded

    def load_validator(self, validator_path: str) -> Optional[str]:
        """加载单个验证器

        Args:
            validator_path: 验证器文件路径

        Returns:
            验证器名称，失败返回 None
        """
        validator_file = Path(validator_path)

        if not validator_file.exists():
            print(f"Validator file does not exist: {validator_path}")
            return None

        module_name = validator_file.stem
        category_name = validator_file.parent.name

        try:
            spec = importlib.util.spec_from_file_location(
                f"validators.{category_name}.{module_name}",
                validator_file
            )
            if spec is None or spec.loader is None:
                print(f"Failed to create module spec for {validator_path}")
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type)
                    and issubclass(attr, Validator)
                    and attr is not Validator
                    and attr_name != 'Validator'):

                    validator_instance = attr()
                    validator_name = getattr(validator_instance, 'name', None)

                    if validator_name:
                        self.validators[validator_name] = validator_instance
                        self._validator_modules[validator_name] = attr
                        self._register_global(validator_instance)
                        return validator_name

            if hasattr(module, 'validate') and callable(getattr(module, 'validate')):
                default_name = f"{category_name}.{module_name}"
                validator_instance = self._create_wrapper_validator(module, default_name)
                if validator_instance:
                    self.validators[default_name] = validator_instance
                    return default_name

        except Exception as e:
            print(f"Error loading validator from {validator_path}: {e}")

        return None

    def _create_wrapper_validator(self, module: Any, name: str) -> Optional[Validator]:
        """创建包装验证器

        Args:
            module: 模块对象
            name: 验证器名称

        Returns:
            包装后的验证器实例
        """
        validate_func = getattr(module, 'validate', None)

        class WrappedValidator(Validator):
            name = name
            vuln_types = getattr(module, 'VULN_TYPES', [])
            description = getattr(module, 'DESCRIPTION', getattr(module, '__doc__', '') or '')
            confidence_level = getattr(module, 'CONFIDENCE_LEVEL', 'medium')

            def verify(self, context: Dict[str, Any]) -> Dict[str, Any]:
                if validate_func:
                    return validate_func(context)
                return {"status": "error", "message": "No validate function"}

        return WrappedValidator()

    def _register_global(self, validator: Validator) -> None:
        """注册到全局注册表

        Args:
            validator: 验证器实例
        """
        if validator.name:
            _VALIDATOR_REGISTRY[validator.name] = validator.__class__

    def select_validators(self, vuln_type: str) -> List[Validator]:
        """根据漏洞类型选择验证器

        Args:
            vuln_type: 漏洞类型，如 "sql_injection", "auth_bypass"

        Returns:
            匹配的验证器列表
        """
        selected = []
        for validator in self.validators.values():
            if hasattr(validator, 'vuln_types') and vuln_type in validator.vuln_types:
                selected.append(validator)
        return selected

    def reload_validator(self, validator_name: str) -> bool:
        """重新加载指定验证器（热更新）

        Args:
            validator_name: 验证器名称

        Returns:
            是否成功
        """
        if validator_name not in self._validator_modules:
            return False

        old_module_path = None
        for path in self._get_validator_paths():
            if path.endswith(f"{validator_name.replace('.', os.sep)}.py"):
                old_module_path = path
                break

        if old_module_path:
            try:
                del sys.modules[old_module_path]
            except KeyError:
                pass

        if old_module_path:
            return self.load_validator(old_module_path) is not None

        return False

    def _get_validator_paths(self) -> List[str]:
        """获取所有已加载验证器的文件路径

        Returns:
            验证器文件路径列表
        """
        paths = []
        for module_name in sys.modules:
            if module_name.startswith('validators.'):
                module = sys.modules[module_name]
                if hasattr(module, '__file__') and module.__file__:
                    paths.append(module.__file__)
        return paths

    def get_validator(self, name: str) -> Optional[Validator]:
        """获取指定验证器

        Args:
            name: 验证器名称

        Returns:
            验证器实例，不存在返回 None
        """
        return self.validators.get(name)

    def list_validators(self) -> List[Dict[str, str]]:
        """列出所有已加载的验证器

        Returns:
            验证器信息列表
        """
        return [
            {
                'name': v.name,
                'types': ', '.join(getattr(v, 'vuln_types', [])),
                'description': getattr(v, 'description', ''),
                'confidence': getattr(v, 'confidence_level', 'medium')
            }
            for v in self.validators.values()
        ]

    def unregister_validator(self, name: str) -> bool:
        """取消注册验证器

        Args:
            name: 验证器名称

        Returns:
            是否成功
        """
        if name in self.validators:
            del self.validators[name]
        if name in _VALIDATOR_REGISTRY:
            del _VALIDATOR_REGISTRY[name]
        return True

    def clear(self) -> None:
        """清空所有已加载的验证器"""
        self.validators.clear()
        self._validator_modules.clear()


def get_registry_validators() -> Dict[str, Type[Validator]]:
    """获取全局注册表中的验证器

    Returns:
        注册的验证器字典
    """
    return _VALIDATOR_REGISTRY.copy()
