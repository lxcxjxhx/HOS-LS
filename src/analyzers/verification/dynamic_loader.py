"""动态验证加载器模块

支持扫描、加载、选择和热更新验证器。
"""

import os
import sys
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Type, Any
from concurrent.futures import ThreadPoolExecutor
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

        self._vuln_type_index: Dict[str, List[Validator]] = {}
        self._validator_cache: Dict[str, Validator] = {}
        self.parallel_workers: int = 4

        self._load_config()
        self._build_type_index()

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
                    self.parallel_workers = config.get('parallel_workers', 4) if config else 4
            except Exception as e:
                print(f"Failed to load config from {self.config_path}: {e}")
                self.rules = {}
                self.parallel_workers = 4
        else:
            self.rules = {}
            self.parallel_workers = 4

    def reload_config(self) -> None:
        """重新加载配置"""
        self._load_config()

    def _build_type_index(self) -> None:
        """构建漏洞类型索引"""
        self._vuln_type_index.clear()
        for validator in self.validators.values():
            if hasattr(validator, 'vuln_types') and validator.vuln_types:
                for vuln_type in validator.vuln_types:
                    if vuln_type not in self._vuln_type_index:
                        self._vuln_type_index[vuln_type] = []
                    self._vuln_type_index[vuln_type].append(validator)

    def _invalidate_cache(self) -> None:
        """使验证器缓存失效"""
        self._validator_cache.clear()
        self._build_type_index()

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
        self._invalidate_cache()
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
                        self._invalidate_cache()
                        return validator_name

            if hasattr(module, 'validate') and callable(getattr(module, 'validate')):
                default_name = f"{category_name}.{module_name}"
                validator_instance = self._create_wrapper_validator(module, default_name)
                if validator_instance:
                    self.validators[default_name] = validator_instance
                    self._invalidate_cache()
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
        """根据漏洞类型选择验证器（O(1)索引查找）

        Args:
            vuln_type: 漏洞类型，如 "sql_injection", "auth_bypass"

        Returns:
            匹配的验证器列表
        """
        return self._vuln_type_index.get(vuln_type, [])

    def select_validators_parallel(self, vuln_types: List[str]) -> Dict[str, List[Validator]]:
        """根据多个漏洞类型并行选择验证器

        Args:
            vuln_types: 漏洞类型列表

        Returns:
            漏洞类型到验证器列表的映射
        """
        result = {}
        for vuln_type in vuln_types:
            result[vuln_type] = self.select_validators(vuln_type)
        return result

    def _validate_parallel(self, validators: List[Validator], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """并行执行验证

        Args:
            validators: 验证器列表
            context: 验证上下文

        Returns:
            验证结果列表
        """
        if not validators:
            return []

        results = []
        with ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
            future_to_validator = {
                executor.submit(self._execute_validator, validator, context): validator
                for validator in validators
            }
            for future in future_to_validator:
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    validator = future_to_validator[future]
                    results.append({
                        "validator": getattr(validator, 'name', 'unknown'),
                        "status": "error",
                        "message": str(e)
                    })
        return results

    def _execute_validator(self, validator: Validator, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行单个验证器

        Args:
            validator: 验证器实例
            context: 验证上下文

        Returns:
            验证结果
        """
        try:
            return validator.verify(context)
        except Exception as e:
            return {
                "validator": getattr(validator, 'name', 'unknown'),
                "status": "error",
                "message": str(e)
            }

    def get_validator(self, name: str) -> Optional[Validator]:
        """获取指定验证器（带缓存）

        Args:
            name: 验证器名称

        Returns:
            验证器实例，不存在返回 None
        """
        if name in self._validator_cache:
            return self._validator_cache[name]

        validator = self.validators.get(name)
        if validator:
            self._validator_cache[name] = validator
        return validator

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
            result = self.load_validator(old_module_path) is not None
            self._invalidate_cache()
            return result

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
        self._invalidate_cache()
        return True

    def clear(self) -> None:
        """清空所有已加载的验证器"""
        self.validators.clear()
        self._validator_modules.clear()
        self._validator_cache.clear()
        self._vuln_type_index.clear()


def get_registry_validators() -> Dict[str, Type[Validator]]:
    """获取全局注册表中的验证器

    Returns:
        注册的验证器字典
    """
    return _VALIDATOR_REGISTRY.copy()