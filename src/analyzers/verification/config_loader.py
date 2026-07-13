from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
import time


class ConfigLoader:
    """
    配置加载器

    职责：
    - 加载 YAML 配置文件
    - 管理验证器配置
    - 管理规则配置
    - 支持配置热更新
    """

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.validators_config: Dict[str, List[Dict[str, Any]]] = {}
        self.rules_config: Dict[str, Any] = {}
        self.global_config: Dict[str, Any] = {}
        self._last_modified: float = 0
        self._load_config()

    def _load_config(self):
        """加载配置文件"""
        if not self.config_path.exists():
            self._create_default_config()
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or {}

            self.validators_config = self.config.get('validators', {})
            self.rules_config = self.config.get('rules', {})
            self.global_config = self.config.get('global', {})

            self._last_modified = self.config_path.stat().st_mtime

        except Exception as e:
            print(f"Failed to load config from {self.config_path}: {e}")
            self._create_default_config()

    def _create_default_config(self):
        """创建默认配置"""
        self.config = {
            'validators': {
                'sql_injection': [
                    {'name': 'mybatis_dollar_brace', 'enabled': True, 'priority': 'high'},
                    {'name': 'entity_wrapper_safe', 'enabled': True, 'priority': 'medium'},
                    {'name': 'string_concat', 'enabled': True, 'priority': 'high'},
                ],
                'auth_bypass': [
                    {'name': 'csrf_disabled', 'enabled': True, 'priority': 'high'},
                    {'name': 'permit_all_wildcard', 'enabled': True, 'priority': 'high'},
                    {'name': 'wildcard_bypass', 'enabled': True, 'priority': 'medium'},
                ],
                'secrets': [
                    {'name': 'code_hardcoded', 'enabled': True, 'priority': 'high'},
                    {'name': 'config_stored', 'enabled': True, 'priority': 'medium'},
                    {'name': 'database_stored', 'enabled': True, 'priority': 'low'},
                ],
                'ssrf': [
                    {'name': 'resttemplate', 'enabled': True, 'priority': 'high'},
                    {'name': 'url_controllable', 'enabled': True, 'priority': 'high'},
                ],
                'deserialization': [
                    {'name': 'objectinputstream', 'enabled': True, 'priority': 'high'},
                    {'name': 'jackson_config', 'enabled': True, 'priority': 'medium'},
                ],
            },
            'rules': {
                'sql_injection': {
                    'confidence_threshold': 0.7,
                    'min_evidence_count': 2,
                    'check_hardcoded': True,
                },
                'auth_bypass': {
                    'confidence_threshold': 0.6,
                    'check_annotation': True,
                },
                'secrets': {
                    'confidence_threshold': 0.8,
                    'allow_config_center': True,
                },
                'ssrf': {
                    'confidence_threshold': 0.7,
                    'check_url_validation': True,
                },
                'deserialization': {
                    'confidence_threshold': 0.8,
                    'check_input_validation': True,
                },
            },
            'global': {
                'verification_enabled': False,
                'auto_generate_poc': False,
                'output_reports_dir': 'reports/verified',
                'pocs_output_dir': 'dynamic_code/pocs/generated',
                'methods_storage_dir': 'dynamic_code/methods',
                'max_verification_time': 300,
                'parallel_workers': 4,
            }
        }

        self.validators_config = self.config.get('validators', {})
        self.rules_config = self.config.get('rules', {})
        self.global_config = self.config.get('global', {})

        self.save_config()

    def save_config(self):
        """保存配置到文件"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, allow_unicode=True, sort_keys=False)

            self._last_modified = self.config_path.stat().st_mtime

        except Exception as e:
            print(f"Failed to save config to {self.config_path}: {e}")

    def reload_if_modified(self) -> bool:
        """
        如果配置文件被修改则重新加载

        Returns:
            是否重新加载了配置
        """
        if not self.config_path.exists():
            return False

        current_mtime = self.config_path.stat().st_mtime

        if current_mtime > self._last_modified:
            self._load_config()
            return True

        return False

    def get_validator_config(self, vuln_type: str) -> List[Dict[str, Any]]:
        """
        获取漏洞类型的验证器配置

        Args:
            vuln_type: 漏洞类型

        Returns:
            验证器配置列表
        """
        return self.validators_config.get(vuln_type, [])

    def get_enabled_validators(self, vuln_type: str) -> List[str]:
        """
        获取启用的验证器列表

        Args:
            vuln_type: 漏洞类型

        Returns:
            启用的验证器名称列表
        """
        validators = self.validators_config.get(vuln_type, [])
        return [v['name'] for v in validators if v.get('enabled', True)]

    def set_validator_enabled(self, vuln_type: str, validator_name: str, enabled: bool):
        """
        设置验证器启用/禁用状态

        Args:
            vuln_type: 漏洞类型
            validator_name: 验证器名称
            enabled: 是否启用
        """
        validators = self.validators_config.get(vuln_type, [])

        for v in validators:
            if v['name'] == validator_name:
                v['enabled'] = enabled
                break
        else:
            validators.append({'name': validator_name, 'enabled': enabled, 'priority': 'medium'})

        self.validators_config[vuln_type] = validators
        self.config['validators'] = self.validators_config
        self.save_config()

    def get_rule_config(self, vuln_type: str) -> Dict[str, Any]:
        """
        获取漏洞类型的规则配置

        Args:
            vuln_type: 漏洞类型

        Returns:
            规则配置
        """
        return self.rules_config.get(vuln_type, {})

    def get_confidence_threshold(self, vuln_type: str) -> float:
        """
        获取漏洞类型的置信度阈值

        Args:
            vuln_type: 漏洞类型

        Returns:
            置信度阈值
        """
        rule = self.rules_config.get(vuln_type, {})
        return rule.get('confidence_threshold', 0.7)

    def get_global_config(self, key: str, default: Any = None) -> Any:
        """
        获取全局配置

        Args:
            key: 配置键
            default: 默认值

        Returns:
            配置值
        """
        return self.global_config.get(key, default)

    def set_global_config(self, key: str, value: Any):
        """
        设置全局配置

        Args:
            key: 配置键
            value: 配置值
        """
        self.global_config[key] = value
        self.config['global'] = self.global_config
        self.save_config()

    def is_verification_enabled(self) -> bool:
        """检查是否启用验证"""
        return self.global_config.get('verification_enabled', False)

    def set_verification_enabled(self, enabled: bool):
        """
        设置验证启用状态

        Args:
            enabled: 是否启用
        """
        self.set_global_config('verification_enabled', enabled)

    def get_all_vuln_types(self) -> List[str]:
        """
        获取所有配置的漏洞类型

        Returns:
            漏洞类型列表
        """
        return list(self.validators_config.keys())

    def get_pocs_output_dir(self) -> str:
        """获取 POC 输出目录"""
        return self.global_config.get('pocs_output_dir', 'dynamic_code/pocs/generated')

    def get_methods_storage_dir(self) -> str:
        """获取方法存储目录"""
        return self.global_config.get('methods_storage_dir', 'dynamic_code/methods')

    def get_reports_output_dir(self) -> str:
        """获取报告输出目录"""
        return self.global_config.get('output_reports_dir', 'reports/verified')
