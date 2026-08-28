"""数据保护类安全规则

包含敏感数据暴露、PII 泄露等检测规则。
"""

from src.rules.builtin.data_protection.sensitive_data_exposure import SensitiveDataExposureRule

__all__ = ["SensitiveDataExposureRule"]
