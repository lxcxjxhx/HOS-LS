"""内置安全规则模块

提供开箱即用的安全检测规则。
"""

from src.rules.builtin.injection.sql_injection import SQLInjectionRule
from src.rules.builtin.injection.command_injection import CommandInjectionRule
from src.rules.builtin.injection.xss import XSSRule
from src.rules.builtin.authentication.hardcoded_credentials import HardcodedCredentialsRule
from src.rules.builtin.cryptography.weak_crypto import WeakCryptoRule
from src.rules.builtin.cryptography.hardcoded_keys import HardcodedKeysRule
from src.rules.builtin.cryptography.insecure_random import InsecureRandomRule
from src.rules.builtin.data_protection.sensitive_data_exposure import SensitiveDataExposureRule
from src.rules.builtin.ai_security.prompt_injection import (
    DirectPromptInjectionRule,
    InstructionOverrideRule,
    ContextOverflowRule,
)
from src.rules.builtin.ai_security.encoding_issues import (
    HomoglyphAttackRule,
    UnicodeNormalizationRule,
    BidirectionalTextInjectionRule,
)
from src.rules.builtin.ai_security.output_control import (
    UnvalidatedModelOutputRule,
    SchemaValidationMissingRule,
    HallucinationRiskRule,
    OutputSafetyFilterMissingRule,
)
from src.rules.builtin.ai_security.insecure_design import (
    IDORRule,
    BusinessLogicFlawRule,
    RaceConditionRule,
)
from src.rules.builtin.ai_security.logging_security import (
    MissingSecurityEventLoggingRule,
    InsufficientAuditTrailRule,
    SensitiveDataInLogsRule,
)

__all__ = [
    "SQLInjectionRule",
    "CommandInjectionRule",
    "XSSRule",
    "HardcodedCredentialsRule",
    "WeakCryptoRule",
    "HardcodedKeysRule",
    "InsecureRandomRule",
    "SensitiveDataExposureRule",
    "DirectPromptInjectionRule",
    "InstructionOverrideRule",
    "ContextOverflowRule",
    "HomoglyphAttackRule",
    "UnicodeNormalizationRule",
    "BidirectionalTextInjectionRule",
    "UnvalidatedModelOutputRule",
    "SchemaValidationMissingRule",
    "HallucinationRiskRule",
    "OutputSafetyFilterMissingRule",
    "IDORRule",
    "BusinessLogicFlawRule",
    "RaceConditionRule",
    "MissingSecurityEventLoggingRule",
    "InsufficientAuditTrailRule",
    "SensitiveDataInLogsRule",
    "load_all_rules",
]


def load_all_rules():
    """加载所有内置规则

    Returns:
        规则实例列表
    """
    return [
        SQLInjectionRule(),
        CommandInjectionRule(),
        XSSRule(),
        HardcodedCredentialsRule(),
        WeakCryptoRule(),
        HardcodedKeysRule(),
        InsecureRandomRule(),
        SensitiveDataExposureRule(),
        DirectPromptInjectionRule(),
        InstructionOverrideRule(),
        ContextOverflowRule(),
        HomoglyphAttackRule(),
        UnicodeNormalizationRule(),
        BidirectionalTextInjectionRule(),
        UnvalidatedModelOutputRule(),
        SchemaValidationMissingRule(),
        HallucinationRiskRule(),
        OutputSafetyFilterMissingRule(),
        IDORRule(),
        BusinessLogicFlawRule(),
        RaceConditionRule(),
        MissingSecurityEventLoggingRule(),
        InsufficientAuditTrailRule(),
        SensitiveDataInLogsRule(),
    ]
