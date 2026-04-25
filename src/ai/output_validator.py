"""输出验证器模块

提供统一的输出验证接口，基于 SchemaValidator。
"""

from typing import Any, Dict, Optional

from src.ai.pure_ai.schema_validator import SchemaValidator
from src.ai.pure_ai.schema import (
    FINAL_DECISION_SCHEMA,
    VULNERABILITY_SCHEMA,
    ADVERSARIAL_SCHEMA,
    RISK_ENUMERATION_SCHEMA,
    ATTACK_CHAIN_SCHEMA,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


class OutputValidator:
    """输出验证器

    统一验证所有 Agent 输出，确保符合 Schema 规范。
    """

    _instance: Optional['OutputValidator'] = None

    def __init__(self):
        self._validator = SchemaValidator()
        self._schema_map = {
            "context_builder": None,
            "code_understanding": None,
            "risk_enumeration": RISK_ENUMERATION_SCHEMA,
            "vulnerability_verification": VULNERABILITY_SCHEMA,
            "attack_chain": ATTACK_CHAIN_SCHEMA,
            "adversarial_validation": ADVERSARIAL_SCHEMA,
            "final_decision": FINAL_DECISION_SCHEMA,
        }

    @classmethod
    def get_instance(cls) -> 'OutputValidator':
        """获取单例实例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def validate(self, data: Any, agent_name: str) -> tuple[bool, Optional[str]]:
        """验证数据是否符合对应 Agent 的 Schema

        Args:
            data: 待验证的数据
            agent_name: Agent 名称

        Returns:
            (是否通过, 错误信息)
        """
        schema = self._schema_map.get(agent_name)
        if schema is None:
            logger.debug(f"No schema for agent {agent_name}, skipping validation")
            return True, None

        is_valid, error = self._validator.validate(data, agent_name)
        if not is_valid:
            logger.warning(f"Schema validation failed for {agent_name}: {error}")
        return is_valid, error

    def validate_with_fallback(self, data: Any, agent_name: str) -> Dict[str, Any]:
        """验证数据，如果不符合 Schema 则尝试修复

        Args:
            data: 待验证的数据
            agent_name: Agent 名称

        Returns:
            修复后的数据
        """
        return self._validator.validate_with_fallback(data, agent_name)

    def parse_and_validate(
        self,
        response_text: str,
        agent_name: str
    ) -> Optional[Dict[str, Any]]:
        """解析 JSON 响应并验证

        Args:
            response_text: AI 响应文本
            agent_name: Agent 名称

        Returns:
            验证后的数据或 None
        """
        return self._validator.parse_json_response(response_text, agent_name)


def get_output_validator() -> OutputValidator:
    """获取 OutputValidator 实例"""
    return OutputValidator.get_instance()
