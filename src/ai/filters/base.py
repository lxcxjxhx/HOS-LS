"""过滤器基类

提供误报过滤的抽象接口。
"""

from abc import ABC, abstractmethod
from typing import Any, List

from src.ai.models import VulnerabilityFinding


class BaseFilter(ABC):
    """过滤器基类"""

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def filter(
        self, findings: List[VulnerabilityFinding]
    ) -> List[VulnerabilityFinding]:
        """过滤发现

        Args:
            findings: 发现列表

        Returns:
            过滤后的发现列表
        """
        pass

    def should_filter(self, finding: VulnerabilityFinding) -> bool:
        """判断是否过滤单个发现

        Args:
            finding: 单个发现

        Returns:
            是否过滤
        """
        return False
