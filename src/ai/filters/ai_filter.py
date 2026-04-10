"""AI 误报过滤器

使用 AI 判断发现是否为误报。
"""

from typing import List, Optional

from src.ai.filters.base import BaseFilter
from src.ai.json_parser import SmartJSONParser
from src.ai.models import AIRequest, VulnerabilityFinding
from src.core.config import Config, get_config


class AIFalsePositiveFilter(BaseFilter):
    """AI 误报过滤器"""

    def __init__(
        self,
        config: Optional[Config] = None,
        confidence_threshold: float = 0.7,
    ) -> None:
        super().__init__("ai_false_positive_filter")
        self.config = config or get_config()
        self.confidence_threshold = confidence_threshold
        self._json_parser = SmartJSONParser()
        self._system_prompt = self._load_system_prompt()

    def _load_system_prompt(self) -> str:
        """加载系统提示"""
        return """你是一个代码安全分析专家。你的任务是判断给定的安全问题是否为误报。

请分析提供的代码片段和问题描述，判断这是否是一个真正的安全问题。

请以 JSON 格式输出你的判断：
{
    "is_false_positive": true/false,
    "confidence": 0.0-1.0,
    "reason": "判断理由",
    "suggestion": "如果不是误报，提供修复建议"
}

注意：
- 只有在非常确定是误报时才返回 is_false_positive: true
- confidence 应该反映你的确定程度
- 提供详细的判断理由"""

    async def filter(
        self, findings: List[VulnerabilityFinding]
    ) -> List[VulnerabilityFinding]:
        """过滤发现"""
        from src.ai.client import get_model_manager
        manager = await get_model_manager(self.config)
        filtered = []

        for finding in findings:
            if not await self._is_false_positive(manager, finding):
                filtered.append(finding)

        return filtered

    async def _is_false_positive(
        self, manager: 'AIModelManager', finding: VulnerabilityFinding
    ) -> bool:
        """判断是否为误报"""
        prompt = self._build_prompt(finding)

        request = AIRequest(
            prompt=prompt,
            system_prompt=self._system_prompt,
            temperature=0.0,
            max_tokens=1024,
        )

        try:
            response = await manager.generate(request)
            result = self._json_parser.parse(response.content)

            if result and result.get("is_false_positive", False):
                confidence = result.get("confidence", 0.0)
                return confidence >= self.confidence_threshold

        except Exception:
            # 如果 AI 判断失败，保留发现
            return False

        return False

    def _build_prompt(self, finding: VulnerabilityFinding) -> str:
        """构建提示"""
        return f"""请判断以下安全问题是否为误报：

规则 ID: {finding.rule_id}
规则名称: {finding.rule_name}
问题描述: {finding.description}
严重级别: {finding.severity}
置信度: {finding.confidence}

代码片段:
```
{finding.code_snippet}
```

问题解释: {finding.explanation}
"""

    def should_filter(self, finding: VulnerabilityFinding) -> bool:
        """判断是否过滤（同步版本）"""
        # 这里可以实现简单的硬规则过滤
        # 例如：过滤掉某些已知误报模式
        return False
