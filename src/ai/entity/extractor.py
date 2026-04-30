"""AI 实体提取器

提供基于AI的命名实体识别和语义角色标注，用于从用户输入中提取结构化实体。
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path

from src.ai.models import AIRequest
from src.ai.client import AIModelManager, get_model_manager
from src.core.config import Config, get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ExtractedEntity:
    """提取的实体"""
    type: str
    value: str
    confidence: float = 1.0
    start_pos: int = 0
    end_pos: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "confidence": self.confidence,
            "start_pos": self.start_pos,
            "end_pos": self.end_pos,
            "metadata": self.metadata,
        }


@dataclass
class EntityExtractionResult:
    """实体提取结果"""
    entities: List[ExtractedEntity]
    raw_entities: List[Dict[str, Any]] = field(default_factory=list)
    method: str = "ai_model"
    confidence: float = 1.0

    def get_by_type(self, entity_type: str) -> List[ExtractedEntity]:
        """按类型获取实体"""
        return [e for e in self.entities if e.type == entity_type]

    def get_first(self, entity_type: str) -> Optional[ExtractedEntity]:
        """获取第一个指定类型的实体"""
        entities = self.get_by_type(entity_type)
        return entities[0] if entities else None

    @property
    def target_path(self) -> Optional[str]:
        """获取目标路径"""
        entity = self.get_first("path") or self.get_first("file") or self.get_first("directory")
        return entity.value if entity else None

    @property
    def vulnerability_types(self) -> List[str]:
        """获取漏洞类型列表"""
        return [e.value for e in self.get_by_type("vulnerability_type")]

    @property
    def has_high_confidence(self) -> bool:
        """是否高置信度"""
        return self.confidence >= 0.7 and all(e.confidence >= 0.6 for e in self.entities)


class FallbackEntityExtractor:
    """Fallback规则实体提取器"""

    PATH_PATTERNS = [
        r'(?:扫描|分析|检查|查看|看看)\s+([^\s]+)',
        r'(?:target|目标)\s*:?\s*([^\s]+)',
        r'@file\s+([^\s]+)',
        r'(?:在|到)\s+([^\s]+)\s*(?:目录|文件夹|文件)',
    ]

    VULNERABILITY_KEYWORDS = [
        "sql注入", "xss", "命令注入", "sql_injection", "command_injection",
        "敏感信息", "密码", "密钥", "api_key", "token", "hardcoded",
        "注入", "越权", "绕过", "csrf", "ssrf", "xxe", "rce", "lfi", "rfi",
    ]

    def extract(self, user_input: str) -> List[ExtractedEntity]:
        """使用规则提取实体"""
        entities = []

        for pattern in self.PATH_PATTERNS:
            for match in re.finditer(pattern, user_input):
                value = match.group(1).strip()
                if value and len(value) > 0:
                    entities.append(ExtractedEntity(
                        type="path",
                        value=value,
                        confidence=0.7,
                        start_pos=match.start(),
                        end_pos=match.end()
                    ))

        for keyword in self.VULNERABILITY_KEYWORDS:
            if keyword in user_input.lower():
                entities.append(ExtractedEntity(
                    type="vulnerability_type",
                    value=keyword,
                    confidence=0.6,
                    metadata={"source": "keyword_match"}
                ))

        return entities


class AIEntityExtractor:
    """AI实体提取器

    使用AI模型进行实体识别，支持置信度阈值和fallback机制。
    """

    CONFIDENCE_THRESHOLD = 0.6

    SYSTEM_PROMPT = """你是一个实体提取专家。从用户输入中提取结构化实体。

实体类型：
- path: 文件路径或目录，如"src/auth.py"、"src目录"
- vulnerability_type: 漏洞类型，如"SQL注入"、"XSS"、"命令注入"
- function_name: 函数名，如"authenticate"、"login"
- class_name: 类名，如"SecurityAgent"
- scope: 范围，如"整个项目"、"指定目录"
- depth: 深度，如"深度"、"详细"、"快速"
- language: 编程语言，如"Python"、"JavaScript"

请以JSON格式返回结果：
{
    "entities": [
        {
            "type": "实体类型",
            "value": "实体值",
            "confidence": 0.0-1.0,
            "start_pos": 起始位置,
            "end_pos": 结束位置
        }
    ],
    "reasoning": "提取理由"
}

只返回JSON，不要有其他内容。"""

    FEW_SHOT_EXAMPLES = """
示例：
输入: "扫描src目录下的auth.py有什么漏洞"
输出: {
    "entities": [
        {"type": "path", "value": "src/auth.py", "confidence": 0.95, "start_pos": 5, "end_pos": 15},
        {"type": "vulnerability_type", "value": "sql注入", "confidence": 0.8, "start_pos": 16, "end_pos": 21}
    ],
    "reasoning": "识别出要扫描的文件路径和关注的漏洞类型"
}

输入: "帮我深度审计一下项目的安全问题，重点看SQL注入和XSS"
输出: {
    "entities": [
        {"type": "depth", "value": "深度", "confidence": 0.9, "start_pos": 3, "end_pos": 5},
        {"type": "scope", "value": "项目", "confidence": 0.85, "start_pos": 9, "end_pos": 11},
        {"type": "vulnerability_type", "value": "SQL注入", "confidence": 0.95, "start_pos": 18, "end_pos": 23},
        {"type": "vulnerability_type", "value": "XSS", "confidence": 0.95, "start_pos": 25, "end_pos": 28}
    ],
    "reasoning": "识别出审计深度、范围和重点漏洞类型"
}"""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._manager: Optional[AIModelManager] = None
        self._fallback_extractor = FallbackEntityExtractor()
        self._initialized = False

    async def initialize(self) -> None:
        """初始化提取器"""
        if not self._initialized:
            self._manager = await get_model_manager(self.config)
            self._initialized = True

    async def extract(self, user_input: str) -> EntityExtractionResult:
        """提取实体

        Args:
            user_input: 用户输入的自然语言

        Returns:
            实体提取结果
        """
        if not self._initialized:
            await self.initialize()

        if not user_input or not user_input.strip():
            return EntityExtractionResult(entities=[], method="empty_input")

        try:
            result = await self._ai_extract(user_input)

            if result.has_high_confidence:
                return result

            fallback_entities = self._fallback_extractor.extract(user_input)
            if fallback_entities:
                fallback_result = EntityExtractionResult(
                    entities=fallback_entities,
                    method="fallback_rules"
                )
                return fallback_result

            return result

        except Exception as e:
            logger.warning(f"AI entity extraction failed: {e}, using fallback")

            fallback_entities = self._fallback_extractor.extract(user_input)
            if fallback_entities:
                return EntityExtractionResult(
                    entities=fallback_entities,
                    method="fallback_exception"
                )

            return EntityExtractionResult(entities=[], method="error")

    async def _ai_extract(self, user_input: str) -> EntityExtractionResult:
        """使用AI模型提取实体"""
        prompt = self._build_extraction_prompt(user_input)

        request = AIRequest(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.1,
            max_tokens=512,
            model=self.config.ai.model,
        )

        response = await self._manager.generate(request)

        return self._parse_extraction_response(response.content, user_input)

    def _build_extraction_prompt(self, user_input: str) -> str:
        """构建提取提示"""
        return f"{self.FEW_SHOT_EXAMPLES}\n\n输入: \"{user_input}\"\n输出:"

    def _parse_extraction_response(
        self, content: str, original_input: str
    ) -> EntityExtractionResult:
        """解析AI提取响应"""
        import json
        import re

        try:
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
            else:
                data = json.loads(content)

            entities_data = data.get("entities", [])

            entities = []
            for e in entities_data:
                entity = ExtractedEntity(
                    type=e.get("type", "unknown"),
                    value=e.get("value", ""),
                    confidence=float(e.get("confidence", 0.5)),
                    start_pos=int(e.get("start_pos", 0)),
                    end_pos=int(e.get("end_pos", 0)),
                    metadata={"reasoning": data.get("reasoning", "")}
                )
                entities.append(entity)

            avg_confidence = sum(e.confidence for e in entities) / len(entities) if entities else 0.0

            return EntityExtractionResult(
                entities=entities,
                raw_entities=entities_data,
                method="ai_model",
                confidence=avg_confidence
            )

        except Exception as e:
            logger.error(f"Failed to parse extraction response: {e}")
            return EntityExtractionResult(entities=[], method="parse_error")

    async def extract_batch(
        self, inputs: List[str]
    ) -> List[EntityExtractionResult]:
        """批量提取实体

        Args:
            inputs: 用户输入列表

        Returns:
            提取结果列表
        """
        if not self._initialized:
            await self.initialize()

        results = []
        for user_input in inputs:
            result = await self.extract(user_input)
            results.append(result)

        return results

    def infer_entity_type(self, value: str) -> str:
        """推断实体类型"""
        path_indicators = [".py", ".js", ".ts", ".java", ".go", ".cpp", ".c", "/", "\\", "src", "dist", "app"]
        if any(ind in value for ind in path_indicators):
            return "path"

        vuln_indicators = ["注入", "xss", "sql", "csrf", "ssrf", "rce", "lfi"]
        if any(ind in value.lower() for ind in vuln_indicators):
            return "vulnerability_type"

        func_indicators = ["(", ")", "def ", "function "]
        if any(ind in value for ind in func_indicators):
            return "function_name"

        return "unknown"
