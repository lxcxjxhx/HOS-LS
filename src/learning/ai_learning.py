"""AI驱动的自学习模块

利用AI从扫描结果和用户反馈中学习，改进漏洞检测和分类能力。
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union

from src.ai.client import AIModelManager, get_model_manager
from src.ai.models import AIRequest, AIResponse, SecurityAnalysisResult, VulnerabilityFinding
from src.ai.prompts import get_prompt_manager
from src.learning.self_learning import (
    SelfLearning, LearningConfig, Feedback, FeedbackType, 
    ScanResult, Pattern, Knowledge, KnowledgeType
)
from src.utils.logger import get_logger
from src.core.config import Config, get_config

logger = get_logger(__name__)


@dataclass
class AILearningConfig:
    """AI学习配置"""
    enable_ai_learning: bool = True
    min_samples_for_ai_learning: int = 3
    confidence_threshold: float = 0.7
    learning_rate: float = 0.1
    model_name: Optional[str] = None
    max_learning_iterations: int = 100


@dataclass
class AILearningResult:
    """AI学习结果"""
    patterns: List[Pattern]
    knowledge: List[Knowledge]
    improvement_suggestions: List[Dict[str, Any]]
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class AIDrivenLearning:
    """AI驱动的自学习系统"""

    def __init__(self, config: Optional[Config] = None):
        """初始化AI驱动的自学习系统

        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self._ai_config = AILearningConfig(
            enable_ai_learning=self.config.ai.enable_learning,
            model_name=self.config.ai.model
        )
        self._self_learning = SelfLearning()
        self._manager: Optional[AIModelManager] = None
        self._prompt_manager = get_prompt_manager(self.config)
        self._system_prompt = self._load_system_prompt()

    def _load_system_prompt(self) -> str:
        """加载AI学习系统提示"""
        return self._prompt_manager.get_prompt("ai_learning")

    async def initialize(self) -> None:
        """初始化AI驱动的学习系统"""
        from src.ai.client import _manager
        _manager = None
        self._manager = await get_model_manager(self.config)

    async def learn_from_scan_results(self, scan_results: List[ScanResult]) -> AILearningResult:
        """从扫描结果中学习

        Args:
            scan_results: 扫描结果列表

        Returns:
            AI学习结果
        """
        if not self._ai_config.enable_ai_learning:
            return AILearningResult(
                patterns=[],
                knowledge=[],
                improvement_suggestions=[],
                confidence=0.0
            )

        await self.initialize()

        # 首先使用传统自学习
        for result in scan_results:
            self._self_learning.learn_from_result(result)

        # 提取学习数据
        learning_data = self._extract_learning_data(scan_results)

        # 使用AI分析学习数据
        ai_insights = await self._analyze_with_ai(learning_data)

        # 处理AI洞察
        patterns, knowledge, suggestions = self._process_ai_insights(ai_insights)

        # 更新知识库
        for pattern in patterns:
            self._self_learning._patterns[pattern.id] = pattern

        for knowledge_item in knowledge:
            self._self_learning.update_knowledge_base(knowledge_item)

        return AILearningResult(
            patterns=patterns,
            knowledge=knowledge,
            improvement_suggestions=suggestions,
            confidence=ai_insights.get("confidence", 0.7)
        )

    def _extract_learning_data(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """提取学习数据

        Args:
            scan_results: 扫描结果列表

        Returns:
            学习数据
        """
        findings = []
        for result in scan_results:
            findings.extend(result.findings)

        # 统计数据
        severity_counts = {}
        type_counts = {}
        for finding in findings:
            severity = finding.get("severity", "medium")
            vuln_type = finding.get("vulnerability_type", "other")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

        # 提取模式
        patterns = self._self_learning.get_all_patterns()
        knowledge = self._self_learning.get_all_knowledge()

        return {
            "findings": findings,
            "scan_count": len(scan_results),
            "finding_count": len(findings),
            "severity_distribution": severity_counts,
            "type_distribution": type_counts,
            "existing_patterns": [p.to_dict() for p in patterns],
            "existing_knowledge": [k.to_dict() for k in knowledge]
        }

    async def _analyze_with_ai(self, learning_data: Dict[str, Any]) -> Dict[str, Any]:
        """使用AI分析学习数据

        Args:
            learning_data: 学习数据

        Returns:
            AI分析结果
        """
        prompt = self._build_learning_prompt(learning_data)

        request = AIRequest(
            prompt=prompt,
            system_prompt=self._system_prompt,
            temperature=0.1,
            max_tokens=4096,
            model=self._ai_config.model_name or self.config.ai.model
        )

        response = await self._manager.generate(request)

        # 解析AI响应
        return self._parse_ai_response(response.content)

    def _build_learning_prompt(self, learning_data: Dict[str, Any]) -> str:
        """构建学习提示"""
        prompt_parts = [
            "# 安全漏洞学习分析",
            f"\n## 扫描统计",
            f"- 扫描次数: {learning_data['scan_count']}",
            f"- 漏洞数量: {learning_data['finding_count']}",
            "\n## 严重程度分布:",
        ]

        for severity, count in learning_data['severity_distribution'].items():
            prompt_parts.append(f"- {severity}: {count}")

        prompt_parts.append("\n## 漏洞类型分布:")
        for vuln_type, count in learning_data['type_distribution'].items():
            prompt_parts.append(f"- {vuln_type}: {count}")

        prompt_parts.append("\n## 现有模式数量:")
        prompt_parts.append(f"- 模式: {len(learning_data['existing_patterns'])}")
        prompt_parts.append(f"- 知识: {len(learning_data['existing_knowledge'])}")

        prompt_parts.append("\n## 分析要求:")
        prompt_parts.append("1. 识别常见漏洞模式和趋势")
        prompt_parts.append("2. 发现潜在的误报模式")
        prompt_parts.append("3. 建议新的检测规则或改进现有规则")
        prompt_parts.append("4. 提取有价值的安全知识")
        prompt_parts.append("5. 预测可能的新型漏洞")

        prompt_parts.append("\n请以JSON格式返回分析结果，包含以下字段:")
        prompt_parts.append("{")
        prompt_parts.append("  \"patterns\": [ { \"type\": \"...\", \"value\": \"...\", \"description\": \"...\", \"confidence\": 0.0 } ],")
        prompt_parts.append("  \"knowledge\": [ { \"type\": \"...\", \"content\": \"...\", \"source\": \"...\", \"confidence\": 0.0, \"tags\": [] } ],")
        prompt_parts.append("  \"improvements\": [ { \"rule_id\": \"...\", \"suggestion\": \"...\", \"confidence\": 0.0 } ],")
        prompt_parts.append("  \"confidence\": 0.0")
        prompt_parts.append("}")

        return "\n".join(prompt_parts)

    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """解析AI响应"""
        import re
        
        try:
            # 提取JSON部分
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
            else:
                # 尝试直接解析
                data = json.loads(content)

            return data
        except Exception as e:
            logger.error(f"AI响应解析失败: {e}")
            return {
                "patterns": [],
                "knowledge": [],
                "improvements": [],
                "confidence": 0.5
            }

    def _process_ai_insights(self, insights: Dict[str, Any]) -> tuple:
        """处理AI洞察

        Args:
            insights: AI洞察

        Returns:
            (patterns, knowledge, suggestions)
        """
        patterns = []
        knowledge = []
        suggestions = []

        # 处理模式
        for pattern_data in insights.get("patterns", []):
            pattern_id = hashlib.sha256(pattern_data.get("value", "").encode()).hexdigest()[:16]
            pattern = Pattern(
                id=pattern_id,
                pattern_type=pattern_data.get("type", "ai_pattern"),
                pattern_value=pattern_data.get("value", ""),
                description=pattern_data.get("description", ""),
                confidence=pattern_data.get("confidence", 0.7)
            )
            patterns.append(pattern)

        # 处理知识
        for knowledge_data in insights.get("knowledge", []):
            knowledge_id = hashlib.sha256(knowledge_data.get("content", "").encode()).hexdigest()[:16]
            knowledge_item = Knowledge(
                id=knowledge_id,
                knowledge_type=KnowledgeType(knowledge_data.get("type", "pattern")),
                content=knowledge_data.get("content", ""),
                source=knowledge_data.get("source", "ai_learning"),
                confidence=knowledge_data.get("confidence", 0.7),
                tags=knowledge_data.get("tags", [])
            )
            knowledge.append(knowledge_item)

        # 处理改进建议
        suggestions = insights.get("improvements", [])

        return patterns, knowledge, suggestions

    async def learn_from_feedback(self, feedback: Feedback) -> AILearningResult:
        """从用户反馈中学习

        Args:
            feedback: 用户反馈

        Returns:
            AI学习结果
        """
        if not self._ai_config.enable_ai_learning:
            return AILearningResult(
                patterns=[],
                knowledge=[],
                improvement_suggestions=[],
                confidence=0.0
            )

        await self.initialize()

        # 首先使用传统自学习处理反馈
        self._self_learning.add_feedback(feedback)

        # 构建反馈学习提示
        prompt = self._build_feedback_learning_prompt(feedback)

        request = AIRequest(
            prompt=prompt,
            system_prompt=self._system_prompt,
            temperature=0.1,
            max_tokens=2048,
            model=self._ai_config.model_name or self.config.ai.model
        )

        response = await self._manager.generate(request)

        # 解析AI响应
        insights = self._parse_ai_response(response.content)

        # 处理AI洞察
        patterns, knowledge, suggestions = self._process_ai_insights(insights)

        # 更新知识库
        for pattern in patterns:
            self._self_learning._patterns[pattern.id] = pattern

        for knowledge_item in knowledge:
            self._self_learning.update_knowledge_base(knowledge_item)

        return AILearningResult(
            patterns=patterns,
            knowledge=knowledge,
            improvement_suggestions=suggestions,
            confidence=insights.get("confidence", 0.7)
        )

    def _build_feedback_learning_prompt(self, feedback: Feedback) -> str:
        """构建反馈学习提示"""
        prompt_parts = [
            "# 安全漏洞反馈学习",
            f"\n## 反馈信息",
            f"- 反馈类型: {feedback.feedback_type.value}",
            f"- 规则ID: {feedback.rule_id}",
            f"- 严重程度: {feedback.severity}",
            f"- 置信度: {feedback.confidence}",
            f"- 文件路径: {feedback.file_path}",
            f"- 行号: {feedback.line}",
            f"\n## 代码片段:",
            f"```\n{feedback.code_snippet}\n```",
            f"\n## 反馈消息:",
            f"{feedback.message}"
        ]

        if feedback.user_comment:
            prompt_parts.append(f"\n## 用户评论:")
            prompt_parts.append(f"{feedback.user_comment}")

        prompt_parts.append("\n## 分析要求:")
        prompt_parts.append("1. 分析此反馈的模式和原因")
        prompt_parts.append("2. 提取可用于改进检测的知识")
        prompt_parts.append("3. 建议如何调整规则以减少类似问题")
        prompt_parts.append("4. 识别可能的误报或漏报模式")

        prompt_parts.append("\n请以JSON格式返回分析结果，包含以下字段:")
        prompt_parts.append("{")
        prompt_parts.append("  \"patterns\": [ { \"type\": \"...\", \"value\": \"...\", \"description\": \"...\", \"confidence\": 0.0 } ],")
        prompt_parts.append("  \"knowledge\": [ { \"type\": \"...\", \"content\": \"...\", \"source\": \"...\", \"confidence\": 0.0, \"tags\": [] } ],")
        prompt_parts.append("  \"improvements\": [ { \"rule_id\": \"...\", \"suggestion\": \"...\", \"confidence\": 0.0 } ],")
        prompt_parts.append("  \"confidence\": 0.0")
        prompt_parts.append("}")

        return "\n".join(prompt_parts)

    def get_self_learning(self) -> SelfLearning:
        """获取自学习系统实例"""
        return self._self_learning

    def save_knowledge_base(self, path: Optional[Union[str, Path]] = None) -> None:
        """保存知识库"""
        if path:
            self._self_learning.export_knowledge_base(path)
        else:
            self._self_learning._save_knowledge_base()

    def load_knowledge_base(self, path: Optional[Union[str, Path]] = None) -> None:
        """加载知识库"""
        if path:
            self._self_learning.import_knowledge_base(path)
        else:
            self._self_learning._load_knowledge_base()
