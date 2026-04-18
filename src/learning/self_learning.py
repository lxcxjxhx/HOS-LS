"""自学习系统模块

从扫描结果中持续学习和优化，改进检测能力和降低误报率。
"""

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class LearningMode(Enum):
    """学习模式"""

    ONLINE = "online"
    BATCH = "batch"
    INCREMENTAL = "incremental"


class FeedbackType(Enum):
    """反馈类型"""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"


class KnowledgeType(Enum):
    """知识类型"""

    PATTERN = "pattern"
    RULE = "rule"
    CONTEXT = "context"
    EXCEPTION = "exception"
    CORRELATION = "correlation"
    AI_LEARNING = "ai_learning"
    ai_learning = "ai_learning"
    VULNERABILITY = "vulnerability"
    
    # 领域分类
    VULNERABILITY_DOMAIN = "vulnerability_domain"  # 漏洞类
    CODE_DOMAIN = "code_domain"  # 代码类
    RULE_DOMAIN = "rule_domain"  # 规则类


@dataclass
class Feedback:
    """反馈信息"""

    finding_id: str
    feedback_type: FeedbackType
    rule_id: str
    severity: str
    confidence: float
    file_path: str
    line: int
    code_snippet: str
    message: str
    user_comment: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "finding_id": self.finding_id,
            "feedback_type": self.feedback_type.value,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line": self.line,
            "code_snippet": self.code_snippet,
            "message": self.message,
            "user_comment": self.user_comment,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanResult:
    """扫描结果"""

    scan_id: str
    file_path: str
    findings: List[Dict[str, Any]]
    duration: float
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Pattern:
    """模式"""

    id: str
    pattern_type: str
    pattern_value: str
    description: str
    confidence: float
    occurrence_count: int = 0
    true_positive_count: int = 0
    false_positive_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "pattern_type": self.pattern_type,
            "pattern_value": self.pattern_value,
            "description": self.description,
            "confidence": self.confidence,
            "occurrence_count": self.occurrence_count,
            "true_positive_count": self.true_positive_count,
            "false_positive_count": self.false_positive_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class RuleImprovement:
    """规则改进建议"""

    rule_id: str
    improvement_type: str
    description: str
    suggested_change: str
    confidence: float
    impact_score: float
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "rule_id": self.rule_id,
            "improvement_type": self.improvement_type,
            "description": self.description,
            "suggested_change": self.suggested_change,
            "confidence": self.confidence,
            "impact_score": self.impact_score,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class Knowledge:
    """知识"""

    id: str
    knowledge_type: KnowledgeType
    content: str
    source: str
    confidence: float
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "knowledge_type": self.knowledge_type.value,
            "content": self.content,
            "source": self.source,
            "confidence": self.confidence,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class LearningConfig:
    """学习配置"""

    min_samples_for_pattern: int = 5
    confidence_threshold: float = 0.7
    false_positive_threshold: float = 0.3
    max_patterns: int = 1000
    learning_rate: float = 0.1
    decay_factor: float = 0.95
    enable_auto_update: bool = True
    knowledge_base_path: Optional[str] = None


class SelfLearning:
    """自学习系统

    从扫描结果中持续学习和优化，改进检测能力。
    """

    def __init__(
        self,
        config: Optional[LearningConfig] = None,
        knowledge_base_path: Optional[Union[str, Path]] = None,
    ):
        """初始化自学习系统

        Args:
            config: 学习配置
            knowledge_base_path: 知识库路径
        """
        self.config = config or LearningConfig()
        self.knowledge_base_path = Path(
            knowledge_base_path or self.config.knowledge_base_path or "./knowledge_base"
        )

        self._feedbacks: List[Feedback] = []
        self._patterns: Dict[str, Pattern] = {}
        self._knowledge: Dict[str, Knowledge] = {}
        self._rule_stats: Dict[str, Dict[str, int]] = {}
        self._false_positive_patterns: List[Pattern] = []
        self._improvement_suggestions: List[RuleImprovement] = []

        self._load_knowledge_base()

    def learn_from_result(
        self,
        scan_result: ScanResult,
        feedback: Optional[Feedback] = None,
    ) -> None:
        """从扫描结果学习

        Args:
            scan_result: 扫描结果
            feedback: 用户反馈
        """
        for finding in scan_result.findings:
            rule_id = finding.get("rule_id", "unknown")

            if rule_id not in self._rule_stats:
                self._rule_stats[rule_id] = {
                    "total": 0,
                    "true_positive": 0,
                    "false_positive": 0,
                    "true_negative": 0,
                    "false_negative": 0,
                }

            self._rule_stats[rule_id]["total"] += 1

            self._extract_patterns(finding)

        if feedback:
            self._process_feedback(feedback)

        self._update_rule_statistics()

    def suggest_rule_improvements(self) -> List[RuleImprovement]:
        """建议规则改进

        Returns:
            规则改进建议列表
        """
        improvements: List[RuleImprovement] = []

        for rule_id, stats in self._rule_stats.items():
            total = stats["total"]
            if total < self.config.min_samples_for_pattern:
                continue

            fp_rate = stats["false_positive"] / total if total > 0 else 0
            tp_rate = stats["true_positive"] / total if total > 0 else 0

            if fp_rate > self.config.false_positive_threshold:
                improvement = RuleImprovement(
                    rule_id=rule_id,
                    improvement_type="reduce_false_positives",
                    description=f"规则 {rule_id} 误报率过高 ({fp_rate:.2%})，建议调整检测条件",
                    suggested_change="增加更严格的匹配条件或添加排除模式",
                    confidence=0.8,
                    impact_score=fp_rate,
                )
                improvements.append(improvement)

            if tp_rate < 0.5 and total > 10:
                improvement = RuleImprovement(
                    rule_id=rule_id,
                    improvement_type="improve_detection",
                    description=f"规则 {rule_id} 真阳性率较低 ({tp_rate:.2%})，建议增强检测能力",
                    suggested_change="扩展检测模式或降低置信度阈值",
                    confidence=0.7,
                    impact_score=1 - tp_rate,
                )
                improvements.append(improvement)

        for pattern in self._false_positive_patterns:
            if pattern.occurrence_count >= self.config.min_samples_for_pattern:
                improvement = RuleImprovement(
                    rule_id="*",
                    improvement_type="add_exclusion_pattern",
                    description=f"发现常见误报模式: {pattern.description}",
                    suggested_change=f"添加排除模式: {pattern.pattern_value}",
                    confidence=pattern.confidence,
                    impact_score=pattern.false_positive_count / max(pattern.occurrence_count, 1),
                )
                improvements.append(improvement)

        self._improvement_suggestions = improvements
        return improvements

    def identify_false_positive_patterns(self) -> List[Pattern]:
        """识别误报模式

        Returns:
            误报模式列表
        """
        fp_patterns: List[Pattern] = []

        fp_feedbacks = [
            f for f in self._feedbacks if f.feedback_type == FeedbackType.FALSE_POSITIVE
        ]

        pattern_counts: Counter = Counter()
        for feedback in fp_feedbacks:
            code_snippet = feedback.code_snippet
            patterns = self._extract_code_patterns(code_snippet)
            for pattern in patterns:
                pattern_counts[pattern] += 1

        for pattern_value, count in pattern_counts.most_common(50):
            if count >= self.config.min_samples_for_pattern:
                pattern_id = hashlib.sha256(pattern_value.encode()).hexdigest()[:16]
                pattern = Pattern(
                    id=pattern_id,
                    pattern_type="false_positive",
                    pattern_value=pattern_value,
                    description=f"常见误报模式 (出现 {count} 次)",
                    confidence=min(count / 10.0, 1.0),
                    occurrence_count=count,
                    false_positive_count=count,
                )
                fp_patterns.append(pattern)

        self._false_positive_patterns = fp_patterns
        return fp_patterns

    def update_knowledge_base(self, knowledge: Knowledge) -> None:
        """更新知识库

        Args:
            knowledge: 知识
        """
        self._knowledge[knowledge.id] = knowledge

        if self.config.enable_auto_update:
            self._save_knowledge_base()

    def add_feedback(self, feedback: Feedback) -> None:
        """添加反馈

        Args:
            feedback: 反馈
        """
        self._feedbacks.append(feedback)
        self._process_feedback(feedback)

    def get_feedback_stats(self) -> Dict[str, Any]:
        """获取反馈统计

        Returns:
            反馈统计信息
        """
        if not self._feedbacks:
            return {
                "total": 0,
                "by_type": {},
                "by_rule": {},
            }

        by_type: Dict[str, int] = {}
        by_rule: Dict[str, int] = {}

        for feedback in self._feedbacks:
            ft = feedback.feedback_type.value
            by_type[ft] = by_type.get(ft, 0) + 1

            by_rule[feedback.rule_id] = by_rule.get(feedback.rule_id, 0) + 1

        return {
            "total": len(self._feedbacks),
            "by_type": by_type,
            "by_rule": by_rule,
        }

    def get_pattern(self, pattern_id: str) -> Optional[Pattern]:
        """获取模式

        Args:
            pattern_id: 模式ID

        Returns:
            模式
        """
        return self._patterns.get(pattern_id)

    def get_knowledge(self, knowledge_id: str) -> Optional[Knowledge]:
        """获取知识

        Args:
            knowledge_id: 知识ID

        Returns:
            知识
        """
        return self._knowledge.get(knowledge_id)

    def get_all_patterns(self) -> List[Pattern]:
        """获取所有模式

        Returns:
            所有模式列表
        """
        return list(self._patterns.values())

    def get_all_knowledge(self) -> List[Knowledge]:
        """获取所有知识

        Returns:
            所有知识列表
        """
        return list(self._knowledge.values())

    def export_knowledge_base(self, output_path: Union[str, Path]) -> None:
        """导出知识库

        Args:
            output_path: 输出路径
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "patterns": [p.to_dict() for p in self._patterns.values()],
            "knowledge": [k.to_dict() for k in self._knowledge.values()],
            "rule_stats": self._rule_stats,
            "false_positive_patterns": [p.to_dict() for p in self._false_positive_patterns],
            "improvement_suggestions": [i.to_dict() for i in self._improvement_suggestions],
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def import_knowledge_base(self, input_path: Union[str, Path]) -> None:
        """导入知识库

        Args:
            input_path: 输入路径
        """
        path = Path(input_path)

        if not path.exists():
            return

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for pattern_data in data.get("patterns", []):
            pattern = Pattern(
                id=pattern_data["id"],
                pattern_type=pattern_data["pattern_type"],
                pattern_value=pattern_data["pattern_value"],
                description=pattern_data["description"],
                confidence=pattern_data["confidence"],
                occurrence_count=pattern_data.get("occurrence_count", 0),
                true_positive_count=pattern_data.get("true_positive_count", 0),
                false_positive_count=pattern_data.get("false_positive_count", 0),
            )
            self._patterns[pattern.id] = pattern

        for knowledge_data in data.get("knowledge", []):
            knowledge = Knowledge(
                id=knowledge_data["id"],
                knowledge_type=KnowledgeType(knowledge_data["knowledge_type"]),
                content=knowledge_data["content"],
                source=knowledge_data["source"],
                confidence=knowledge_data["confidence"],
                tags=knowledge_data.get("tags", []),
            )
            self._knowledge[knowledge.id] = knowledge

        self._rule_stats = data.get("rule_stats", {})

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息

        Returns:
            统计信息字典
        """
        return {
            "total_patterns": len(self._patterns),
            "total_knowledge": len(self._knowledge),
            "total_feedbacks": len(self._feedbacks),
            "total_rules_tracked": len(self._rule_stats),
            "false_positive_patterns": len(self._false_positive_patterns),
            "improvement_suggestions": len(self._improvement_suggestions),
            "feedback_stats": self.get_feedback_stats(),
        }

    def _process_feedback(self, feedback: Feedback) -> None:
        """处理反馈

        Args:
            feedback: 反馈
        """
        rule_id = feedback.rule_id

        if rule_id not in self._rule_stats:
            self._rule_stats[rule_id] = {
                "total": 0,
                "true_positive": 0,
                "false_positive": 0,
                "true_negative": 0,
                "false_negative": 0,
            }

        if feedback.feedback_type == FeedbackType.TRUE_POSITIVE:
            self._rule_stats[rule_id]["true_positive"] += 1
        elif feedback.feedback_type == FeedbackType.FALSE_POSITIVE:
            self._rule_stats[rule_id]["false_positive"] += 1
            self._extract_false_positive_pattern(feedback)
        elif feedback.feedback_type == FeedbackType.TRUE_NEGATIVE:
            self._rule_stats[rule_id]["true_negative"] += 1
        elif feedback.feedback_type == FeedbackType.FALSE_NEGATIVE:
            self._rule_stats[rule_id]["false_negative"] += 1

    def _extract_patterns(self, finding: Dict[str, Any]) -> None:
        """从发现中提取模式

        Args:
            finding: 发现
        """
        code_snippet = finding.get("code_snippet", "")
        if not code_snippet:
            return

        patterns = self._extract_code_patterns(code_snippet)

        for pattern_value in patterns:
            pattern_id = hashlib.sha256(pattern_value.encode()).hexdigest()[:16]

            if pattern_id in self._patterns:
                self._patterns[pattern_id].occurrence_count += 1
                self._patterns[pattern_id].updated_at = datetime.now()
            else:
                pattern = Pattern(
                    id=pattern_id,
                    pattern_type="code_pattern",
                    pattern_value=pattern_value,
                    description=f"代码模式: {pattern_value[:50]}...",
                    confidence=0.5,
                    occurrence_count=1,
                )
                self._patterns[pattern_id] = pattern

    def _extract_false_positive_pattern(self, feedback: Feedback) -> None:
        """从误报反馈中提取模式

        Args:
            feedback: 反馈
        """
        code_snippet = feedback.code_snippet
        patterns = self._extract_code_patterns(code_snippet)

        for pattern_value in patterns:
            pattern_id = hashlib.sha256(pattern_value.encode()).hexdigest()[:16]

            if pattern_id in self._patterns:
                self._patterns[pattern_id].false_positive_count += 1
            else:
                pattern = Pattern(
                    id=pattern_id,
                    pattern_type="false_positive",
                    pattern_value=pattern_value,
                    description=f"误报模式: {pattern_value[:50]}...",
                    confidence=0.5,
                    occurrence_count=1,
                    false_positive_count=1,
                )
                self._patterns[pattern_id] = pattern

    def _extract_code_patterns(self, code: str) -> List[str]:
        """提取代码模式

        Args:
            code: 代码

        Returns:
            模式列表
        """
        patterns: List[str] = []

        function_pattern = r"\bdef\s+(\w+)\s*\([^)]*\)"
        for match in re.finditer(function_pattern, code):
            patterns.append(f"function:{match.group(1)}")

        class_pattern = r"\bclass\s+(\w+)"
        for match in re.finditer(class_pattern, code):
            patterns.append(f"class:{match.group(1)}")

        import_pattern = r"\bimport\s+(\w+)|from\s+(\w+)\s+import"
        for match in re.finditer(import_pattern, code):
            module = match.group(1) or match.group(2)
            patterns.append(f"import:{module}")

        dangerous_functions = [
            "eval",
            "exec",
            "compile",
            "open",
            "input",
            "raw_input",
            "os.system",
            "subprocess",
            "pickle.loads",
            "yaml.load",
            "marshal.loads",
        ]
        for func in dangerous_functions:
            if func in code:
                patterns.append(f"dangerous:{func}")

        sensitive_keywords = [
            "password",
            "secret",
            "key",
            "token",
            "credential",
            "api_key",
            "private",
        ]
        for keyword in sensitive_keywords:
            if keyword.lower() in code.lower():
                patterns.append(f"sensitive:{keyword}")

        return patterns

    def _update_rule_statistics(self) -> None:
        """更新规则统计"""
        for rule_id, stats in self._rule_stats.items():
            total = stats["total"]
            if total == 0:
                continue

    def _save_knowledge_base(self) -> None:
        """保存知识库"""
        self.knowledge_base_path.mkdir(parents=True, exist_ok=True)

        patterns_path = self.knowledge_base_path / "patterns.json"
        with open(patterns_path, "w", encoding="utf-8") as f:
            json.dump(
                [p.to_dict() for p in self._patterns.values()],
                f,
                indent=2,
                ensure_ascii=False,
            )

        knowledge_path = self.knowledge_base_path / "knowledge.json"
        with open(knowledge_path, "w", encoding="utf-8") as f:
            json.dump(
                [k.to_dict() for k in self._knowledge.values()],
                f,
                indent=2,
                ensure_ascii=False,
            )

        stats_path = self.knowledge_base_path / "rule_stats.json"
        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(self._rule_stats, f, indent=2, ensure_ascii=False)

    def _load_knowledge_base(self) -> None:
        """加载知识库"""
        if not self.knowledge_base_path.exists():
            return

        patterns_path = self.knowledge_base_path / "patterns.json"
        if patterns_path.exists():
            self.import_knowledge_base(patterns_path)

        knowledge_path = self.knowledge_base_path / "knowledge.json"
        if knowledge_path.exists():
            with open(knowledge_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for knowledge_data in data:
                    knowledge = Knowledge(
                        id=knowledge_data["id"],
                        knowledge_type=KnowledgeType(knowledge_data["knowledge_type"]),
                        content=knowledge_data["content"],
                        source=knowledge_data["source"],
                        confidence=knowledge_data["confidence"],
                        tags=knowledge_data.get("tags", []),
                    )
                    self._knowledge[knowledge.id] = knowledge

        stats_path = self.knowledge_base_path / "rule_stats.json"
        if stats_path.exists():
            with open(stats_path, "r", encoding="utf-8") as f:
                self._rule_stats = json.load(f)
