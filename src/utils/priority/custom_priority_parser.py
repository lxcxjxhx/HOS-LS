"""自定义优先级规则解析器模块

解析 YAML/JSON 格式的优先级规则配置，提供灵活的文件优先级评估功能。
"""

import fnmatch
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from src.utils.logger import get_logger

logger = get_logger(__name__)


class PriorityLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PriorityWeights:
    keyword_match: float = 0.4
    file_pattern: float = 0.3
    path_match: float = 0.3


@dataclass
class PriorityRules:
    name: str = "默认规则"
    keywords: Dict[str, List[str]] = field(default_factory=dict)
    file_patterns: Dict[str, List[str]] = field(default_factory=dict)
    path_rules: Dict[str, List[str]] = field(default_factory=dict)
    weights: PriorityWeights = field(default_factory=PriorityWeights)


@dataclass
class PriorityResult:
    priority_level: PriorityLevel
    total_score: float
    keyword_score: float
    file_pattern_score: float
    path_score: float
    matched_keywords: List[str] = field(default_factory=list)
    matched_file_patterns: List[str] = field(default_factory=list)
    matched_paths: List[str] = field(default_factory=list)


class CustomPriorityParser:
    """自定义优先级规则解析器

    解析 YAML/JSON 配置并根据规则评估文件优先级。
    """

    def __init__(self):
        self._config: Optional[Dict[str, Any]] = None
        self._rules: Optional[PriorityRules] = None

    def load_from_file(self, path: Union[str, Path]) -> "CustomPriorityParser":
        """从文件加载优先级规则配置

        Args:
            path: 配置文件路径

        Returns:
            self
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"配置文件不存在: {path}")

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        if path.suffix.lower() in [".yaml", ".yml"]:
            self._config = yaml.safe_load(content)
        elif path.suffix.lower() == ".json":
            self._config = json.loads(content)
        else:
            try:
                self._config = yaml.safe_load(content)
            except yaml.YAMLError:
                self._config = json.loads(content)

        logger.info(f"从文件加载优先级配置: {path}")
        return self

    def load_from_dict(self, config: Dict[str, Any]) -> "CustomPriorityParser":
        """从字典加载优先级规则配置

        Args:
            config: 配置字典

        Returns:
            self
        """
        self._config = config
        logger.info("从字典加载优先级配置")
        return self

    def parse(self) -> Dict[str, Any]:
        """解析配置并返回规则字典

        Returns:
            解析后的规则字典
        """
        if self._config is None:
            raise ValueError("配置未加载，请先调用 load_from_file 或 load_from_dict")

        priority_rules = self._config.get("priority_rules", {})
        custom_rules = priority_rules.get("custom", {})

        self._rules = PriorityRules(
            name=custom_rules.get("name", "默认规则"),
            keywords=custom_rules.get("keywords", {}),
            file_patterns=custom_rules.get("file_patterns", {}),
            path_rules=custom_rules.get("path_rules", {}),
            weights=PriorityWeights(
                keyword_match=custom_rules.get("weights", {}).get(
                    "keyword_match", 0.4
                ),
                file_pattern=custom_rules.get("weights", {}).get(
                    "file_pattern", 0.3
                ),
                path_match=custom_rules.get("weights", {}).get("path_match", 0.3),
            ),
        )

        return {
            "name": self._rules.name,
            "keywords": self._rules.keywords,
            "file_patterns": self._rules.file_patterns,
            "path_rules": self._rules.path_rules,
            "weights": {
                "keyword_match": self._rules.weights.keyword_match,
                "file_pattern": self._rules.weights.file_pattern,
                "path_match": self._rules.weights.path_match,
            },
        }

    def get_priority(
        self, file_path: Union[str, Path]
    ) -> PriorityResult:
        """评估文件的优先级

        Args:
            file_path: 文件路径

        Returns:
            优先级结果
        """
        if self._rules is None:
            self.parse()

        file_path = Path(file_path)
        file_content = ""

        if file_path.exists() and file_path.is_file():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    file_content = f.read()
            except Exception:
                pass

        keyword_score, matched_keywords = self._evaluate_keywords(
            file_path, file_content
        )
        file_pattern_score, matched_file_patterns = self._evaluate_file_patterns(
            file_path
        )
        path_score, matched_paths = self._evaluate_paths(file_path)

        total_score = (
            keyword_score * self._rules.weights.keyword_match
            + file_pattern_score * self._rules.weights.file_pattern
            + path_score * self._rules.weights.path_match
        )

        priority_level = self._determine_priority_level(total_score)

        return PriorityResult(
            priority_level=priority_level,
            total_score=total_score,
            keyword_score=keyword_score,
            file_pattern_score=file_pattern_score,
            path_score=path_score,
            matched_keywords=matched_keywords,
            matched_file_patterns=matched_file_patterns,
            matched_paths=matched_paths,
        )

    def _evaluate_keywords(
        self, file_path: Path, file_content: str
    ) -> tuple[float, List[str]]:
        """评估关键词匹配

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            (分数, 匹配的关键词列表)
        """
        if not self._rules.keywords:
            return 0.0, []

        matched: List[str] = []
        score_details: Dict[str, float] = {
            "high_priority": 0.0,
            "medium_priority": 0.0,
            "low_priority": 0.0,
        }

        high_keywords = self._rules.keywords.get("high_priority", [])
        medium_keywords = self._rules.keywords.get("medium_priority", [])
        low_keywords = self._rules.keywords.get("low_priority", [])

        file_path_str = str(file_path).lower()
        file_name = file_path.name.lower()
        file_content_lower = file_content.lower()

        for keyword in high_keywords:
            keyword_lower = keyword.lower()
            if (
                keyword_lower in file_path_str
                or keyword_lower in file_name
                or keyword_lower in file_content_lower
            ):
                if keyword not in matched:
                    matched.append(keyword)
                score_details["high_priority"] += 1.0

        for keyword in medium_keywords:
            keyword_lower = keyword.lower()
            if (
                keyword_lower in file_path_str
                or keyword_lower in file_name
                or keyword_lower in file_content_lower
            ):
                if keyword not in matched:
                    matched.append(keyword)
                score_details["medium_priority"] += 0.6

        for keyword in low_keywords:
            keyword_lower = keyword.lower()
            if (
                keyword_lower in file_path_str
                or keyword_lower in file_name
                or keyword_lower in file_content_lower
            ):
                if keyword not in matched:
                    matched.append(keyword)
                score_details["low_priority"] += 0.3

        max_possible = len(high_keywords) * 1.0 + len(medium_keywords) * 0.6 + len(low_keywords) * 0.3
        if max_possible == 0:
            return 0.0, matched

        raw_score = (
            score_details["high_priority"]
            + score_details["medium_priority"]
            + score_details["low_priority"]
        )
        score = min(raw_score / max_possible, 1.0)

        return score, matched

    def _evaluate_file_patterns(
        self, file_path: Path
    ) -> tuple[float, List[str]]:
        """评估文件模式匹配

        Args:
            file_path: 文件路径

        Returns:
            (分数, 匹配的文件模式列表)
        """
        if not self._rules.file_patterns:
            return 0.0, []

        matched: List[str] = []
        score_details: Dict[str, float] = {
            "high_priority": 0.0,
            "medium_priority": 0.0,
            "low_priority": 0.0,
        }

        high_patterns = self._rules.file_patterns.get("high_priority", [])
        medium_patterns = self._rules.file_patterns.get("medium_priority", [])
        low_patterns = self._rules.file_patterns.get("low_priority", [])

        file_name = file_path.name

        for pattern in high_patterns:
            if fnmatch.fnmatch(file_name, pattern):
                if pattern not in matched:
                    matched.append(pattern)
                score_details["high_priority"] += 1.0

        for pattern in medium_patterns:
            if fnmatch.fnmatch(file_name, pattern):
                if pattern not in matched:
                    matched.append(pattern)
                score_details["medium_priority"] += 0.6

        for pattern in low_patterns:
            if fnmatch.fnmatch(file_name, pattern):
                if pattern not in matched:
                    matched.append(pattern)
                score_details["low_priority"] += 0.3

        max_possible = len(high_patterns) * 1.0 + len(medium_patterns) * 0.6 + len(low_patterns) * 0.3
        if max_possible == 0:
            return 0.0, matched

        raw_score = (
            score_details["high_priority"]
            + score_details["medium_priority"]
            + score_details["low_priority"]
        )
        score = min(raw_score / max_possible, 1.0)

        return score, matched

    def _evaluate_paths(self, file_path: Path) -> tuple[float, List[str]]:
        """评估路径规则匹配

        Args:
            file_path: 文件路径

        Returns:
            (分数, 匹配的路径规则列表)
        """
        if not self._rules.path_rules:
            return 0.0, []

        matched: List[str] = []
        score_details: Dict[str, float] = {
            "high_priority": 0.0,
            "medium_priority": 0.0,
            "low_priority": 0.0,
        }

        high_paths = self._rules.path_rules.get("high_priority", [])
        medium_paths = self._rules.path_rules.get("medium_priority", [])
        low_paths = self._rules.path_rules.get("low_priority", [])

        file_path_str = str(file_path)

        for pattern in high_paths:
            if self._match_path_pattern(file_path_str, pattern):
                if pattern not in matched:
                    matched.append(pattern)
                score_details["high_priority"] += 1.0

        for pattern in medium_paths:
            if self._match_path_pattern(file_path_str, pattern):
                if pattern not in matched:
                    matched.append(pattern)
                score_details["medium_priority"] += 0.6

        for pattern in low_paths:
            if self._match_path_pattern(file_path_str, pattern):
                if pattern not in matched:
                    matched.append(pattern)
                score_details["low_priority"] += 0.3

        max_possible = len(high_paths) * 1.0 + len(medium_paths) * 0.6 + len(low_paths) * 0.3
        if max_possible == 0:
            return 0.0, matched

        raw_score = (
            score_details["high_priority"]
            + score_details["medium_priority"]
            + score_details["low_priority"]
        )
        score = min(raw_score / max_possible, 1.0)

        return score, matched

    def _match_path_pattern(self, file_path: str, pattern: str) -> bool:
        """匹配路径模式

        Args:
            file_path: 文件路径
            pattern: 路径模式

        Returns:
            是否匹配
        """
        if pattern.startswith("**/"):
            pattern_suffix = pattern[3:]
            if "**/" in pattern_suffix:
                parts = pattern_suffix.split("**/")
                current_idx = 0
                for part in parts:
                    if not part:
                        continue
                    idx = file_path.find(part, current_idx)
                    if idx == -1:
                        return False
                    current_idx = idx + len(part)
                return True
            else:
                return pattern_suffix in file_path
        elif "**" in pattern:
            regex_pattern = pattern.replace("**/", ".*/").replace("**", ".*")
            import re
            return bool(re.search(regex_pattern, file_path))
        else:
            return pattern in file_path

    def _determine_priority_level(self, score: float) -> PriorityLevel:
        """确定优先级等级

        Args:
            score: 总评分

        Returns:
            优先级等级
        """
        if score >= 0.7:
            return PriorityLevel.HIGH
        elif score >= 0.4:
            return PriorityLevel.MEDIUM
        else:
            return PriorityLevel.LOW

    def get_rules(self) -> Optional[PriorityRules]:
        """获取解析后的规则

        Returns:
            规则对象
        """
        return self._rules

    def to_dict(self, result: PriorityResult) -> Dict[str, Any]:
        """将优先级结果转换为字典

        Args:
            result: 优先级结果

        Returns:
            字典格式的结果
        """
        return {
            "priority_level": result.priority_level.value,
            "total_score": result.total_score,
            "keyword_score": result.keyword_score,
            "file_pattern_score": result.file_pattern_score,
            "path_score": result.path_score,
            "matched_keywords": result.matched_keywords,
            "matched_file_patterns": result.matched_file_patterns,
            "matched_paths": result.matched_paths,
        }
