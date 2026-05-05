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
    related_file: float = 0.3
    call_chain: float = 0.4
    data_flow: float = 0.3


@dataclass
class RelatedFileRules:
    keywords: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)


@dataclass
class CallChainRules:
    java_patterns: List[str] = field(default_factory=list)
    python_patterns: List[str] = field(default_factory=list)


@dataclass
class DataFlowRules:
    java_patterns: List[str] = field(default_factory=list)
    python_patterns: List[str] = field(default_factory=list)


@dataclass
class OWASPRules:
    """OWASP TOP10 规则配置"""
    a01_broken_access_control: List[str] = field(default_factory=list)
    a02_cryptographic_failures: List[str] = field(default_factory=list)
    a03_injection: List[str] = field(default_factory=list)
    a04_insecure_design: List[str] = field(default_factory=list)
    a05_security_misconfiguration: List[str] = field(default_factory=list)
    a06_vulnerable_components: List[str] = field(default_factory=list)
    a07_authentication_failures: List[str] = field(default_factory=list)
    a08_software_integrity: List[str] = field(default_factory=list)
    a09_logging_failures: List[str] = field(default_factory=list)
    a10_ssrf: List[str] = field(default_factory=list)


@dataclass
class PriorityRules:
    name: str = "默认规则"
    keywords: Dict[str, List[str]] = field(default_factory=dict)
    file_patterns: Dict[str, List[str]] = field(default_factory=dict)
    path_rules: Dict[str, List[str]] = field(default_factory=dict)
    related_file_rules: Optional[RelatedFileRules] = None
    call_chain_rules: Optional[CallChainRules] = None
    data_flow_rules: Optional[DataFlowRules] = None
    owasp_rules: Optional[OWASPRules] = None
    owasp_weight: float = 0.3
    weights: PriorityWeights = field(default_factory=PriorityWeights)


@dataclass
class RelatedFileMatch:
    file_path: str
    match_type: str
    matched_pattern: str
    score: float


@dataclass
class PriorityResult:
    priority_level: PriorityLevel
    total_score: float
    keyword_score: float
    file_pattern_score: float
    path_score: float
    correlation_score: float = 0.0
    matched_keywords: List[str] = field(default_factory=list)
    matched_file_patterns: List[str] = field(default_factory=list)
    matched_paths: List[str] = field(default_factory=list)
    matched_related_files: List[RelatedFileMatch] = field(default_factory=list)


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

        related_file_rules_data = custom_rules.get("related_file_rules", {})
        call_chain_rules_data = custom_rules.get("call_chain_rules", {})
        data_flow_rules_data = custom_rules.get("data_flow_rules", {})

        related_file_rules = None
        if related_file_rules_data:
            related_file_rules = RelatedFileRules(
                keywords=related_file_rules_data.get("keywords", []),
                patterns=related_file_rules_data.get("patterns", []),
            )

        call_chain_rules = None
        if call_chain_rules_data:
            call_chain_rules = CallChainRules(
                java_patterns=call_chain_rules_data.get("java_patterns", []),
                python_patterns=call_chain_rules_data.get("python_patterns", []),
            )

        data_flow_rules = None
        if data_flow_rules_data:
            data_flow_rules = DataFlowRules(
                java_patterns=data_flow_rules_data.get("java_patterns", []),
                python_patterns=data_flow_rules_data.get("python_patterns", []),
            )

        owasp_config = custom_rules.get("owasp_rules", {})
        owasp_rules = None
        if owasp_config:
            owasp_rules = OWASPRules(
                a01_broken_access_control=owasp_config.get("a01_broken_access_control", []),
                a02_cryptographic_failures=owasp_config.get("a02_cryptographic_failures", []),
                a03_injection=owasp_config.get("a03_injection", []),
                a04_insecure_design=owasp_config.get("a04_insecure_design", []),
                a05_security_misconfiguration=owasp_config.get("a05_security_misconfiguration", []),
                a06_vulnerable_components=owasp_config.get("a06_vulnerable_components", []),
                a07_authentication_failures=owasp_config.get("a07_authentication_failures", []),
                a08_software_integrity=owasp_config.get("a08_software_integrity", []),
                a09_logging_failures=owasp_config.get("a09_logging_failures", []),
                a10_ssrf=owasp_config.get("a10_ssrf", []),
            )

        owasp_weight = custom_rules.get("owasp_weight", 0.3)

        weights_data = custom_rules.get("weights", {})
        correlation_weights_data = custom_rules.get("correlation_weights", {})

        self._rules = PriorityRules(
            name=custom_rules.get("name", "默认规则"),
            keywords=custom_rules.get("keywords", {}),
            file_patterns=custom_rules.get("file_patterns", {}),
            path_rules=custom_rules.get("path_rules", {}),
            related_file_rules=related_file_rules,
            call_chain_rules=call_chain_rules,
            data_flow_rules=data_flow_rules,
            owasp_rules=owasp_rules,
            owasp_weight=owasp_weight,
            weights=PriorityWeights(
                keyword_match=weights_data.get("keyword_match", 0.4),
                file_pattern=weights_data.get("file_pattern", 0.3),
                path_match=weights_data.get("path_match", 0.3),
                related_file=correlation_weights_data.get("related_file", 0.3),
                call_chain=correlation_weights_data.get("call_chain", 0.4),
                data_flow=correlation_weights_data.get("data_flow", 0.3),
            ),
        )

        return {
            "name": self._rules.name,
            "keywords": self._rules.keywords,
            "file_patterns": self._rules.file_patterns,
            "path_rules": self._rules.path_rules,
            "related_file_rules": {
                "keywords": self._rules.related_file_rules.keywords if self._rules.related_file_rules else [],
                "patterns": self._rules.related_file_rules.patterns if self._rules.related_file_rules else [],
            } if self._rules.related_file_rules else {},
            "call_chain_rules": {
                "java_patterns": self._rules.call_chain_rules.java_patterns if self._rules.call_chain_rules else [],
                "python_patterns": self._rules.call_chain_rules.python_patterns if self._rules.call_chain_rules else [],
            } if self._rules.call_chain_rules else {},
            "data_flow_rules": {
                "java_patterns": self._rules.data_flow_rules.java_patterns if self._rules.data_flow_rules else [],
                "python_patterns": self._rules.data_flow_rules.python_patterns if self._rules.data_flow_rules else [],
            } if self._rules.data_flow_rules else {},
            "owasp_rules": {
                "a01_broken_access_control": self._rules.owasp_rules.a01_broken_access_control if self._rules.owasp_rules else [],
                "a02_cryptographic_failures": self._rules.owasp_rules.a02_cryptographic_failures if self._rules.owasp_rules else [],
                "a03_injection": self._rules.owasp_rules.a03_injection if self._rules.owasp_rules else [],
                "a04_insecure_design": self._rules.owasp_rules.a04_insecure_design if self._rules.owasp_rules else [],
                "a05_security_misconfiguration": self._rules.owasp_rules.a05_security_misconfiguration if self._rules.owasp_rules else [],
                "a06_vulnerable_components": self._rules.owasp_rules.a06_vulnerable_components if self._rules.owasp_rules else [],
                "a07_authentication_failures": self._rules.owasp_rules.a07_authentication_failures if self._rules.owasp_rules else [],
                "a08_software_integrity": self._rules.owasp_rules.a08_software_integrity if self._rules.owasp_rules else [],
                "a09_logging_failures": self._rules.owasp_rules.a09_logging_failures if self._rules.owasp_rules else [],
                "a10_ssrf": self._rules.owasp_rules.a10_ssrf if self._rules.owasp_rules else [],
            } if self._rules.owasp_rules else {},
            "owasp_weight": self._rules.owasp_weight,
            "weights": {
                "keyword_match": self._rules.weights.keyword_match,
                "file_pattern": self._rules.weights.file_pattern,
                "path_match": self._rules.weights.path_match,
                "related_file": self._rules.weights.related_file,
                "call_chain": self._rules.weights.call_chain,
                "data_flow": self._rules.weights.data_flow,
            },
        }

    def get_priority(
        self, file_path: Union[str, Path], project_root: Optional[Union[str, Path]] = None
    ) -> PriorityResult:
        """评估文件的优先级

        Args:
            file_path: 文件路径
            project_root: 项目根目录，用于扫描相关文件

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

        correlation_score, matched_related_files = self.evaluate_related_files(
            file_path, file_content, project_root
        )

        base_score = (
            keyword_score * self._rules.weights.keyword_match
            + file_pattern_score * self._rules.weights.file_pattern
            + path_score * self._rules.weights.path_match
        )

        total_score = (
            base_score * 0.7
            + correlation_score * 0.3
        )

        priority_level = self._determine_priority_level(total_score)

        return PriorityResult(
            priority_level=priority_level,
            total_score=total_score,
            keyword_score=keyword_score,
            file_pattern_score=file_pattern_score,
            path_score=path_score,
            correlation_score=correlation_score,
            matched_keywords=matched_keywords,
            matched_file_patterns=matched_file_patterns,
            matched_paths=matched_paths,
            matched_related_files=matched_related_files,
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

    def evaluate_related_files(
        self,
        file_path: Path,
        file_content: str,
        project_root: Optional[Union[str, Path]] = None
    ) -> tuple[float, List[RelatedFileMatch]]:
        """评估相关文件的相关性评分

        基于相关文件规则、调用链规则和数据流规则，扫描项目目录找到相关文件并计算相关性分数。

        Args:
            file_path: 当前文件路径
            file_content: 当前文件内容
            project_root: 项目根目录，用于扫描相关文件

        Returns:
            (相关性分数, 匹配的相关文件列表)
        """
        if (
            self._rules.related_file_rules is None
            and self._rules.call_chain_rules is None
            and self._rules.data_flow_rules is None
        ):
            return 0.0, []

        matched_files: List[RelatedFileMatch] = []

        if project_root is None:
            project_root = file_path.parent

        project_root = Path(project_root)
        if not project_root.is_dir():
            return 0.0, []

        if self._rules.related_file_rules:
            keyword_matches = self._scan_files_by_keywords(
                project_root, self._rules.related_file_rules.keywords, self._rules.related_file_rules.patterns
            )
            matched_files.extend(keyword_matches)

        if self._rules.call_chain_rules:
            call_chain_matches = self._scan_call_chain_relationships(
                file_path, file_content, project_root
            )
            matched_files.extend(call_chain_matches)

        if self._rules.data_flow_rules:
            data_flow_matches = self._scan_data_flow_relationships(
                file_path, file_content, project_root
            )
            matched_files.extend(data_flow_matches)

        if not matched_files:
            return 0.0, []

        total_possible = len(matched_files)
        if total_possible == 0:
            return 0.0, matched_files

        weighted_score = sum(m.score for m in matched_files) / total_possible
        correlation_score = min(weighted_score, 1.0)

        return correlation_score, matched_files

    def _scan_files_by_keywords(
        self,
        project_root: Path,
        keywords: List[str],
        patterns: List[str]
    ) -> List[RelatedFileMatch]:
        """根据关键词和模式扫描相关文件

        Args:
            project_root: 项目根目录
            keywords: 匹配关键词列表
            patterns: 文件模式列表

        Returns:
            匹配的相关文件列表
        """
        matched: List[RelatedFileMatch] = []

        for pattern in patterns:
            for file_path in project_root.rglob("*"):
                if file_path.is_file() and fnmatch.fnmatch(file_path.name, pattern):
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read().lower()

                        score = 0.0
                        for keyword in keywords:
                            if keyword.lower() in content:
                                score += 0.2

                        score = min(score, 1.0)
                        if score > 0:
                            matched.append(RelatedFileMatch(
                                file_path=str(file_path),
                                match_type="related_file",
                                matched_pattern=pattern,
                                score=score,
                            ))
                    except Exception:
                        pass

        return matched

    def _scan_call_chain_relationships(
        self,
        file_path: Path,
        file_content: str,
        project_root: Path
    ) -> List[RelatedFileMatch]:
        """扫描调用链关系

        检测文件中的依赖注入、导入语句等调用链模式，找到被调用的相关文件。

        Args:
            file_path: 当前文件路径
            file_content: 当前文件内容
            project_root: 项目根目录

        Returns:
            匹配的相关文件列表
        """
        matched: List[RelatedFileMatch] = []
        call_chain_rules = self._rules.call_chain_rules
        if not call_chain_rules:
            return matched

        all_patterns = (
            call_chain_rules.java_patterns + call_chain_rules.python_patterns
        )

        if not all_patterns:
            return matched

        for pattern in all_patterns:
            if pattern in file_content:
                referenced_name = self._extract_referenced_name(file_content, pattern)
                if referenced_name:
                    referenced_files = self._find_referenced_files(
                        project_root, referenced_name
                    )
                    for ref_file in referenced_files:
                        matched.append(RelatedFileMatch(
                            file_path=str(ref_file),
                            match_type="call_chain",
                            matched_pattern=pattern,
                            score=0.8,
                        ))

        return matched

    def _scan_data_flow_relationships(
        self,
        file_path: Path,
        file_content: str,
        project_root: Path
    ) -> List[RelatedFileMatch]:
        """扫描数据流关系

        检测文件中的数据流模式（如请求参数、返回值等），找到处理相同数据的相关文件。

        Args:
            file_path: 当前文件路径
            file_content: 当前文件内容
            project_root: 项目根目录

        Returns:
            匹配的相关文件列表
        """
        matched: List[RelatedFileMatch] = []
        data_flow_rules = self._rules.data_flow_rules
        if not data_flow_rules:
            return matched

        all_patterns = (
            data_flow_rules.java_patterns + data_flow_rules.python_patterns
        )

        if not all_patterns:
            return matched

        pattern_count = 0
        for pattern in all_patterns:
            if pattern in file_content:
                pattern_count += 1

        if pattern_count > 0:
            score = min(pattern_count * 0.3, 1.0)
            matched.append(RelatedFileMatch(
                file_path=str(file_path),
                match_type="data_flow",
                matched_pattern="data_flow_patterns",
                score=score,
            ))

        return matched

    def _extract_referenced_name(self, content: str, pattern: str) -> Optional[str]:
        """从匹配的模式中提取引用的名称

        Args:
            content: 文件内容
            pattern: 匹配的模式

        Returns:
            引用的名称，如果无法提取则返回 None
        """
        import re

        java_patterns_map = {
            "@Autowired": r"@Autowired\s+(\w+)",
            "@Inject": r"@Inject\s+(\w+)",
            "new Service(": r"new\s+(\w+Service\w*)\s*\(",
        }

        python_patterns_map = {
            "from . import": r"from\s+\.\s*import\s+(\w+)",
            "import": r"import\s+(\w+)",
        }

        for p, regex in {**java_patterns_map, **python_patterns_map}.items():
            if p == pattern or pattern in p:
                match = re.search(regex, content)
                if match:
                    return match.group(1)

        return None

    def _find_referenced_files(
        self, project_root: Path, referenced_name: str
    ) -> List[Path]:
        """查找引用的相关文件

        Args:
            project_root: 项目根目录
            referenced_name: 引用的名称

        Returns:
            匹配的文件路径列表
        """
        found_files: List[Path] = []

        for file_path in project_root.rglob("*"):
            if file_path.is_file():
                file_name = file_path.stem
                if referenced_name.lower() in file_name.lower():
                    found_files.append(file_path)
                    if len(found_files) >= 10:
                        break

        return found_files

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
            "correlation_score": result.correlation_score,
            "matched_keywords": result.matched_keywords,
            "matched_file_patterns": result.matched_file_patterns,
            "matched_paths": result.matched_paths,
            "matched_related_files": [
                {
                    "file_path": m.file_path,
                    "match_type": m.match_type,
                    "matched_pattern": m.matched_pattern,
                    "score": m.score,
                }
                for m in result.matched_related_files
            ],
        }
