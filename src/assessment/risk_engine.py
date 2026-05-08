"""Risk Scoring 引擎模块

实现三层过滤架构：
- Layer 1: AST + 结构过滤 - 只保留 API 入口、DB操作、IO操作、敏感调用点
- Layer 2: Taint Analysis - 只保留有完整污染路径的代码
- Layer 3: Risk Scoring - 计算 Top 20~50 候选

评分公式：
score = source可信度 + sink危险等级 + 传播复杂度 + 是否新代码 + 历史相似漏洞
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import hashlib
import json

from src.taint.engine import TaintPath, TaintSource, TaintSink, get_taint_engine
from src.db.models import Finding


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RiskFactorWeights:
    DEFAULT_WEIGHTS = {
        "cvss_weight": 0.40,
        "exploitability_weight": 0.35,
        "reachability_weight": 0.25,
    }

    def __init__(
        self,
        cvss_weight: float = 0.40,
        exploitability_weight: float = 0.35,
        reachability_weight: float = 0.25,
    ):
        self.cvss_weight = cvss_weight
        self.exploitability_weight = exploitability_weight
        self.reachability_weight = reachability_weight

    def to_dict(self) -> Dict[str, float]:
        return {
            "cvss_weight": self.cvss_weight,
            "exploitability_weight": self.exploitability_weight,
            "reachability_weight": self.reachability_weight,
        }


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnerabilityCandidate:
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    confidence: float
    location: Dict[str, Any]
    code_snippet: str
    fix_suggestion: str
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    taint_path: Optional[TaintPath] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "location": self.location,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "score_breakdown": self.score_breakdown,
            "metadata": self.metadata,
        }


@dataclass
class RiskScoreResult:
    overall_score: float
    source_score: float
    sink_score: float
    propagation_score: float
    context_score: float
    factors: Dict[str, float] = field(default_factory=dict)


class Layer1Filter:
    def __init__(self):
        self._api_entry_patterns = [
            "def ", "async def ", "function ", "class ",
        ]
        self._db_operation_patterns = [
            "execute", "query", "cursor", "select", "insert", "update", "delete",
            "fetch", "commit", "rollback",
        ]
        self._io_operation_patterns = [
            "open", "read", "write", "file", "input", "output", "load", "save",
        ]
        self._sensitive_call_patterns = [
            "eval", "exec", "system", "popen", "spawn", "subprocess",
            "os.", "sys.", "shutil.", "requests.", "urllib.",
        ]

    def filter(self, files: List[str], language: str = "python") -> List[Dict[str, Any]]:
        candidates = []

        for file_path in files:
            path = Path(file_path)
            if not path.exists():
                continue

            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            lines = content.split("\n")
            for i, line in enumerate(lines, 1):
                if self._is_interesting_line(line):
                    candidates.append({
                        "file": file_path,
                        "line": i,
                        "content": line.strip(),
                        "type": self._classify_line(line),
                    })

        return candidates

    def _is_interesting_line(self, line: str) -> bool:
        line_lower = line.lower().strip()

        for pattern in self._db_operation_patterns:
            if pattern in line_lower:
                return True

        for pattern in self._io_operation_patterns:
            if pattern in line_lower:
                return True

        for pattern in self._sensitive_call_patterns:
            if pattern in line_lower:
                return True

        if "def " in line and ("request" in line_lower or "user" in line_lower or "data" in line_lower):
            return True

        return False

    def _classify_line(self, line: str) -> str:
        line_lower = line.lower()

        for pattern in self._db_operation_patterns:
            if pattern in line_lower:
                return "db_operation"

        for pattern in self._io_operation_patterns:
            if pattern in line_lower:
                return "io_operation"

        for pattern in self._sensitive_call_patterns:
            if pattern in line_lower:
                return "sensitive_call"

        return "api_entry"


class Layer2Filter:
    def __init__(self):
        self._taint_engine = get_taint_engine()

    def filter(
        self,
        layer1_results: List[Dict[str, Any]],
        files: List[str],
        language: str = "python",
    ) -> List[TaintPath]:
        taint_paths = self._taint_engine.analyze(files, language)

        relevant_paths = []

        for path in taint_paths:
            if self._is_relevant(path, layer1_results):
                relevant_paths.append(path)

        return relevant_paths

    def _is_relevant(self, path: TaintPath, layer1_results: List[Dict[str, Any]]) -> bool:
        sink_file = path.sink.file_path
        sink_line = path.sink.line

        for result in layer1_results:
            if result["file"] == sink_file:
                if abs(result["line"] - sink_line) <= 5:
                    return True

        return False


class Layer3Scorer:
    def __init__(self):
        self._severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 1.0,
        }

        self._vulnerability_base_scores = {
            "SQL Injection": 9.0,
            "Command Injection": 9.5,
            "Code Injection": 10.0,
            "XSS": 7.0,
            "Path Traversal": 7.5,
            "SSRF": 8.0,
            "Deserialization": 9.0,
            "Authentication": 8.5,
            "Authorization": 8.0,
            "Cryptography": 8.5,
        }

        self._source_trust_scores = {
            "input": 1.0,
            "request.json": 0.9,
            "request.args": 0.8,
            "request.form": 0.8,
            "sys.stdin": 1.0,
            "open": 0.5,
            "os.environ": 0.6,
            "database": 0.4,
        }

    def score(self, taint_paths: List[TaintPath], max_candidates: int = 50) -> List[VulnerabilityCandidate]:
        candidates = []

        for path in taint_paths:
            candidate = self._create_candidate(path)
            candidates.append(candidate)

        candidates.sort(key=lambda c: self._get_composite_score(c), reverse=True)

        return candidates[:max_candidates]

    def _create_candidate(self, path: TaintPath) -> VulnerabilityCandidate:
        sink_type = path.sink.vulnerability_type

        source_score = self._calculate_source_score(path.source)
        sink_score = self._calculate_sink_score(sink_type)
        propagation_score = self._calculate_propagation_score(path)
        context_score = self._calculate_context_score(path)
        cross_file_bonus = self._calculate_cross_file_bonus(path)

        overall_score = (
            source_score * 0.2 +
            sink_score * 0.4 +
            propagation_score * 0.25 +
            context_score * 0.15 +
            cross_file_bonus
        )

        severity = self._map_score_to_severity(overall_score)

        confidence = self._calculate_confidence(path, source_score, sink_score)

        location = {
            "file": path.sink.file_path,
            "line": path.sink.line,
            "column": 0,
        }

        code_snippet = f"{path.source.name} → {path.sink.name}"

        fix_suggestion = self._generate_fix_suggestion(sink_type)

        chain_length = len(path.propagation_steps) if hasattr(path, 'propagation_steps') else 2
        file_count = getattr(path, 'file_count', 1) if path.cross_file else 1

        candidate = VulnerabilityCandidate(
            rule_id=f"VULN-{sink_type.replace(' ', '-')}",
            rule_name=sink_type,
            description=f"Potential {sink_type} via {path.source.name}",
            severity=severity,
            confidence=confidence,
            location=location,
            code_snippet=code_snippet,
            fix_suggestion=fix_suggestion,
            score_breakdown={
                "source_score": source_score,
                "sink_score": sink_score,
                "propagation_score": propagation_score,
                "context_score": context_score,
                "cross_file_bonus": cross_file_bonus,
                "overall_score": overall_score,
            },
            taint_path=path,
            metadata={
                "cross_function": path.cross_function,
                "cross_file": path.cross_file,
                "cross_file_vulnerability": path.cross_file,
                "related_file_count": file_count,
                "chain_length": chain_length,
                "sanitizers_found": path.sanitizers_found,
                "propagation_steps": len(path.propagation_steps),
            },
        )

        return candidate

    def _calculate_source_score(self, source: TaintSource) -> float:
        source_lower = source.name.lower()

        for key, score in self._source_trust_scores.items():
            if key in source_lower:
                return score * 10.0

        return 5.0

    def _calculate_sink_score(self, vulnerability_type: str) -> float:
        return self._vulnerability_base_scores.get(vulnerability_type, 5.0)

    def _calculate_cross_file_bonus(self, path: TaintPath) -> float:
        """计算跨文件漏洞额外加分"""
        if not path.cross_file:
            return 0.0

        base_bonus = 0.15
        file_count = getattr(path, 'file_count', 2)
        chain_length = len(path.propagation_steps) if hasattr(path, 'propagation_steps') else 2

        file_count_bonus = min((file_count - 1) * 0.05, 0.15)
        chain_length_bonus = min((chain_length - 2) * 0.03, 0.1)

        return base_bonus + file_count_bonus + chain_length_bonus

    def _calculate_propagation_score(self, path: TaintPath) -> float:
        score = 5.0

        if path.cross_function:
            score += 2.0

        if path.cross_file:
            score += 2.0
            if len(path.propagation_steps) > 2:
                score += 0.1
            if len(path.propagation_steps) > 3:
                score += 0.1

        if len(path.propagation_steps) > 3:
            score += 1.0
        elif len(path.propagation_steps) > 5:
            score += 2.0

        if path.sanitizers_found:
            score -= len(path.sanitizers_found) * 0.5

        return min(max(score, 0.0), 10.0)

    def _calculate_context_score(self, path: TaintPath) -> float:
        score = 5.0

        if path.sink.vulnerability_type in ["SQL Injection", "Command Injection", "Code Injection"]:
            score += 2.0

        if path.source.name in ["eval", "exec", "input"]:
            score += 1.5

        return min(max(score, 0.0), 10.0)

    def _calculate_confidence(self, path: TaintPath, source_score: float, sink_score: float) -> float:
        confidence = (source_score / 10.0) * 0.3 + (sink_score / 10.0) * 0.4

        if path.cross_function:
            confidence *= 0.9
        if path.cross_file:
            confidence += 0.05

        if path.sanitizers_found:
            confidence *= 0.8

        propagation_factor = 1.0 - (len(path.propagation_steps) * 0.05)
        confidence *= max(propagation_factor, 0.5)

        return min(max(confidence, 0.0), 1.0)

    def _map_score_to_severity(self, score: float) -> Severity:
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 5.0:
            return Severity.MEDIUM
        elif score >= 3.0:
            return Severity.LOW
        else:
            return Severity.INFO

    def _generate_fix_suggestion(self, vulnerability_type: str) -> str:
        suggestions = {
            "SQL Injection": "使用参数化查询或 ORM，避免字符串拼接 SQL",
            "Command Injection": "避免使用 shell=True，使用列表形式传递命令参数",
            "Code Injection": "避免使用 eval/exec 处理不可信输入",
            "XSS": "对输出进行 HTML 转义，使用 CSP",
            "Path Traversal": "使用 os.path.realpath 验证路径，使用白名单",
            "SSRF": "使用 URL 验证，禁止内部 IP 访问",
            "Deserialization": "避免反序列化不可信数据，使用 JSON 替代",
        }
        return suggestions.get(vulnerability_type, "对输入进行严格验证和过滤")

    def _get_composite_score(self, candidate: VulnerabilityCandidate) -> float:
        breakdown = candidate.score_breakdown
        return breakdown.get("overall_score", 0.0)


class RiskEngine:
    _instance: Optional["RiskEngine"] = None

    def __new__(cls, weights: Optional[RiskFactorWeights] = None) -> "RiskEngine":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize(weights)
        return cls._instance

    def _initialize(self, weights: Optional[RiskFactorWeights] = None) -> None:
        self.layer1 = Layer1Filter()
        self.layer2 = Layer2Filter()
        self.layer3 = Layer3Scorer()
        self._weights = weights or RiskFactorWeights()

    @staticmethod
    def classify_risk_level(
        cvss: float,
        exploitability: float,
        reachability: float,
    ) -> RiskLevel:
        if cvss >= 9.0 or (cvss >= 7.0 and exploitability >= 0.9):
            return RiskLevel.CRITICAL
        elif cvss >= 7.0 or (cvss >= 4.0 and exploitability >= 0.7):
            return RiskLevel.HIGH
        elif cvss >= 4.0 or (cvss >= 0.1 and exploitability >= 0.3):
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def analyze(
        self,
        files: List[str],
        language: str = "python",
        max_candidates: int = 50,
    ) -> List[VulnerabilityCandidate]:
        layer1_results = self.layer1.filter(files, language)

        if not layer1_results:
            return []

        taint_paths = self.layer2.filter(layer1_results, files, language)

        if not taint_paths:
            return []

        candidates = self.layer3.score(taint_paths, max_candidates)

        return candidates

    def get_candidates_by_severity(
        self,
        candidates: List[VulnerabilityCandidate],
        severity: Severity,
    ) -> List[VulnerabilityCandidate]:
        return [c for c in candidates if c.severity == severity]

    def get_high_risk_candidates(
        self,
        candidates: List[VulnerabilityCandidate],
    ) -> List[VulnerabilityCandidate]:
        return [c for c in candidates if c.severity in [Severity.CRITICAL, Severity.HIGH]]

    def calculate_risk_matrix(
        self,
        findings: List[Finding],
    ) -> Dict[str, Any]:
        matrix: Dict[str, List[Dict[str, Any]]] = {
            "critical_critical": [],
            "critical_high": [],
            "critical_medium": [],
            "critical_low": [],
            "high_critical": [],
            "high_high": [],
            "high_medium": [],
            "high_low": [],
            "medium_critical": [],
            "medium_high": [],
            "medium_medium": [],
            "medium_low": [],
            "low_critical": [],
            "low_high": [],
            "low_medium": [],
            "low_low": [],
        }

        likelihood_labels = ["low", "medium", "high", "critical"]
        impact_labels = ["low", "medium", "high", "critical"]

        for finding in findings:
            cvss = float(finding.metadata.get("cvss", 5.0))
            exploitability = float(finding.metadata.get("exploitability", 0.5))
            reachability = float(finding.metadata.get("reachability", 0.5))

            likelihood = self.classify_risk_level(cvss, exploitability, reachability)
            impact = self.classify_risk_level(cvss * 0.8, exploitability * 0.9, reachability * 0.7)

            likelihood_idx = likelihood_labels.index(likelihood.value) if likelihood.value in likelihood_labels else 1
            impact_idx = impact_labels.index(impact.value) if impact.value in impact_labels else 1

            if likelihood_idx >= 2 and impact_idx >= 2:
                likelihood_key = "critical"
            elif likelihood_idx >= 2:
                likelihood_key = "high"
            elif likelihood_idx >= 1:
                likelihood_key = "medium"
            else:
                likelihood_key = "low"

            if impact_idx >= 2:
                impact_key = "critical"
            elif impact_idx >= 1:
                impact_key = "medium"
            else:
                impact_key = "low"

            matrix_key = f"{likelihood_key}_{impact_key}"

            finding_dict = finding.to_dict() if hasattr(finding, "to_dict") else {
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name,
                "description": finding.description,
                "severity": finding.severity,
                "file_path": finding.file_path,
                "line": finding.line,
                "confidence": finding.confidence,
                "message": finding.message,
                "metadata": finding.metadata,
            }
            matrix[matrix_key].append(finding_dict)

        return matrix

    def generate_risk_summary(
        self,
        findings: List[Finding],
    ) -> Dict[str, Any]:
        matrix = self.calculate_risk_matrix(findings)

        critical_count = (
            len(matrix["critical_critical"]) +
            len(matrix["critical_high"]) +
            len(matrix["critical_medium"]) +
            len(matrix["critical_low"]) +
            len(matrix["high_critical"])
        )

        high_count = (
            len(matrix["high_medium"]) +
            len(matrix["high_low"]) +
            len(matrix["medium_critical"])
        )

        medium_count = (
            len(matrix["medium_medium"]) +
            len(matrix["medium_low"]) +
            len(matrix["low_critical"])
        )

        low_count = (
            len(matrix["low_medium"]) +
            len(matrix["low_low"])
        )

        return {
            "matrix": matrix,
            "summary": {
                "total_findings": len(findings),
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
            },
        }

    def get_standardized_output(
        self,
        candidates: List[VulnerabilityCandidate],
    ) -> List[Dict[str, Any]]:
        output = []

        for candidate in candidates:
            output.append({
                "rule_id": candidate.rule_id,
                "rule_name": candidate.rule_name,
                "description": candidate.description,
                "severity": candidate.severity.value,
                "confidence": candidate.confidence,
                "location": candidate.location,
                "code_snippet": candidate.code_snippet,
                "fix_suggestion": candidate.fix_suggestion,
                "score_breakdown": candidate.score_breakdown,
                "metadata": candidate.metadata,
            })

        return output


def get_risk_engine() -> RiskEngine:
    return RiskEngine()
