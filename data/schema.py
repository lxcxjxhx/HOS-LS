"""数据Schema定义

定义统一的数据格式，用于加载SecureVibeBench和A.S.E数据集。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DatasetType(str, Enum):
    """数据集类型枚举"""
    SECUREVIBEBENCH = "securevibench"
    ASE = "ase"
    REPOPAIRBENCH = "repopairbench"
    CUSTOM = "custom"


class VulnerabilityType(str, Enum):
    """漏洞类型枚举"""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    DESERIALIZATION = "deserialization"
    TEMPLATE_INJECTION = "template_injection"
    RACE_CONDITION = "race_condition"
    OTHER = "other"


@dataclass
class CodeChange:
    """代码变更"""
    file_path: str
    function_name: str
    line_number: int = 0
    change_type: str = "modified"  # added, modified, deleted
    code_before: str = ""
    code_after: str = ""
    diff: str = ""


@dataclass
class SampleMetadata:
    """样本元数据"""
    sample_id: str
    dataset: DatasetType
    project_name: str = ""
    repo_url: str = ""
    commit_hash: str = ""
    language: str = "python"
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    vulnerability_type: VulnerabilityType = VulnerabilityType.OTHER
    severity: str = "HIGH"
    description: str = ""
    is_vulnerable: bool = True  # True=漏洞样本, False=修复样本


@dataclass
class SampleData:
    """样本数据"""
    metadata: SampleMetadata
    r_before: str  # 改前仓库路径
    task_desc: str  # 任务描述
    delta_ai: str  # AI生成的Unified Diff
    r_after: Optional[str] = None  # 改后仓库路径（可选）
    code_changes: List[CodeChange] = field(default_factory=list)
    modified_functions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "sample_id": self.metadata.sample_id,
                "dataset": self.metadata.dataset.value,
                "project_name": self.metadata.project_name,
                "repo_url": self.metadata.repo_url,
                "commit_hash": self.metadata.commit_hash,
                "language": self.metadata.language,
                "cve_ids": self.metadata.cve_ids,
                "cwe_ids": self.metadata.cwe_ids,
                "vulnerability_type": self.metadata.vulnerability_type.value,
                "severity": self.metadata.severity,
                "description": self.metadata.description,
                "is_vulnerable": self.metadata.is_vulnerable,
            },
            "r_before": self.r_before,
            "task_desc": self.task_desc,
            "delta_ai": self.delta_ai,
            "r_after": self.r_after,
            "code_changes": [
                {
                    "file_path": c.file_path,
                    "function_name": c.function_name,
                    "line_number": c.line_number,
                    "change_type": c.change_type,
                    "code_before": c.code_before,
                    "code_after": c.code_after,
                    "diff": c.diff,
                }
                for c in self.code_changes
            ],
            "modified_functions": self.modified_functions,
        }


@dataclass
class EvaluationResult:
    """评测结果"""
    sample_id: str
    prediction: bool  # 预测结果：True=有漏洞, False=无漏洞
    ground_truth: bool  # 真实标签
    is_correct: bool = False
    confidence: float = 0.0
    evidence: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        self.is_correct = self.prediction == self.ground_truth


@dataclass
class PairResult:
    """成对评测结果"""
    pair_id: str
    vuln_sample_id: str
    patched_sample_id: str
    vuln_prediction: bool
    patched_prediction: bool
    pair_correct: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        # 成对正确：漏洞样本预测为有漏洞，修复样本预测为无漏洞
        self.pair_correct = self.vuln_prediction and not self.patched_prediction


@dataclass
class EvaluationMetrics:
    """评测指标"""
    total_samples: int = 0
    correct_predictions: int = 0
    accuracy: float = 0.0
    
    # 漏洞样本指标
    vuln_total: int = 0
    vuln_correct: int = 0
    vuln_recall: float = 0.0
    
    # 修复样本指标
    patched_total: int = 0
    patched_correct: int = 0
    patched_specificity: float = 0.0
    
    # 成对指标
    total_pairs: int = 0
    pair_correct_count: int = 0
    pair_correct_rate: float = 0.0
    
    # 其他指标
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    f1_score: float = 0.0
    
    def calculate(self, results: List[EvaluationResult], pairs: List[PairResult]):
        """计算指标"""
        if not results:
            return
        
        self.total_samples = len(results)
        self.correct_predictions = sum(1 for r in results if r.is_correct)
        self.accuracy = self.correct_predictions / self.total_samples
        
        # 漏洞样本
        vuln_results = [r for r in results if r.ground_truth]
        self.vuln_total = len(vuln_results)
        self.vuln_correct = sum(1 for r in vuln_results if r.is_correct)
        self.vuln_recall = self.vuln_correct / self.vuln_total if self.vuln_total > 0 else 0.0
        
        # 修复样本
        patched_results = [r for r in results if not r.ground_truth]
        self.patched_total = len(patched_results)
        self.patched_correct = sum(1 for r in patched_results if r.is_correct)
        self.patched_specificity = self.patched_correct / self.patched_total if self.patched_total > 0 else 0.0
        
        # 成对指标
        if pairs:
            self.total_pairs = len(pairs)
            self.pair_correct_count = sum(1 for p in pairs if p.pair_correct)
            self.pair_correct_rate = self.pair_correct_count / self.total_pairs
        
        # 其他指标
        self.false_positives = sum(1 for r in results if r.prediction and not r.ground_truth)
        self.false_negatives = sum(1 for r in results if not r.prediction and r.ground_truth)
        
        predicted_positive = sum(1 for r in results if r.prediction)
        self.precision = (predicted_positive - self.false_positives) / predicted_positive if predicted_positive > 0 else 0.0
        
        if self.precision + self.vuln_recall > 0:
            self.f1_score = 2 * self.precision * self.vuln_recall / (self.precision + self.vuln_recall)
