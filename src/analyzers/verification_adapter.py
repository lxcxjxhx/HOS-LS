"""验证适配器模块

将不同扫描器的发现格式转换为统一格式，并通过 UnifiedFindingValidator 进行验证。
用于连接 CodeVulnScanner 等规则扫描器和三重核查机制。
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Type, Union
from pathlib import Path

from src.utils.logger import get_logger
from src.analyzers.unified_finding_validator import UnifiedFindingValidator
from src.analyzers.finding_verifier import FindingVerification

logger = get_logger(__name__)


@dataclass
class VerificationStats:
    """验证统计信息"""
    total_findings: int = 0
    triple_verified: int = 0
    double_verified: int = 0
    single_verified: int = 0
    needs_review: int = 0
    potential_hallucination: int = 0
    unknown: int = 0
    hallucinations_filtered: int = 0
    average_confidence: float = 0.0
    confidence_scores: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_findings': self.total_findings,
            'triple_verified': self.triple_verified,
            'double_verified': self.double_verified,
            'single_verified': self.single_verified,
            'needs_review': self.needs_review,
            'potential_hallucination': self.potential_hallucination,
            'unknown': self.unknown,
            'hallucinations_filtered': self.hallucinations_filtered,
            'average_confidence': self.average_confidence,
        }


class FindingConverter:
    """发现格式转换器

    将不同扫描器的发现格式转换为 UnifiedFindingValidator 可验证的统一格式。
    """

    @staticmethod
    def from_code_vuln_finding(finding) -> Dict[str, Any]:
        """从 CodeVulnFinding 转换

        Args:
            finding: CodeVulnFinding 对象

        Returns:
            统一格式字典
        """
        return {
            'id': f"code_vuln_{finding.file_path}_{finding.line_number}",
            'rule_id': finding.vuln_type,
            'rule_name': finding.vuln_type,
            'severity': finding.level.value if hasattr(finding.level, 'value') else str(finding.level),
            'description': finding.description,
            'file_path': finding.file_path,
            'location': {
                'file': finding.file_path,
                'line': finding.line_number,
            },
            'code_snippet': finding.code_snippet,
            'fix_suggestion': finding.remediation,
            'confidence': 0.5,
            'metadata': {
                'source_scanner': 'CodeVulnScanner',
                'vuln_type': finding.vuln_type,
            }
        }

    @staticmethod
    def from_dict(finding: Dict[str, Any]) -> Dict[str, Any]:
        """从字典格式转换

        Args:
            finding: 字典格式的 finding

        Returns:
            统一格式字典
        """
        rule_id = finding.get('rule_id', finding.get('vuln_type', 'unknown'))
        rule_name = finding.get('rule_name', rule_id)

        severity = finding.get('severity', 'medium')
        if hasattr(severity, 'value'):
            severity = severity.value

        location = finding.get('location', {})
        if isinstance(location, str):
            location = {'file': location}

        file_path = finding.get('file_path', location.get('file', ''))
        line = finding.get('line', location.get('line', 0))

        return {
            'id': finding.get('id', f"dict_{file_path}_{line}"),
            'rule_id': rule_id,
            'rule_name': rule_name,
            'severity': severity,
            'description': finding.get('description', ''),
            'file_path': file_path,
            'location': {
                'file': file_path,
                'line': line,
            },
            'code_snippet': finding.get('code_snippet', ''),
            'fix_suggestion': finding.get('fix_suggestion', ''),
            'confidence': finding.get('confidence', 0.5),
            'metadata': finding.get('metadata', {}),
        }

    @staticmethod
    def to_standard_finding(finding: Dict[str, Any], verification: FindingVerification) -> Dict[str, Any]:
        """转换为包含验证信息的标准格式

        Args:
            finding: 原始发现字典
            verification: 验证结果

        Returns:
            包含验证信息的标准发现字典
        """
        result = finding.copy()
        result['metadata'] = result.get('metadata', {})

        result['metadata']['verification_level'] = verification.verification_level
        result['metadata']['is_hallucination'] = verification.is_hallucination
        result['metadata']['confidence_score'] = verification.confidence
        result['metadata']['path_verified'] = verification.path_verified
        result['metadata']['code_verified'] = verification.code_verified

        if verification.best_match:
            result['metadata']['matched_cwe'] = verification.best_match

        result['confidence'] = verification.confidence

        return result


class VerificationAdapter:
    """验证适配器

    将不同扫描器的发现格式转换为统一格式，
    并通过 UnifiedFindingValidator 进行验证。
    """

    def __init__(self, project_root: str = "", nvd_db_path: str = None):
        self.project_root = project_root
        self.validator = UnifiedFindingValidator(project_root)
        self.converter = FindingConverter()
        self._nvd_adapter = None

        if nvd_db_path:
            self._init_nvd_adapter(nvd_db_path)
        else:
            self._init_nvd_adapter()

    def _init_nvd_adapter(self, db_path: str = None) -> None:
        """初始化 NVD 适配器"""
        try:
            from src.nvd.nvd_query_adapter import NVDQueryAdapter
            self._nvd_adapter = NVDQueryAdapter(db_path)
            if not self._nvd_adapter.is_available():
                self._nvd_adapter = None
                logger.warning("NVD数据库不可用，模糊匹配将使用基础模式")
        except Exception as e:
            logger.warning(f"NVD适配器初始化失败: {e}")
            self._nvd_adapter = None

    def adapt_finding(self, finding: Any, project_root: str = None) -> Dict[str, Any]:
        """适配单个发现

        Args:
            finding: 任意格式的发现对象
            project_root: 项目根目录

        Returns:
            统一格式字典
        """
        root = project_root or self.project_root

        if hasattr(finding, 'vuln_type'):
            return self.converter.from_code_vuln_finding(finding)
        elif isinstance(finding, dict):
            return self.converter.from_dict(finding)
        else:
            logger.warning(f"未知发现格式: {type(finding)}")
            return {
                'id': f"unknown_{id(finding)}",
                'rule_id': 'unknown',
                'rule_name': 'unknown',
                'severity': 'medium',
                'description': str(finding),
                'file_path': '',
                'location': {'file': '', 'line': 0},
                'code_snippet': '',
                'fix_suggestion': '',
                'confidence': 0.0,
                'metadata': {'source_scanner': 'unknown'}
            }

    def verify_scanner_results(
        self,
        findings: List[Any],
        scanner_name: str,
        project_root: str = None,
        filter_hallucinations: bool = True,
        hallucination_threshold: float = 0.2,
        scanner_threshold: float = 0.5
    ) -> Tuple[List[Dict], VerificationStats]:
        """批量验证扫描器结果

        Args:
            findings: 扫描器发现列表
            scanner_name: 扫描器名称
            project_root: 项目根目录
            filter_hallucinations: 是否过滤幻觉发现
            hallucination_threshold: 幻觉阈值
            scanner_threshold: 扫描器特定的置信度阈值

        Returns:
            (验证后的发现列表, 验证统计)
        """
        root = project_root or self.project_root
        stats = VerificationStats()
        stats.total_findings = len(findings)

        verified_findings = []
        all_confidences = []

        for finding in findings:
            adapted = self.adapt_finding(finding, root)

            verification = self.validator.validate_finding(adapted, root)

            adapted = self.converter.to_standard_finding(adapted, verification)

            adapted['metadata']['source_scanner'] = scanner_name

            all_confidences.append(verification.confidence)

            level = verification.verification_level
            if level == 'triple_verified':
                stats.triple_verified += 1
            elif level == 'double_verified':
                stats.double_verified += 1
            elif level == 'single_verified':
                stats.single_verified += 1
            elif level == 'needs_review':
                stats.needs_review += 1
            elif level == 'potential_hallucination':
                stats.potential_hallucination += 1
            else:
                stats.unknown += 1

            if filter_hallucinations and verification.is_hallucination and verification.confidence < hallucination_threshold:
                stats.hallucinations_filtered += 1
                continue

            if verification.confidence >= scanner_threshold:
                verified_findings.append(adapted)

        stats.confidence_scores = all_confidences
        stats.average_confidence = sum(all_confidences) / len(all_confidences) if all_confidences else 0.0

        return verified_findings, stats

    def get_verification_stats(self, findings: List[Dict[str, Any]]) -> VerificationStats:
        """从已验证的发现列表中提取统计信息

        Args:
            findings: 已验证的发现列表

        Returns:
            验证统计
        """
        stats = VerificationStats()
        stats.total_findings = len(findings)

        all_confidences = []

        for finding in findings:
            metadata = finding.get('metadata', {})
            level = metadata.get('verification_level', 'unknown')
            confidence = metadata.get('confidence_score', 0.0)

            all_confidences.append(confidence)

            if level == 'triple_verified':
                stats.triple_verified += 1
            elif level == 'double_verified':
                stats.double_verified += 1
            elif level == 'single_verified':
                stats.single_verified += 1
            elif level == 'needs_review':
                stats.needs_review += 1
            elif level == 'potential_hallucination':
                stats.potential_hallucination += 1
            else:
                stats.unknown += 1

        stats.confidence_scores = all_confidences
        stats.average_confidence = sum(all_confidences) / len(all_confidences) if all_confidences else 0.0

        return stats


def get_verification_adapter(project_root: str = "", nvd_db_path: str = None) -> VerificationAdapter:
    """获取验证适配器实例

    Args:
        project_root: 项目根目录
        nvd_db_path: NVD 数据库路径

    Returns:
        VerificationAdapter 实例
    """
    return VerificationAdapter(project_root, nvd_db_path)
