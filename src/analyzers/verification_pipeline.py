"""验证管道

确保所有来源的发现都经过统一的三重核查
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.analyzers.finding_verifier import FindingVerifier
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class VerificationStats:
    """验证统计信息"""
    total_findings: int = 0
    verified_findings: int = 0
    already_verified: int = 0
    hallucination_count: int = 0
    triple_verified: int = 0
    double_verified: int = 0
    single_verified: int = 0
    needs_review: int = 0
    potential_hallucination: int = 0
    unknown: int = 0


class VerificationPipeline:
    """验证管道

    确保所有来源的发现都经过统一的三重核查：
    1. 路径验证 - 文件是否存在
    2. 代码验证 - 代码片段是否在文件中
    3. CWE匹配 - 是否匹配已知漏洞模式
    """

    def __init__(self, project_root: str = "", nvd_db_path: str = None):
        """初始化验证管道

        Args:
            project_root: 项目根目录
            nvd_db_path: NVD 数据库路径（可选）
        """
        self.project_root = project_root
        self.nvd_db_path = nvd_db_path
        self.verifier = FindingVerifier(project_root, nvd_db_path)

    def process_findings(self, findings: List, project_root: str = None) -> List:
        """处理所有发现，进行验证和标注

        Args:
            findings: 发现列表
            project_root: 项目根目录（可选，会覆盖初始化时的值）

        Returns:
            添加了验证信息的发现列表
        """
        root = project_root or self.project_root
        processed = []

        for finding in findings:
            if not self._has_verification(finding):
                verification = self.verifier.verify_and_annotate(finding, root)
                self._apply_verification(finding, verification)

            processed.append(finding)

        return processed

    def _has_verification(self, finding) -> bool:
        """检查发现是否有验证等级

        Args:
            finding: Finding 对象或字典

        Returns:
            是否已有验证等级
        """
        if isinstance(finding, dict):
            metadata = finding.get('metadata', {})
            return 'verification_level' in metadata
        elif hasattr(finding, 'metadata'):
            return 'verification_level' in finding.metadata
        elif hasattr(finding, 'location') and hasattr(finding.location, 'file'):
            return False
        return False

    def _apply_verification(self, finding, verification) -> None:
        """应用验证结果到发现

        Args:
            finding: Finding 对象或字典
            verification: FindingVerification 对象
        """
        if isinstance(finding, dict):
            metadata = finding.get('metadata', {})
            if not metadata:
                finding['metadata'] = metadata

            metadata['verification_level'] = verification.verification_level
            metadata['is_hallucination'] = verification.is_hallucination
            metadata['confidence_score'] = verification.confidence
            metadata['path_verified'] = verification.path_verified
            metadata['code_verified'] = verification.code_verified

            if verification.cwe_match:
                metadata['cwe_match'] = verification.cwe_match
                if verification.cwe_match.get('best_match'):
                    metadata['matched_cwe'] = verification.cwe_match['best_match']
                metadata['matched_cwes'] = verification.cwe_match.get('matched_cwes', [])

        elif hasattr(finding, 'metadata'):
            finding.metadata['verification_level'] = verification.verification_level
            finding.metadata['is_hallucination'] = verification.is_hallucination
            finding.metadata['confidence_score'] = verification.confidence
            finding.metadata['path_verified'] = verification.path_verified
            finding.metadata['code_verified'] = verification.code_verified

            if verification.cwe_match:
                finding.metadata['cwe_match'] = verification.cwe_match
                if verification.cwe_match.get('best_match'):
                    finding.metadata['matched_cwe'] = verification.cwe_match['best_match']
                finding.metadata['matched_cwes'] = verification.cwe_match.get('matched_cwes', [])

    def get_verification_stats(self, findings: List) -> VerificationStats:
        """获取验证统计信息

        Args:
            findings: 发现列表

        Returns:
            验证统计信息
        """
        stats = VerificationStats()
        stats.total_findings = len(findings)

        for finding in findings:
            verification_level = 'unknown'
            is_hallucination = False

            if isinstance(finding, dict):
                metadata = finding.get('metadata', {})
                verification_level = metadata.get('verification_level', 'unknown')
                is_hallucination = metadata.get('is_hallucination', False)
            elif hasattr(finding, 'metadata'):
                verification_level = finding.metadata.get('verification_level', 'unknown')
                is_hallucination = finding.metadata.get('is_hallucination', False)

            if verification_level != 'unknown':
                stats.verified_findings += 1
            else:
                stats.unknown += 1

            if is_hallucination:
                stats.hallucination_count += 1

            if verification_level == 'triple_verified':
                stats.triple_verified += 1
            elif verification_level == 'double_verified':
                stats.double_verified += 1
            elif verification_level == 'single_verified':
                stats.single_verified += 1
            elif verification_level == 'needs_review':
                stats.needs_review += 1
            elif verification_level == 'potential_hallucination':
                stats.potential_hallucination += 1

        return stats

    def filter_by_verification_level(
        self,
        findings: List,
        min_level: str = 'needs_review'
    ) -> List:
        """根据验证等级过滤发现

        Args:
            findings: 发现列表
            min_level: 最低验证等级要求

        Returns:
            符合要求的发现列表
        """
        level_order = {
            'triple_verified': 5,
            'double_verified': 4,
            'single_verified': 3,
            'needs_review': 2,
            'potential_hallucination': 1,
            'unknown': 0
        }

        min_order = level_order.get(min_level, 0)

        filtered = []
        for finding in findings:
            verification_level = 'unknown'

            if isinstance(finding, dict):
                verification_level = finding.get('metadata', {}).get('verification_level', 'unknown')
            elif hasattr(finding, 'metadata'):
                verification_level = finding.metadata.get('verification_level', 'unknown')

            level_order_value = level_order.get(verification_level, 0)

            if level_order_value >= min_order:
                filtered.append(finding)

        return filtered

    def sort_by_verification_level(self, findings: List, reverse: bool = True) -> List:
        """按验证等级排序发现

        Args:
            findings: 发现列表
            reverse: 是否降序（高等级在前）

        Returns:
            排序后的发现列表
        """
        level_order = {
            'triple_verified': 5,
            'double_verified': 4,
            'single_verified': 3,
            'needs_review': 2,
            'potential_hallucination': 1,
            'unknown': 0
        }

        def get_level_key(finding):
            verification_level = 'unknown'

            if isinstance(finding, dict):
                verification_level = finding.get('metadata', {}).get('verification_level', 'unknown')
            elif hasattr(finding, 'metadata'):
                verification_level = finding.metadata.get('verification_level', 'unknown')

            level_value = level_order.get(verification_level, 0)

            confidence = 0.0
            if isinstance(finding, dict):
                confidence = finding.get('metadata', {}).get('confidence_score', 0.0)
            elif hasattr(finding, 'metadata'):
                confidence = finding.metadata.get('confidence_score', 0.0)

            return (level_value, confidence)

        return sorted(findings, key=get_level_key, reverse=reverse)


def create_pipeline(project_root: str = "", nvd_db_path: str = None) -> VerificationPipeline:
    """创建验证管道实例

    Args:
        project_root: 项目根目录
        nvd_db_path: NVD 数据库路径

    Returns:
        VerificationPipeline 实例
    """
    return VerificationPipeline(project_root, nvd_db_path)