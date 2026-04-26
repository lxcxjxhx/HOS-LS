"""统一漏洞发现验证器

所有漏洞发现必须经过此验证器进行三重核查：
1. 路径验证 - 文件是否存在
2. 代码验证 - 代码片段是否在文件中
3. CWE匹配 - 是否匹配已知漏洞模式

验证结果：
- verification_level: triple_verified / double_verified / single_verified / needs_review / potential_hallucination
- is_hallucination: bool
- confidence: float (0-1)
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from src.analyzers.finding_verifier import FindingVerifier, FindingVerification


VERIFICATION_MULTIPLIER = {
    'potential_hallucination': 0.5,
    'needs_review': 0.8,
    'single_verified': 1.0,
    'double_verified': 1.1,
    'triple_verified': 1.2
}


@dataclass
class UnifiedFindingValidator:
    """统一漏洞发现验证器

    所有漏洞发现必须经过此验证器进行三重核查，
    并将结果应用到 finding.metadata 中。
    """

    def __init__(self, project_root: str = ""):
        self.project_root = project_root
        self._verifier = FindingVerifier(project_root)

    def validate_finding(self, finding, project_root: Optional[str] = None) -> FindingVerification:
        """验证单个发现

        Args:
            finding: Finding 对象或字典
            project_root: 项目根目录

        Returns:
            FindingVerification 验证结果
        """
        root = project_root or self.project_root

        if isinstance(finding, dict):
            finding_dict = finding
            class DictFinding:
                def __init__(self, d):
                    for k, v in d.items():
                        setattr(self, k, v)
                    self.metadata = d.get('metadata', {})
                    self.location = type('Location', (), {'file': d.get('file_path', d.get('location', {}).get('file', ''))})()
            finding = DictFinding(finding_dict)

        verification = self._verifier.verify_and_annotate(finding, root)

        if hasattr(finding, 'metadata'):
            finding.metadata['verification_level'] = verification.verification_level
            finding.metadata['is_hallucination'] = verification.is_hallucination
            finding.metadata['confidence_score'] = verification.confidence
            finding.metadata['path_verified'] = verification.path_verified
            finding.metadata['code_verified'] = verification.code_verified
            if verification.best_match:
                finding.metadata['matched_cwe'] = verification.best_match

        return verification

    def validate_findings(self, findings: List, project_root: Optional[str] = None) -> List[FindingVerification]:
        """批量验证发现

        Args:
            findings: Finding 对象或字典列表
            project_root: 项目根目录

        Returns:
            验证结果列表
        """
        root = project_root or self.project_root
        verifications = []

        for finding in findings:
            verification = self.validate_finding(finding, root)
            verifications.append(verification)

        return verifications

    def filter_hallucinations(self, findings: List, threshold: float = 0.2) -> List:
        """过滤高风险幻觉发现

        Args:
            findings: Finding 对象或字典列表
            threshold: 置信度阈值，低于此值且为幻觉的发现将被过滤

        Returns:
            过滤后的发现列表
        """
        filtered = []
        for finding in findings:
            is_hallucination = False
            confidence = 1.0

            if isinstance(finding, dict):
                metadata = finding.get('metadata', {})
                is_hallucination = metadata.get('is_hallucination', False)
                confidence = metadata.get('confidence_score', 1.0)
            elif hasattr(finding, 'metadata'):
                metadata = finding.metadata
                is_hallucination = metadata.get('is_hallucination', False)
                confidence = metadata.get('confidence_score', 1.0)

            if is_hallucination and confidence < threshold:
                continue

            filtered.append(finding)

        return filtered

    def get_verification_stats(self, findings: List) -> Dict[str, int]:
        """获取验证统计信息

        Args:
            findings: Finding 对象或字典列表

        Returns:
            各验证等级的统计
        """
        stats = {
            'total': len(findings),
            'triple_verified': 0,
            'double_verified': 0,
            'single_verified': 0,
            'needs_review': 0,
            'potential_hallucination': 0,
            'unknown': 0
        }

        for finding in findings:
            level = 'unknown'
            if isinstance(finding, dict):
                level = finding.get('metadata', {}).get('verification_level', 'unknown')
            elif hasattr(finding, 'metadata'):
                level = finding.metadata.get('verification_level', 'unknown')

            if level in stats:
                stats[level] += 1
            else:
                stats['unknown'] += 1

        return stats


def get_unified_validator(project_root: str = "") -> UnifiedFindingValidator:
    """获取统一验证器实例

    Args:
        project_root: 项目根目录

    Returns:
        UnifiedFindingValidator 实例
    """
    return UnifiedFindingValidator(project_root)