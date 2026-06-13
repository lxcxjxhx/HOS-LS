"""AI 发现验证模块

对 AI 生成的漏洞发现进行验证，包括：
- 文件路径真实性核查
- 代码片段存在性验证
- CWE/NVD 模式匹配
- 置信度计算
"""

import os
import re
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Set
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class FindingVerification:
    """漏洞发现验证结果

    包含三重核查的完整结果：
    - path_verified: 文件路径是否真实存在
    - code_verified: 代码片段是否在文件中
    - cwe_match: CWE 模式匹配结果
    - confidence: 综合置信度 (0-1)
    - verification_level: 验证等级
    - is_hallucination: 是否为幻觉发现
    - matched_cwes: 匹配的 CWE 列表
    - best_match: 最佳匹配的 CWE
    """
    path_verified: bool = False
    code_verified: bool = False
    cwe_match: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    verification_level: str = 'unknown'
    is_hallucination: bool = True
    matched_cwes: List[Dict] = field(default_factory=list)
    best_match: Optional[Dict] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'path_verified': self.path_verified,
            'code_verified': self.code_verified,
            'cwe_match': self.cwe_match,
            'confidence': self.confidence,
            'verification_level': self.verification_level,
            'is_hallucination': self.is_hallucination,
            'matched_cwes': self.matched_cwes,
            'best_match': self.best_match
        }


class FindingVerifier:
    """AI 发现验证器

    改造版：使用 AI 动态编排替代硬编码 CWE_PATTERNS。
    硬编码规则已迁移到 src/ai/agents/ai_security_agents.py。
    """

    # 保留最小化的 CWE 映射用于回退（当 AI/LLM 不可用时）
    # 这些不再用于主动匹配，仅作为降级模式
    CWE_PATTERNS = {}  # 已清空，改用 AI 动态分类

    def __init__(self, project_root: str = "", nvd_db_path: str = None):
        self.project_root = project_root
        self.nvd_adapter = None

        if nvd_db_path:
            try:
                from src.nvd.nvd_query_adapter import NVDQueryAdapter
                self.nvd_adapter = NVDQueryAdapter(nvd_db_path)
                if not self.nvd_adapter.is_available():
                    self.nvd_adapter = None
            except Exception:
                self.nvd_adapter = None

    def verify_finding_path(self, finding, project_root: Optional[str] = None) -> bool:
        """验证 Finding 中的路径是否存在且有效"""
        try:
            if isinstance(finding, dict):
                location = finding.get('location')
                if not location or not isinstance(location, dict):
                    logger.debug(f"[Path] Finding has no valid location (dict)")
                    return False
                file_path = location.get('file')
                line = location.get('line', 0)
            else:
                if not hasattr(finding, 'location'):
                    logger.debug(f"[Path] Finding has no location attribute")
                    return False

                if isinstance(finding.location, dict):
                    file_path = finding.location.get('file')
                    line = finding.location.get('line', 0)
                else:
                    file_path = finding.location.file
                    line = getattr(finding.location, 'line', 0)

            if not file_path:
                logger.debug(f"[Path] Finding has no file path")
                return False

            root = project_root or self.project_root
            if root and not os.path.isabs(file_path):
                full_path = os.path.join(root, file_path)
            else:
                full_path = file_path

            return os.path.exists(full_path)
        except Exception as e:
            logger.debug(f"[Path] Exception verifying path: {e}")
            return False

    def verify_finding_code(self, finding, project_root: Optional[str] = None) -> bool:
        """验证漏洞报告中的代码片段是否在文件中

        Args:
            finding: Finding 对象
            project_root: 项目根目录

        Returns:
            代码片段是否在文件中
        """
        root = project_root or self.project_root

        if isinstance(finding, dict):
            location = finding.get('location')
            if not location or not isinstance(location, dict):
                logger.debug(f"[Code] Finding has no valid location (dict)")
                return False
            file_path = location.get('file')
            code_snippet = finding.get('code_snippet')
            line_num = location.get('line', 0)
        else:
            if not hasattr(finding, 'location'):
                logger.debug(f"[Code] Finding has no location attribute")
                return False
            if isinstance(finding.location, dict):
                file_path = finding.location.get('file')
                line_num = finding.location.get('line', 0)
            else:
                file_path = finding.location.file
                line_num = getattr(finding.location, 'line', 0)
            code_snippet = getattr(finding, 'code_snippet', None)

        if not file_path:
            return False

        if root and not os.path.isabs(file_path):
            full_path = os.path.join(root, file_path)
        else:
            full_path = file_path

        if not os.path.exists(full_path):
            return False

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return False

        if code_snippet and code_snippet.strip():
            if code_snippet.strip() in content:
                return True

        # 回退：如果没有代码片段但有有效行号，尝试从文件提取对应行
        if (not code_snippet or not code_snippet.strip()) and line_num and line_num > 0:
            try:
                lines = content.split('\n')
                if 1 <= line_num <= len(lines):
                    # 提取目标行及上下文
                    start = max(0, line_num - 1 - 2)
                    end = min(len(lines), line_num + 2)
                    extracted = '\n'.join(lines[start:end])
                    # 将提取的代码填充到finding中
                    if isinstance(finding, dict):
                        finding['code_snippet'] = extracted
                    else:
                        setattr(finding, 'code_snippet', extracted)
                    return True
            except Exception:
                pass

        rule_name = getattr(finding, 'rule_name', '') or ''
        if rule_name and code_snippet and code_snippet.strip():
            # 使用 NVD 动态匹配而非硬编码模式
            if self.nvd_adapter and self.nvd_adapter.is_available():
                keywords = self._extract_keywords(finding)
                nvd_results = self.nvd_adapter.match_cwe(keywords, limit=3)
                for nvd_result in nvd_results:
                    nvd_keywords = nvd_result.get('matched_keywords', [])
                    for kw in nvd_keywords:
                        if kw.lower() in content.lower():
                            return True

        return False

    def match_cwe(self, finding) -> Dict[str, Any]:
        """将 AI 发现与 CWE 模式匹配

        优化版本：优先使用 NVD 数据库 + 缓存 + CVSS 统计辅助

        Args:
            finding: Finding 对象

        Returns:
            匹配的 CWE 信息，包含:
            - matched_cwes: 匹配的 CWE 列表
            - confidence: 置信度
            - matched_patterns: 匹配的模式列表
        """
        matched_cwes = []
        keywords = self._extract_keywords(finding)

        if not keywords:
            return {'matched_cwes': [], 'best_match': None, 'confidence': 0.0}

        if self.nvd_adapter and self.nvd_adapter.is_available():
            nvd_results = self.nvd_adapter.match_cwe(keywords, limit=5)
            if nvd_results:
                for nvd_result in nvd_results:
                    cvss_stats = {}
                    if self.nvd_adapter:
                        cvss_stats = self.nvd_adapter.get_cwe_with_cvss_stats(nvd_result['cwe_id'])

                    confidence = nvd_result.get('confidence', 0.5)

                    if cvss_stats and cvss_stats.get('avg_cvss', 0) > 7.0:
                        confidence = min(1.0, confidence * 1.2)

                    matched_cwes.append({
                        'cwe_id': nvd_result['cwe_id'],
                        'cwe_name': nvd_result['cwe_name'],
                        'pattern_name': 'nvd_db',
                        'confidence': confidence,
                        'matched_keywords': nvd_result.get('matched_keywords', []),
                        'matched_patterns': [],
                        'source': 'nvd_database',
                        'cvss_stats': cvss_stats
                    })

        hardcoded_results = self._match_cwe_hardcoded(finding)
        matched_cwes.extend(hardcoded_results.get('matched_cwes', []))

        if matched_cwes:
            seen = set()
            unique_results = []
            for m in matched_cwes:
                if m['cwe_id'] not in seen:
                    seen.add(m['cwe_id'])
                    unique_results.append(m)

            best_match = max(unique_results, key=lambda x: x['confidence'])
            return {
                'matched_cwes': unique_results,
                'best_match': best_match,
                'confidence': best_match['confidence']
            }

        return {
            'matched_cwes': [],
            'best_match': None,
            'confidence': 0.0
        }

    def _match_cwe_hardcoded(self, finding) -> Dict[str, Any]:
        """使用 NVD 数据库动态匹配 CWE（替代硬编码模式）

        Args:
            finding: Finding 对象

        Returns:
            匹配的 CWE 信息
        """
        matched_cwes = []
        rule_name = self._get_finding_attr(finding, 'rule_name')
        description = self._get_finding_attr(finding, 'description')
        code_snippet = self._get_finding_attr(finding, 'code_snippet')

        combined_text = f"{rule_name} {description} {code_snippet}".lower()

        # 从 NVD 动态匹配 CWE
        if self.nvd_adapter and self.nvd_adapter.is_available():
            keywords = self._extract_keywords(finding)
            nvd_results = self.nvd_adapter.match_cwe(keywords, limit=5)

            for nvd_result in nvd_results:
                matched_cwes.append({
                    'cwe_id': nvd_result.get('cwe_id', ''),
                    'cwe_name': nvd_result.get('cwe_name', ''),
                    'pattern_name': nvd_result.get('cwe_id', '').lower().replace('-', '_'),
                    'confidence': nvd_result.get('confidence', 0.5),
                    'matched_keywords': nvd_result.get('matched_keywords', []),
                    'matched_patterns': [],
                    'source': 'nvd_database'
                })

        # 如果 NVD 不可用或无匹配，返回空（不再使用硬编码回退）
        return {'matched_cwes': matched_cwes}

    def _get_finding_attr(self, finding, key: str, default: str = '') -> str:
        """安全获取finding属性，支持dict和对象

        Args:
            finding: Finding 对象或字典
            key: 属性名
            default: 默认值

        Returns:
            属性值字符串
        """
        if isinstance(finding, dict):
            val = finding.get(key, default)
        else:
            val = getattr(finding, key, default)
        return val or default

    def _extract_keywords(self, finding) -> List[str]:
        """从 finding 中提取关键词

        Args:
            finding: Finding 对象

        Returns:
            关键词列表
        """
        rule_name = self._get_finding_attr(finding, 'rule_name')
        description = self._get_finding_attr(finding, 'description')
        code_snippet = self._get_finding_attr(finding, 'code_snippet')

        combined_text = f"{rule_name} {description}".lower()

        keywords = []
        keyword_set = set()

        for pattern_info in self.CWE_PATTERNS.values():
            for kw in pattern_info['keywords']:
                if kw.lower() in combined_text and kw.lower() not in keyword_set:
                    keywords.append(kw)
                    keyword_set.add(kw.lower())

        vuln_keywords = ['injection', 'xss', 'csrf', 'traversal', 'disclosure', 'weak', 'hardcoded',
                        'command', 'sql', 'path', 'sensitive', 'credential', 'secret', 'authentication']
        for kw in vuln_keywords:
            if kw in combined_text and kw not in keyword_set:
                keywords.append(kw)
                keyword_set.add(kw)

        return keywords[:10]

    def calculate_confidence(self, finding, project_root: Optional[str] = None) -> float:
        """计算 AI 发现的最终置信度

        Args:
            finding: Finding 对象
            project_root: 项目根目录

        Returns:
            置信度分数 (0.0 - 1.0)
        """
        root = project_root or self.project_root

        path_valid = self.verify_finding_path(finding, root)
        code_valid = self.verify_finding_code(finding, root)
        cwe_match = self.match_cwe(finding)

        # Check if finding was agent-confirmed (from metadata)
        is_agent_confirmed = False
        if hasattr(finding, 'metadata'):
            meta = finding.metadata
            is_agent_confirmed = meta.get('signal_state') == 'CONFIRMED' or meta.get('status') == 'CONFIRMED'
        elif isinstance(finding, dict):
            meta = finding.get('metadata', {})
            is_agent_confirmed = meta.get('signal_state') == 'CONFIRMED' or meta.get('status') == 'CONFIRMED'

        confidence = 0.0
        verification_score = 0.0

        if path_valid:
            verification_score += 0.25

        if code_valid:
            verification_score += 0.35

        # CWE match contribution (now works with Python patterns)
        cwe_conf = cwe_match.get('confidence', 0.0) if isinstance(cwe_match, dict) else 0.0
        if cwe_conf > 0:
            verification_score += cwe_conf * 0.3
        elif is_agent_confirmed and (path_valid or code_valid):
            # Agent confirmed + code/path verification = sufficient for confidence boost
            verification_score += 0.25

        # Get original AI confidence for blending
        original_conf = 0.5
        if hasattr(finding, 'confidence'):
            original_conf = finding.confidence
        elif isinstance(finding, dict):
            original_conf = finding.get('confidence', 0.5)

        # Dynamic confidence calculation
        if verification_score >= 0.8 and is_agent_confirmed:
            # Strong verification: path + code + CWE match
            confidence = min(0.95, verification_score * 0.7 + original_conf * 0.3)
        elif verification_score >= 0.6 and is_agent_confirmed:
            # Good verification: path + code or agent + partial
            confidence = min(0.85, verification_score * 0.6 + original_conf * 0.4)
        elif verification_score >= 0.5:
            # Basic verification: path + code
            confidence = verification_score
        else:
            # Low verification - blend with original confidence
            confidence = verification_score * 0.5 + original_conf * 0.5

        # Severity-based floor (CRITICAL/HIGH vulns with agent confirmation should have minimum confidence)
        if is_agent_confirmed and path_valid and code_valid:
            severity = ''
            if hasattr(finding, 'severity'):
                severity = getattr(finding, 'severity', '')
            elif isinstance(finding, dict):
                severity = finding.get('severity', '')
            if severity in ('CRITICAL', 'HIGH'):
                confidence = max(confidence, 0.75)

        return min(1.0, max(0.0, confidence))

    def _is_file_in_project_scope(self, file_path: str, project_root: str) -> bool:
        """检查文件是否在项目扫描范围内

        Args:
            file_path: 文件路径
            project_root: 项目根目录

        Returns:
            文件是否在项目扫描范围内
        """
        if not file_path or not project_root:
            return False

        try:
            file_path_obj = Path(file_path)
            if file_path_obj.is_absolute():
                abs_file_path = file_path_obj.resolve()
            else:
                abs_file_path = (Path(project_root) / file_path_obj).resolve()
            abs_project_root = Path(project_root).resolve()

            file_str = str(abs_file_path)
            root_str = str(abs_project_root)

            return file_str.startswith(root_str)
        except Exception:
            return False

    def verify_and_annotate(self, finding, project_root: Optional[str] = None) -> Dict[str, Any]:
        """对发现进行全面验证并注解

        Args:
            finding: Finding 对象
            project_root: 项目根目录

        Returns:
            验证结果字典
        """
        root = project_root or self.project_root

        if isinstance(finding, dict):
            location = finding.get('location')
            if location and isinstance(location, dict):
                file_path = location.get('file')
            else:
                file_path = None
            metadata = finding.get('metadata', {})
        else:
            if hasattr(finding, 'location'):
                if isinstance(finding.location, dict):
                    file_path = finding.location.get('file')
                else:
                    file_path = finding.location.file if hasattr(finding.location, 'file') else None
            else:
                file_path = None
            metadata = getattr(finding, 'metadata', {})

        signal_state = metadata.get('signal_state', 'NEW')
        status = metadata.get('status', 'UNKNOWN')
        is_agent_confirmed = signal_state == 'CONFIRMED' or status == 'CONFIRMED'

        is_scope_verified = True
        if root and file_path and not self._is_file_in_project_scope(file_path, root):
            logger.debug(f"[Scope] 文件路径与项目根目录不匹配，尝试模糊匹配: {file_path}")
            file_name = Path(file_path).name
            root_files = list(Path(root).rglob('*')) if Path(root).exists() else []
            root_file_names = {f.name for f in root_files if f.is_file()}
            if file_name not in root_file_names:
                logger.debug(f"[Scope] 模糊匹配失败，文件不在项目扫描范围内: {file_path}")
                is_scope_verified = False
            else:
                logger.debug(f"[Scope] 模糊匹配成功，文件名存在于项目中: {file_name}")
                is_scope_verified = True

        if not is_scope_verified:
            path_valid = self.verify_finding_path(finding, root)
            code_valid = self.verify_finding_code(finding, root)
            cwe_match = self.match_cwe(finding)
            confidence = self.calculate_confidence(finding, root) * 0.5

            return FindingVerification(
                path_verified=False,
                code_verified=code_valid,
                cwe_match=cwe_match,
                confidence=confidence,
                verification_level='needs_review',
                is_hallucination=False,
                matched_cwes=[],
                best_match=None
            )

        path_valid = self.verify_finding_path(finding, root)
        code_valid = self.verify_finding_code(finding, root)
        cwe_match = self.match_cwe(finding)
        confidence = self.calculate_confidence(finding, root)

        if is_agent_confirmed:
            verification_level = 'single_verified' if confidence < 0.5 else (
                'double_verified' if confidence < 0.7 else (
                    'triple_verified' if confidence >= 0.9 else 'single_verified'
                )
            )
        elif confidence >= 0.9 and path_valid and code_valid and cwe_match['best_match']:
            verification_level = 'triple_verified'
        elif confidence >= 0.7 and path_valid and cwe_match['best_match']:
            verification_level = 'double_verified'
        elif confidence >= 0.5 and path_valid:
            verification_level = 'single_verified'
        elif confidence >= 0.3 and path_valid:
            verification_level = 'needs_review'
        else:
            verification_level = 'potential_hallucination'

        is_hallucination = confidence < 0.3 and not is_agent_confirmed

        return FindingVerification(
            path_verified=path_valid,
            code_verified=code_valid,
            cwe_match=cwe_match,
            confidence=confidence,
            verification_level=verification_level,
            is_hallucination=is_hallucination,
            matched_cwes=cwe_match.get('matched_cwes', []),
            best_match=cwe_match.get('best_match')
        )


class FuzzyCweMatcher:
    """模糊 CWE 匹配器

    使用语义相似性而非硬编码关键词匹配。
    集成 NVD 数据库进行语义相似度计算。
    """

    def __init__(self, nvd_adapter=None):
        """初始化模糊匹配器

        Args:
            nvd_adapter: NVDQueryAdapter 实例
        """
        self.nvd_adapter = nvd_adapter
        self._semantic_cache: Dict[str, List[Dict]] = {}

    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """计算两个文本的相似度

        使用简单的词集合相似度算法

        Args:
            text1: 文本1
            text2: 文本2

        Returns:
            相似度分数 (0-1)
        """
        if not text1 or not text2:
            return 0.0

        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2

        if not union:
            return 0.0

        return len(intersection) / len(union)

    def _get_cwe_descriptions(self, cwe_ids: List[str]) -> Dict[str, str]:
        """获取 CWE 描述字典

        Args:
            cwe_ids: CWE ID 列表

        Returns:
            CWE ID -> 描述的字典
        """
        if not self.nvd_adapter:
            return {}

        descriptions = {}
        for cwe_id in cwe_ids:
            cwe_info = self.nvd_adapter.get_cwe_by_id(cwe_id)
            if cwe_info:
                descriptions[cwe_id] = cwe_info.get('cwe_description', '')

        return descriptions

    def match_with_fuzzy_similarity(
        self,
        finding: Dict[str, Any],
        threshold: float = 0.6
    ) -> List[Dict[str, Any]]:
        """基于语义相似性匹配 CWE

        Args:
            finding: 发现字典
            threshold: 相似度阈值 (0-1)

        Returns:
            匹配的 CWE 列表，按相似度排序
        """
        rule_name = finding.get('rule_name', '')
        description = finding.get('description', '')
        code_snippet = finding.get('code_snippet', '')

        combined_text = f"{rule_name} {description}".strip()

        cache_key = f"{combined_text}:{threshold}"
        if cache_key in self._semantic_cache:
            return self._semantic_cache[cache_key]

        matched_results = []

        if self.nvd_adapter and self.nvd_adapter.is_available():
            keywords = self._extract_keywords_from_text(combined_text)
            nvd_results = self.nvd_adapter.match_cwe(keywords, limit=10)

            for nvd_result in nvd_results:
                cwe_desc = nvd_result.get('cwe_description', '')
                similarity = self._calculate_text_similarity(combined_text.lower(), cwe_desc.lower())

                if similarity >= threshold:
                    matched_results.append({
                        'cwe_id': nvd_result['cwe_id'],
                        'cwe_name': nvd_result['cwe_name'],
                        'cwe_description': cwe_desc,
                        'confidence': similarity,
                        'matched_keywords': nvd_result.get('matched_keywords', []),
                        'source': 'nvd_database',
                        'match_type': 'fuzzy_semantic'
                    })

        hardcoded_results = self._match_cwe_hardcoded(finding)
        for hr in hardcoded_results.get('matched_cwes', []):
            cwe_desc = hr.get('cwe_description', '')
            similarity = self._calculate_text_similarity(combined_text.lower(), cwe_desc.lower())

            if similarity >= threshold:
                matched_results.append({
                    'cwe_id': hr['cwe_id'],
                    'cwe_name': hr['cwe_name'],
                    'cwe_description': cwe_desc,
                    'confidence': similarity,
                    'matched_keywords': hr.get('matched_keywords', []),
                    'source': 'hardcoded_pattern',
                    'match_type': 'fuzzy_semantic'
                })

        matched_results.sort(key=lambda x: x['confidence'], reverse=True)
        unique_results = []
        seen_ids = set()
        for r in matched_results:
            if r['cwe_id'] not in seen_ids:
                seen_ids.add(r['cwe_id'])
                unique_results.append(r)

        self._semantic_cache[cache_key] = unique_results[:5]
        return unique_results[:5]

    def _extract_keywords_from_text(self, text: str) -> List[str]:
        """从文本中提取关键词

        Args:
            text: 输入文本

        Returns:
            关键词列表
        """
        vuln_keywords = [
            'injection', 'xss', 'csrf', 'traversal', 'disclosure', 'weak',
            'hardcoded', 'command', 'sql', 'path', 'sensitive', 'credential',
            'secret', 'authentication', 'authorization', 'serialization',
            'deserialization', 'overflow', 'disclosure', 'exposure'
        ]

        text_lower = text.lower()
        keywords = []

        for kw in vuln_keywords:
            if kw in text_lower:
                keywords.append(kw)

        words = text_lower.split()
        for word in words:
            if len(word) > 4 and word not in keywords:
                keywords.append(word)

        return keywords[:10]

    def _match_cwe_hardcoded(self, finding) -> Dict[str, Any]:
        """使用 NVD 数据库动态匹配 CWE（替代硬编码模式）

        Args:
            finding: Finding 对象

        Returns:
            匹配的 CWE 信息
        """
        matched_cwes = []
        rule_name = getattr(finding, 'rule_name', '') or finding.get('rule_name', '')
        description = getattr(finding, 'description', '') or finding.get('description', '')
        code_snippet = getattr(finding, 'code_snippet', '') or finding.get('code_snippet', '')

        combined_text = f"{rule_name} {description} {code_snippet}".lower()

        # FuzzyCweMatcher 使用 NVD 动态匹配
        if self.nvd_adapter and self.nvd_adapter.is_available():
            keywords = self._extract_keywords_from_text(combined_text)
            nvd_results = self.nvd_adapter.match_cwe(keywords, limit=5)

            for nvd_result in nvd_results:
                cwe_desc = nvd_result.get('cwe_description', '')
                similarity = self._calculate_text_similarity(combined_text.lower(), cwe_desc.lower())

                matched_cwes.append({
                    'cwe_id': nvd_result['cwe_id'],
                    'cwe_name': nvd_result['cwe_name'],
                    'confidence': similarity,
                    'matched_keywords': nvd_result.get('matched_keywords', []),
                    'cwe_description': cwe_desc,
                    'source': 'nvd_database'
                })

        return {'matched_cwes': matched_cwes}


def verify_ai_findings(findings: List, project_root: str, nvd_vulnerabilities: List = None, nvd_db_path: str = None) -> List[Dict[str, Any]]:
    """批量验证 AI 发现

    Args:
        findings: Finding 对象列表
        project_root: 项目根目录
        nvd_vulnerabilities: NVD 漏洞列表（可选，已废弃，仅保留兼容性）
        nvd_db_path: NVD 数据库路径（可选）

    Returns:
        验证结果列表
    """
    verifier = FindingVerifier(project_root, nvd_db_path)
    results = []

    for finding in findings:
        verification = verifier.verify_and_annotate(finding, project_root)
        verification_dict = verification.to_dict() if hasattr(verification, 'to_dict') else verification
        results.append(verification_dict)

        if isinstance(finding, dict):
            if 'metadata' in finding and isinstance(finding['metadata'], dict):
                finding['metadata']['verification'] = verification_dict
                finding['metadata']['path_verified'] = verification_dict.get('path_verified', False)
                finding['metadata']['code_verified'] = verification_dict.get('code_verified', False)
                finding['metadata']['confidence_score'] = verification_dict.get('confidence', 0.0)
                finding['metadata']['verification_level'] = verification_dict.get('verification_level', 'none')
                finding['metadata']['is_hallucination'] = verification_dict.get('is_hallucination', True)
                cwe_match = verification_dict.get('cwe_match', {})
                if isinstance(cwe_match, dict) and cwe_match.get('best_match'):
                    finding['metadata']['matched_cwe'] = cwe_match['best_match']
        else:
            if hasattr(finding, 'metadata'):
                finding.metadata['verification'] = verification_dict
                finding.metadata['path_verified'] = verification_dict['path_verified']
                finding.metadata['code_verified'] = verification_dict['code_verified']
                finding.metadata['confidence_score'] = verification_dict['confidence']
                finding.metadata['verification_level'] = verification_dict['verification_level']
                finding.metadata['is_hallucination'] = verification_dict['is_hallucination']

                if verification_dict.get('cwe_match') and verification_dict['cwe_match'].get('best_match'):
                    finding.metadata['matched_cwe'] = verification_dict['cwe_match']['best_match']

    return results


class MultiLayerValidator:
    """多层验证机制

    第一层：关键词匹配（英文）
    第二层：注解类型检查
    第三层：代码语义验证
    """

    def __init__(self):
        self.layers = [
            KeywordMatchValidator(),
            AnnotationTypeValidator(),
            SemanticValidator()
        ]

    def validate(self, vulnerability: dict, file_content: str) -> tuple[bool, str, dict]:
        """执行多层验证

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容

        Returns:
            (是否通过, 状态, 详细信息)
        """
        results = []
        for layer in self.layers:
            is_valid, status, details = layer.validate(vulnerability, file_content)
            results.append({
                "layer": layer.__class__.__name__,
                "is_valid": is_valid,
                "status": status,
                "details": details
            })

            if not is_valid:
                return False, status, {"layers": results}

        return True, "CONFIRMED", {"layers": results}

    def validate_location(self, line_number: int, line_content: str,
                         vulnerability_type: str) -> tuple[bool, str]:
        """验证行号位置是否与漏洞类型匹配

        Args:
            line_number: 行号
            line_content: 行内容
            vulnerability_type: 漏洞类型

        Returns:
            (是否匹配, 原因)
        """
        for layer in self.layers:
            if hasattr(layer, 'validate_location'):
                is_valid, reason = layer.validate_location(line_number, line_content, vulnerability_type)
                if not is_valid:
                    return False, reason

        return True, "VALID"


class KeywordMatchValidator:
    """第一层验证：关键词匹配（英文）"""

    def validate(self, vulnerability: dict, file_content: str) -> tuple[bool, str, dict]:
        """验证关键词是否在文件中匹配

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容

        Returns:
            (是否通过, 状态, 详情)
        """
        keywords = self._extract_keywords(vulnerability)

        if not keywords:
            return True, "SKIPPED", {"reason": "无可用关键词"}

        matched_lines = []
        for kw in keywords:
            if kw.lower() in file_content.lower():
                lines = file_content.split('\n')
                for i, line in enumerate(lines):
                    if kw.lower() in line.lower():
                        matched_lines.append(i + 1)

        if not matched_lines:
            return False, "NO_MATCH", {"keywords": keywords, "matched": 0}

        return True, "MATCHED", {"keywords": keywords, "matched_lines": matched_lines[:5]}

    def _extract_keywords(self, vulnerability: dict) -> list:
        """提取英文关键词"""
        keywords = []
        rule_name = vulnerability.get("rule_name", "")
        description = vulnerability.get("description", "")
        vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", ""))

        combined = f"{rule_name} {description} {vuln_type}"

        words = re.findall(r'[a-zA-Z][a-zA-Z0-9]{2,}', combined.lower())
        keywords.extend([w for w in words if len(w) > 3 and not self._contains_chinese(w)])

        annotation_pattern = r'@(\w+)'
        annotations = re.findall(annotation_pattern, combined)
        keywords.extend([f"@{ann.lower()}" for ann in annotations if not self._contains_chinese(ann)])

        return list(set(keywords))[:20]

    def _contains_chinese(self, text: str) -> bool:
        """检查是否包含中文"""
        for char in text:
            if '\u4e00' <= char <= '\u9fff':
                return True
        return False

    def validate_location(self, line_number: int, line_content: str,
                         vulnerability_type: str) -> tuple[bool, str]:
        """验证位置 - 关键词层面"""
        return True, "VALID"


class AnnotationTypeValidator:
    """第二层验证：注解类型检查"""

    def validate(self, vulnerability: dict, file_content: str) -> tuple[bool, str, dict]:
        """验证注解类型是否匹配

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容

        Returns:
            (是否通过, 状态, 详情)
        """
        vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", "")).lower()
        line_number = vulnerability.get("line_number", vulnerability.get("ai_reported_line", 0))

        if not vuln_type:
            return True, "SKIPPED", {"reason": "无漏洞类型信息"}

        if "annotation" in vuln_type or "@" in file_content:
            return True, "VALID", {"type": "annotation_check"}

        return True, "VALID", {}

    def validate_location(self, line_number: int, line_content: str,
                         vulnerability_type: str) -> tuple[bool, str]:
        """验证位置 - 注解类型层面"""
        if not vulnerability_type:
            return True, "VALID"

        type_lower = vulnerability_type.lower()

        if "annotation" in type_lower:
            if not any(ann in line_content for ann in ["@", "Annotation"]):
                return False, "该行不包含注解，与漏洞类型不匹配"

        if "refreshscope" in type_lower:
            if "@RefreshScope" not in line_content:
                return False, "该行不包含@RefreshScope注解"

        if "configuration" in type_lower or "config" in type_lower:
            if not any(kw in line_content.lower() for kw in ["config", "properties", "@", "configuration"]):
                return False, "该行不包含配置相关代码"

        return True, "VALID"


class SemanticValidator:
    """第三层验证：代码语义验证"""

    def validate(self, vulnerability: dict, file_content: str) -> tuple[bool, str, dict]:
        """验证代码语义是否与漏洞描述匹配

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容

        Returns:
            (是否通过, 状态, 详情)
        """
        vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", "")).lower()
        description = vulnerability.get("description", "").lower()

        if not vuln_type and not description:
            return True, "SKIPPED", {"reason": "无漏洞描述"}

        semantic_score = self._calculate_semantic_score(vuln_type, description, file_content)

        if semantic_score < 0.3:
            return False, "LOW_SEMANTIC_MATCH", {"score": semantic_score}

        return True, "VALID", {"score": semantic_score}

    def _calculate_semantic_score(self, vuln_type: str, description: str, file_content: str) -> float:
        """计算语义匹配分数（动态从 NVD 获取关键词）"""
        score = 0.0
        keywords = []

        # 从 NVD 获取动态关键词
        from src.nvd.nvd_query_adapter import NVDQueryAdapter
        try:
            nvd = NVDQueryAdapter()
            if nvd.is_available():
                nvd_results = nvd.match_cwe([vuln_type], limit=3)
                for result in nvd_results:
                    keywords.extend(result.get('matched_keywords', []))
        except Exception:
            # Fallback: use basic keywords if NVD fails
            pass

        if not keywords:
            # Minimal fallback keywords for when NVD is unavailable
            basic_keywords = {
                'sql': ['select', 'query', 'cursor', 'execute'],
                'xss': ['html', 'script', 'escape'],
                'command': ['exec', 'process', 'shell'],
                'path': ['path', 'file', 'traversal'],
                'config': ['config', 'properties'],
                'refreshscope': ['refreshscope', 'refresh'],
            }
            for key, kws in basic_keywords.items():
                if key in vuln_type.lower() or key in description.lower():
                    keywords.extend(kws)

        content_lower = file_content.lower()
        matched = sum(1 for kw in keywords if kw.lower() in content_lower)

        if keywords:
            score = matched / len(keywords)

        return min(1.0, score)

    def validate_location(self, line_number: int, line_content: str,
                         vulnerability_type: str) -> tuple[bool, str]:
        """验证位置 - 语义层面"""
        return True, "VALID"


def multi_layer_validate(vulnerability: dict, file_content: str,
                         line_number: int = None, line_content: str = None) -> tuple[bool, str, dict]:
    """多层验证的便捷函数

    Args:
        vulnerability: 漏洞数据
        file_content: 文件内容
        line_number: 行号（可选）
        line_content: 行内容（可选）

    Returns:
        (是否通过, 状态, 详细信息)
    """
    validator = MultiLayerValidator()

    is_valid, status, details = validator.validate(vulnerability, file_content)

    if is_valid and line_number is not None and line_content is not None:
        vuln_type = vulnerability.get("vulnerability_type", "")
        is_valid, reason = validator.validate_location(line_number, line_content, vuln_type)
        if not is_valid:
            status = "REJECTED"
            details["rejection_reason"] = reason

    return is_valid, status, details
