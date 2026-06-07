"""多维度漏洞去重引擎

提供基于四个维度的去重算法：
1. 基础去重：漏洞类型 + 文件路径完全相同
2. 描述相似度匹配：使用模糊字符串匹配（Levenshtein 距离），相似度 > 80% 视为重复
3. 代码位置重叠检测：如果两个漏洞的代码行范围有重叠，视为重复
4. 时间戳和信号ID匹配：相同信号ID的漏洞合并

支持任意组合使用这些维度，提供灵活的配置选项。
"""

from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class DedupDimension(Enum):
    """去重维度"""
    BASIC = "basic"  # 漏洞类型 + 文件路径
    DESCRIPTION_SIMILARITY = "description_similarity"  # 描述相似度
    CODE_LOCATION_OVERLAP = "code_location_overlap"  # 代码位置重叠
    SIGNAL_ID_MATCH = "signal_id_match"  # 信号ID匹配


@dataclass
class DedupConfig:
    """去重配置"""
    enabled_dimensions: List[DedupDimension] = field(default_factory=lambda: [
        DedupDimension.BASIC,
        DedupDimension.DESCRIPTION_SIMILARITY,
        DedupDimension.CODE_LOCATION_OVERLAP,
        DedupDimension.SIGNAL_ID_MATCH,
    ])
    description_similarity_threshold: float = 0.8  # 描述相似度阈值
    code_location_tolerance: int = 3  # 代码行容差
    use_semantic_merge: bool = True  # 是否启用语义合并
    log_details: bool = True  # 是否记录详细日志


class MultiDimensionDeduplicator:
    """多维度漏洞去重器"""

    def __init__(self, config: Optional[DedupConfig] = None):
        self.config = config or DedupConfig()
        self.stats = {
            'total_input': 0,
            'total_output': 0,
            'duplicates_removed': 0,
            'by_dimension': {dim.value: 0 for dim in DedupDimension},
            'merged_groups': 0,
        }

    def deduplicate(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """执行多维度去重

        Args:
            vulnerabilities: 漏洞列表（字典格式）

        Returns:
            去重后的漏洞列表
        """
        if not vulnerabilities:
            return []

        self.stats['total_input'] = len(vulnerabilities)
        
        remaining = list(vulnerabilities)
        
        for dimension in self.config.enabled_dimensions:
            if len(remaining) <= 1:
                break
            
            before_count = len(remaining)
            remaining = self._apply_dimension(remaining, dimension)
            removed = before_count - len(remaining)
            
            if removed > 0:
                self.stats['by_dimension'][dimension.value] = removed
                if self.config.log_details:
                    logger.info(f"[去重] {dimension.value} 维度移除 {removed} 个重复漏洞")
        
        self.stats['total_output'] = len(remaining)
        self.stats['duplicates_removed'] = self.stats['total_input'] - self.stats['total_output']
        
        return remaining

    def _apply_dimension(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        dimension: DedupDimension
    ) -> List[Dict[str, Any]]:
        """应用指定维度的去重

        Args:
            vulnerabilities: 漏洞列表
            dimension: 去重维度

        Returns:
            去重后的漏洞列表
        """
        if dimension == DedupDimension.BASIC:
            return self._deduplicate_basic(vulnerabilities)
        elif dimension == DedupDimension.DESCRIPTION_SIMILARITY:
            return self._deduplicate_description_similarity(vulnerabilities)
        elif dimension == DedupDimension.CODE_LOCATION_OVERLAP:
            return self._deduplicate_code_location_overlap(vulnerabilities)
        elif dimension == DedupDimension.SIGNAL_ID_MATCH:
            return self._deduplicate_signal_id(vulnerabilities)
        else:
            return vulnerabilities

    def _deduplicate_basic(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """基础去重：漏洞类型 + 文件路径完全相同

        Args:
            vulnerabilities: 漏洞列表

        Returns:
            去重后的漏洞列表
        """
        groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        
        for vuln in vulnerabilities:
            vuln_type = self._get_vuln_type(vuln)
            file_path = self._get_file_path(vuln)
            
            dedup_key = (str(vuln_type), str(file_path))
            
            if dedup_key not in groups:
                groups[dedup_key] = []
            groups[dedup_key].append(vuln)
        
        deduplicated: List[Dict[str, Any]] = []
        for dedup_key, group in groups.items():
            if len(group) > 1:
                merged = self._merge_vulnerabilities(group)
                merged['merge_info'] = {
                    'merged_count': len(group),
                    'merge_dimension': 'basic',
                }
                deduplicated.append(merged)
                self.stats['merged_groups'] += 1
            else:
                deduplicated.append(group[0])
        
        return deduplicated

    def _deduplicate_description_similarity(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """描述相似度去重

        使用 Levenshtein 距离计算描述相似度，相似度超过阈值视为重复。

        Args:
            vulnerabilities: 漏洞列表

        Returns:
            去重后的漏洞列表
        """
        if len(vulnerabilities) <= 1:
            return vulnerabilities
        
        used_indices: Set[int] = set()
        deduplicated: List[Dict[str, Any]] = []
        
        for i, vuln_i in enumerate(vulnerabilities):
            if i in used_indices:
                continue
            
            group = [vuln_i]
            used_indices.add(i)
            
            desc_i = self._get_description(vuln_i)
            
            for j in range(i + 1, len(vulnerabilities)):
                if j in used_indices:
                    continue
                
                vuln_j = vulnerabilities[j]
                desc_j = self._get_description(vuln_j)
                
                if self._descriptions_similar(desc_i, desc_j):
                    group.append(vuln_j)
                    used_indices.add(j)
            
            if len(group) > 1:
                merged = self._merge_vulnerabilities(group)
                merged['merge_info'] = {
                    'merged_count': len(group),
                    'merge_dimension': 'description_similarity',
                    'original_indices': list(used_indices.intersection(set(range(i, i + len(group))))),
                }
                deduplicated.append(merged)
                self.stats['merged_groups'] += 1
            else:
                deduplicated.append(vuln_i)
        
        return deduplicated

    def _deduplicate_code_location_overlap(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """代码位置重叠去重

        如果两个漏洞的代码行范围有重叠（考虑容差），视为重复。

        Args:
            vulnerabilities: 漏洞列表

        Returns:
            去重后的漏洞列表
        """
        if len(vulnerabilities) <= 1:
            return vulnerabilities
        
        used_indices: Set[int] = set()
        deduplicated: List[Dict[str, Any]] = []
        tolerance = self.config.code_location_tolerance
        
        for i, vuln_i in enumerate(vulnerabilities):
            if i in used_indices:
                continue
            
            group = [vuln_i]
            used_indices.add(i)
            
            file_i = self._get_file_path(vuln_i)
            line_range_i = self._get_line_range(vuln_i)
            
            for j in range(i + 1, len(vulnerabilities)):
                if j in used_indices:
                    continue
                
                vuln_j = vulnerabilities[j]
                file_j = self._get_file_path(vuln_j)
                line_range_j = self._get_line_range(vuln_j)
                
                if (file_i == file_j and 
                    self._line_ranges_overlap(line_range_i, line_range_j, tolerance)):
                    group.append(vuln_j)
                    used_indices.add(j)
            
            if len(group) > 1:
                merged = self._merge_vulnerabilities(group)
                merged['merge_info'] = {
                    'merged_count': len(group),
                    'merge_dimension': 'code_location_overlap',
                    'line_range': line_range_i,
                }
                deduplicated.append(merged)
                self.stats['merged_groups'] += 1
            else:
                deduplicated.append(vuln_i)
        
        return deduplicated

    def _deduplicate_signal_id(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """信号ID匹配去重

        相同信号ID的漏洞合并。

        Args:
            vulnerabilities: 漏洞列表

        Returns:
            去重后的漏洞列表
        """
        signal_groups: Dict[str, List[Dict[str, Any]]] = {}
        no_signal: List[Dict[str, Any]] = []
        
        for vuln in vulnerabilities:
            signal_id = self._get_signal_id(vuln)
            
            if signal_id:
                if signal_id not in signal_groups:
                    signal_groups[signal_id] = []
                signal_groups[signal_id].append(vuln)
            else:
                no_signal.append(vuln)
        
        deduplicated: List[Dict[str, Any]] = list(no_signal)
        
        for signal_id, group in signal_groups.items():
            if len(group) > 1:
                merged = self._merge_vulnerabilities(group)
                merged['merge_info'] = {
                    'merged_count': len(group),
                    'merge_dimension': 'signal_id_match',
                    'signal_id': signal_id,
                }
                deduplicated.append(merged)
                self.stats['merged_groups'] += 1
                self.stats['by_dimension']['signal_id_match'] += len(group) - 1
            else:
                deduplicated.append(group[0])
        
        return deduplicated

    def _get_vuln_type(self, vuln: Dict[str, Any]) -> str:
        """获取漏洞类型"""
        return (
            vuln.get('rule_id', '') or 
            vuln.get('vulnerability', '') or 
            vuln.get('type', '') or 
            vuln.get('cwe', '') or
            ''
        )

    def _get_file_path(self, vuln: Dict[str, Any]) -> str:
        """获取文件路径"""
        file_path = vuln.get('file_path', '')
        if not file_path:
            location = vuln.get('location', {})
            if isinstance(location, dict):
                file_path = location.get('file', '')
            elif isinstance(location, str):
                parts = location.rsplit(':', 1)
                file_path = parts[0] if parts else ''
        return str(file_path)

    def _get_description(self, vuln: Dict[str, Any]) -> str:
        """获取漏洞描述"""
        return str(
            vuln.get('description', '') or 
            vuln.get('message', '') or 
            vuln.get('detail', '') or 
            ''
        )

    def _get_line_range(self, vuln: Dict[str, Any]) -> Tuple[int, int]:
        """获取代码行范围"""
        location = vuln.get('location', {})
        
        if isinstance(location, dict):
            start_line = location.get('line', 0) or location.get('start_line', 0) or 0
            end_line = location.get('end_line', 0) or start_line
        elif isinstance(location, str) and ':' in location:
            parts = location.rsplit(':', 1)
            line_part = parts[1] if len(parts) > 1 else '0'
            if '-' in line_part:
                start_end = line_part.split('-', 1)
                start_line = int(start_end[0]) if start_end[0].isdigit() else 0
                end_line = int(start_end[1]) if len(start_end) > 1 and start_end[1].isdigit() else start_line
            else:
                start_line = int(line_part) if line_part.isdigit() else 0
                end_line = start_line
        else:
            start_line = vuln.get('line', 0) or 0
            end_line = vuln.get('end_line', 0) or start_line
        
        if end_line < start_line:
            end_line = start_line
        
        return (start_line, end_line)

    def _get_signal_id(self, vuln: Dict[str, Any]) -> str:
        """获取信号ID"""
        metadata = vuln.get('metadata', {}) or {}
        return (
            metadata.get('signal_id', '') or
            vuln.get('signal_id', '') or
            metadata.get('signal_key', '') or
            ''
        )

    def _descriptions_similar(self, desc1: str, desc2: str) -> bool:
        """判断两个描述是否相似

        Args:
            desc1: 描述1
            desc2: 描述2

        Returns:
            是否相似
        """
        if not desc1 and not desc2:
            return True
        if not desc1 or not desc2:
            return False
        
        similarity = self._calculate_similarity(desc1, desc2)
        return similarity >= self.config.description_similarity_threshold

    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """计算字符串相似度

        综合使用 Levenshtein 距离和 token 重叠度。

        Args:
            s1: 字符串1
            s2: 字符串2

        Returns:
            相似度 (0-1)
        """
        lev_sim = self._levenshtein_similarity(s1, s2)
        token_sim = self._token_overlap_similarity(s1, s2)
        
        return max(lev_sim, token_sim)

    @staticmethod
    def _levenshtein_similarity(s1: str, s2: str) -> float:
        """基于 Levenshtein 距离的相似度"""
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0
        
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        
        distance = MultiDimensionDeduplicator._levenshtein_distance(s1, s2)
        return 1.0 - (distance / max_len)

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """计算 Levenshtein 距离"""
        if len(s1) < len(s2):
            return MultiDimensionDeduplicator._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        
        return prev_row[-1]

    @staticmethod
    def _token_overlap_similarity(s1: str, s2: str) -> float:
        """基于 token 重叠的相似度 (Jaccard 相似度)"""
        tokens1 = set(s1.lower().split())
        tokens2 = set(s2.lower().split())
        
        if not tokens1 and not tokens2:
            return 1.0
        if not tokens1 or not tokens2:
            return 0.0
        
        intersection = tokens1 & tokens2
        union = tokens1 | tokens2
        
        return len(intersection) / len(union) if union else 0.0

    def _line_ranges_overlap(
        self, range1: Tuple[int, int], range2: Tuple[int, int], tolerance: int = 3
    ) -> bool:
        """判断两个行范围是否重叠

        Args:
            range1: 行范围1 (start, end)
            range2: 行范围2 (start, end)
            tolerance: 容差（行）

        Returns:
            是否重叠
        """
        start1, end1 = range1
        start2, end2 = range2
        
        return (start1 - tolerance) <= end2 and (start2 - tolerance) <= end1

    def _merge_vulnerabilities(self, group: List[Dict[str, Any]]) -> Dict[str, Any]:
        """合并一组漏洞

        保留最高严重级别、最高置信度，合并证据和标签。

        Args:
            group: 漏洞组

        Returns:
            合并后的漏洞
        """
        if len(group) == 1:
            return group[0]
        
        merged = group[0].copy()
        
        severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        
        best_severity = group[0]
        best_severity_val = severity_rank.get(
            str(best_severity.get('severity', 'info')).lower().split('.')[-1], 5
        )
        
        max_confidence = float(group[0].get('confidence', 0) or 0)
        
        all_evidence = list(group[0].get('evidence', []) or [])
        all_tags = set(group[0].get('tags', []) or [])
        all_files = {self._get_file_path(group[0])}
        
        for vuln in group[1:]:
            sev_val = severity_rank.get(
                str(vuln.get('severity', 'info')).lower().split('.')[-1], 5
            )
            if sev_val < best_severity_val:
                best_severity = vuln
                best_severity_val = sev_val
            
            conf = float(vuln.get('confidence', 0) or 0)
            if conf > max_confidence:
                max_confidence = conf
            
            evidence = vuln.get('evidence', []) or []
            for ev in evidence:
                if ev not in all_evidence:
                    all_evidence.append(ev)
            
            tags = vuln.get('tags', []) or []
            all_tags.update(tags)
            
            all_files.add(self._get_file_path(vuln))
        
        merged['severity'] = best_severity.get('severity', 'info')
        merged['confidence'] = max_confidence
        merged['evidence'] = all_evidence
        merged['tags'] = list(all_tags)
        merged['affected_files'] = list(all_files)
        merged['merge_count'] = len(group)
        
        return merged

    def get_stats(self) -> Dict[str, Any]:
        """获取去重统计信息

        Returns:
            统计信息字典
        """
        return self.stats.copy()
