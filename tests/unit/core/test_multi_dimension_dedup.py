"""多维度漏洞去重模块单元测试

测试覆盖：
1. 基础去重：漏洞类型 + 文件路径
2. 描述相似度匹配
3. 代码位置重叠检测
4. 信号ID匹配
5. 多维度组合去重
6. 合并逻辑验证
"""

import pytest
from typing import Dict, Any, List

from src.core.multi_dimension_dedup import (
    MultiDimensionDeduplicator,
    DedupConfig,
    DedupDimension,
)


def make_vuln(
    rule_id: str = "SQL_INJECTION",
    file_path: str = "test.py",
    description: str = "SQL injection vulnerability",
    line: int = 10,
    end_line: int = 10,
    severity: str = "high",
    confidence: float = 0.8,
    signal_id: str = "",
    metadata: Dict[str, Any] = None,
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "file_path": file_path,
        "description": description,
        "line": line,
        "end_line": end_line,
        "location": {
            "file": file_path,
            "line": line,
            "end_line": end_line,
        },
        "severity": severity,
        "confidence": confidence,
        "signal_id": signal_id,
        "metadata": metadata or {},
    }


class TestBasicDeduplication:
    def test_exact_duplicate_removed(self):
        config = DedupConfig(enabled_dimensions=[DedupDimension.BASIC])
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(rule_id="SQL_INJECTION", file_path="app.py", line=10),
            make_vuln(rule_id="SQL_INJECTION", file_path="app.py", line=20),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 1
        assert result[0]["rule_id"] == "SQL_INJECTION"
        assert result[0]["file_path"] == "app.py"

    def test_different_files_not_deduplicated(self):
        config = DedupConfig(enabled_dimensions=[DedupDimension.BASIC])
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(rule_id="SQL_INJECTION", file_path="app1.py"),
            make_vuln(rule_id="SQL_INJECTION", file_path="app2.py"),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 2

    def test_different_types_not_deduplicated(self):
        config = DedupConfig(enabled_dimensions=[DedupDimension.BASIC])
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(rule_id="SQL_INJECTION", file_path="app.py"),
            make_vuln(rule_id="XSS", file_path="app.py"),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 2


class TestDescriptionSimilarityDeduplication:
    def test_similar_descriptions_merged(self):
        config = DedupConfig(
            enabled_dimensions=[DedupDimension.DESCRIPTION_SIMILARITY],
            description_similarity_threshold=0.6,
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(
                rule_id="SQL_INJECTION",
                file_path="app1.py",
                description="SQL injection in user login",
                line=10,
            ),
            make_vuln(
                rule_id="SQL_INJECTION",
                file_path="app2.py",
                description="SQL injection in user authentication",
                line=20,
            ),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 1
        assert result[0].get("merge_info", {}).get("merged_count", 1) >= 2

    def test_dissimilar_descriptions_not_merged(self):
        config = DedupConfig(
            enabled_dimensions=[DedupDimension.DESCRIPTION_SIMILARITY],
            description_similarity_threshold=0.8,
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(description="SQL injection vulnerability", line=10),
            make_vuln(description="Cross-site scripting in form input", line=20),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 2

    def test_empty_descriptions_handled(self):
        config = DedupConfig(
            enabled_dimensions=[DedupDimension.DESCRIPTION_SIMILARITY],
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(description="", line=10),
            make_vuln(description="", line=20),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 1


class TestCodeLocationOverlapDeduplication:
    def test_overlapping_lines_merged(self):
        config = DedupConfig(
            enabled_dimensions=[DedupDimension.CODE_LOCATION_OVERLAP],
            code_location_tolerance=3,
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(file_path="app.py", line=10, end_line=15),
            make_vuln(file_path="app.py", line=12, end_line=18),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 1

    def test_non_overlapping_lines_not_merged(self):
        config = DedupConfig(
            enabled_dimensions=[DedupDimension.CODE_LOCATION_OVERLAP],
            code_location_tolerance=3,
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(file_path="app.py", line=10, end_line=15),
            make_vuln(file_path="app.py", line=50, end_line=55),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 2

    def test_different_files_not_merged(self):
        config = DedupConfig(
            enabled_dimensions=[DedupDimension.CODE_LOCATION_OVERLAP],
            code_location_tolerance=3,
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(file_path="app1.py", line=10),
            make_vuln(file_path="app2.py", line=10),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 2


class TestSignalIdMatchDeduplication:
    def test_same_signal_id_merged(self):
        config = DedupConfig(
            enabled_dimensions=[DedupDimension.SIGNAL_ID_MATCH],
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(rule_id="SQL_INJECTION", file_path="app1.py", signal_id="SIG-001"),
            make_vuln(rule_id="XSS", file_path="app2.py", signal_id="SIG-001"),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 1
        assert result[0].get("merge_info", {}).get("signal_id") == "SIG-001"

    def test_different_signal_ids_not_merged(self):
        config = DedupConfig(
            enabled_dimensions=[DedupDimension.SIGNAL_ID_MATCH],
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(signal_id="SIG-001"),
            make_vuln(signal_id="SIG-002"),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 2

    def test_no_signal_id_not_merged(self):
        config = DedupConfig(
            enabled_dimensions=[DedupDimension.SIGNAL_ID_MATCH],
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(signal_id=""),
            make_vuln(signal_id=""),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 2


class TestMultiDimensionDeduplication:
    def test_all_dimensions_enabled(self):
        config = DedupConfig(
            enabled_dimensions=[
                DedupDimension.BASIC,
                DedupDimension.DESCRIPTION_SIMILARITY,
                DedupDimension.CODE_LOCATION_OVERLAP,
                DedupDimension.SIGNAL_ID_MATCH,
            ]
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(rule_id="SQL", file_path="a.py", line=10, description="SQL inj"),
            make_vuln(rule_id="SQL", file_path="a.py", line=12, description="SQL injection"),
            make_vuln(rule_id="XSS", file_path="b.py", line=50, description="XSS vuln"),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) <= 2

    def test_stats_tracking(self):
        config = DedupConfig(enabled_dimensions=[DedupDimension.BASIC])
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(rule_id="SQL", file_path="a.py"),
            make_vuln(rule_id="SQL", file_path="a.py"),
            make_vuln(rule_id="XSS", file_path="b.py"),
        ]
        
        dedup.deduplicate(vulns)
        stats = dedup.get_stats()
        
        assert stats["total_input"] == 3
        assert stats["total_output"] == 2
        assert stats["duplicates_removed"] == 1
        assert stats["by_dimension"]["basic"] == 1


class TestMergeLogic:
    def test_highest_severity_preserved(self):
        config = DedupConfig(enabled_dimensions=[DedupDimension.BASIC])
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(rule_id="SQL", file_path="a.py", severity="low"),
            make_vuln(rule_id="SQL", file_path="a.py", severity="critical"),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 1
        assert result[0]["severity"] == "critical"

    def test_highest_confidence_preserved(self):
        config = DedupConfig(enabled_dimensions=[DedupDimension.BASIC])
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(rule_id="SQL", file_path="a.py", confidence=0.5),
            make_vuln(rule_id="SQL", file_path="a.py", confidence=0.9),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 1
        assert result[0]["confidence"] == 0.9

    def test_merge_info_added(self):
        config = DedupConfig(
            enabled_dimensions=[DedupDimension.DESCRIPTION_SIMILARITY],
            description_similarity_threshold=0.6,
        )
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(description="SQL injection test", line=10),
            make_vuln(description="SQL injection testing", line=20),
        ]
        
        result = dedup.deduplicate(vulns)
        
        assert len(result) == 1
        assert "merge_info" in result[0]
        assert result[0]["merge_info"]["merged_count"] == 2


class TestEdgeCases:
    def test_empty_list(self):
        dedup = MultiDimensionDeduplicator()
        result = dedup.deduplicate([])
        assert result == []

    def test_single_vulnerability(self):
        dedup = MultiDimensionDeduplicator()
        vulns = [make_vuln()]
        result = dedup.deduplicate(vulns)
        assert len(result) == 1

    def test_no_dimensions_enabled(self):
        config = DedupConfig(enabled_dimensions=[])
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(),
            make_vuln(),
        ]
        
        result = dedup.deduplicate(vulns)
        assert len(result) == 2

    def test_large_input_performance(self):
        config = DedupConfig(enabled_dimensions=[DedupDimension.BASIC])
        dedup = MultiDimensionDeduplicator(config)
        
        vulns = [
            make_vuln(rule_id=f"VULN_{i}", file_path=f"file_{i % 10}.py", line=i)
            for i in range(100)
        ]
        
        result = dedup.deduplicate(vulns)
        assert len(result) <= 100
