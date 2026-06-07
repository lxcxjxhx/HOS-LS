"""ResultAggregator 单元测试"""

import pytest
from src.core.result_aggregator import (
    Severity,
    AggregatedFinding,
    AggregatedResult,
    ResultAggregator,
    convert_to_aggregated_finding,
)


@pytest.fixture
def aggregator():
    return ResultAggregator()


@pytest.fixture
def sample_finding():
    return AggregatedFinding(
        finding_id="test-001",
        rule_id="SQL_INJECTION",
        rule_name="SQL Injection Vulnerability",
        description="Potential SQL injection in query",
        severity=Severity.HIGH,
        file_path="src/api/user.py",
        line=42,
        column=5,
        confidence=0.85,
        message="SQL injection detected",
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
        fix_suggestion="Use parameterized queries",
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        tags=["injection", "database"],
        metadata={"cwe_id": "CWE-89"},
    )


@pytest.fixture
def sample_finding_2():
    return AggregatedFinding(
        finding_id="test-002",
        rule_id="XSS",
        rule_name="Cross-Site Scripting",
        description="Potential XSS vulnerability",
        severity=Severity.MEDIUM,
        file_path="src/views/template.html",
        line=15,
        column=10,
        confidence=0.75,
        message="XSS detected",
        code_snippet="innerHTML = userInput",
        fix_suggestion="Use textContent instead",
        references=["https://owasp.org/www-community/attacks/xss/"],
        tags=["xss", "frontend"],
        metadata={"cwe_id": "CWE-79"},
    )


@pytest.fixture
def sample_finding_3():
    return AggregatedFinding(
        finding_id="test-003",
        rule_id="COMMAND_INJECTION",
        rule_name="Command Injection",
        description="Potential command injection",
        severity=Severity.CRITICAL,
        file_path="src/utils/exec.py",
        line=28,
        column=1,
        confidence=0.9,
        message="Command injection detected",
        code_snippet="os.system(user_input)",
        fix_suggestion="Use subprocess with shell=False",
        references=["https://owasp.org/www-community/attacks/Command_Injection"],
        tags=["injection", "os"],
        metadata={"cwe_id": "CWE-78"},
    )


class TestSeverity:
    def test_from_str_critical(self):
        assert Severity.from_str("critical") == Severity.CRITICAL

    def test_from_str_high(self):
        assert Severity.from_str("HIGH") == Severity.HIGH

    def test_from_str_medium(self):
        assert Severity.from_str("medium") == Severity.MEDIUM

    def test_from_str_low(self):
        assert Severity.from_str("low") == Severity.LOW

    def test_from_str_info(self):
        assert Severity.from_str("INFO") == Severity.INFO

    def test_from_str_unknown(self):
        assert Severity.from_str("unknown") == Severity.MEDIUM

    def test_get_order_critical(self):
        assert Severity.CRITICAL.get_order() == 0

    def test_get_order_high(self):
        assert Severity.HIGH.get_order() == 1

    def test_get_order_medium(self):
        assert Severity.MEDIUM.get_order() == 2

    def test_get_order_low(self):
        assert Severity.LOW.get_order() == 3

    def test_get_order_info(self):
        assert Severity.INFO.get_order() == 4


class TestAggregatedFinding:
    def test_default_values(self):
        finding = AggregatedFinding()
        assert finding.finding_id == ""
        assert finding.rule_id == ""
        assert finding.severity == Severity.MEDIUM
        assert finding.line == 0
        assert finding.confidence == 0.0

    def test_get_deduplication_key(self, sample_finding):
        key = sample_finding.get_deduplication_key()
        assert key[0] == "SQL_INJECTION"
        assert key[1] == "src/api/user.py"
        assert key[2] == 42

    def test_normalize_rule_id_simple(self, sample_finding):
        normalized = sample_finding._normalize_rule_id()
        assert normalized == "SQL_INJECTION"

    def test_normalize_rule_id_with_suffix(self):
        finding = AggregatedFinding(rule_id="SQL_INJECTION_vulnerability")
        normalized = finding._normalize_rule_id()
        assert "SQL" in normalized

    def test_normalize_rule_id_windows_linux(self):
        finding = AggregatedFinding(rule_id="RULE_windows")
        normalized = finding._normalize_rule_id()
        assert normalized == "RULE"

    def test_normalize_rule_id_number_suffix(self):
        finding = AggregatedFinding(rule_id="SQL_INJECTION_1")
        normalized = finding._normalize_rule_id()
        assert normalized == "SQL_INJECTION"

    def test_normalize_rule_id_ssrf(self):
        finding = AggregatedFinding(rule_id="RemoteTokenServices_SSRF")
        normalized = finding._normalize_rule_id()
        assert normalized == "SSRF"

    def test_normalize_rule_id_empty(self):
        finding = AggregatedFinding(rule_id="")
        normalized = finding._normalize_rule_id()
        assert normalized == ""

    def test_normalize_rule_id_chinese(self):
        finding = AggregatedFinding(rule_id="SQL注入漏洞")
        normalized = finding._normalize_rule_id()
        assert "SQL" in normalized or normalized == "SQL_INJECTION"

    def test_normalize_rule_id_unauthorized(self):
        finding = AggregatedFinding(rule_id="未授权访问")
        normalized = finding._normalize_rule_id()
        assert "AUTH" in normalized or normalized == "UNAUTHORIZED_ACCESS"

    def test_normalize_line(self, sample_finding):
        normalized = sample_finding._normalize_line()
        assert normalized == 40

    def test_get_signal_key(self, sample_finding):
        key = sample_finding.get_signal_key()
        assert isinstance(key, tuple)
        assert len(key) == 3


class TestResultAggregatorInit:
    def test_init(self, aggregator):
        assert isinstance(aggregator.findings, list)
        assert len(aggregator.findings) == 0
        assert isinstance(aggregator._seen_keys, set)


class TestAddFinding:
    def test_add_first_finding(self, aggregator, sample_finding):
        result = aggregator.add_finding(sample_finding)
        assert result is True
        assert len(aggregator.findings) == 1

    def test_add_duplicate_finding(self, aggregator, sample_finding):
        aggregator.add_finding(sample_finding)
        result = aggregator.add_finding(sample_finding)
        assert result is False
        assert len(aggregator.findings) == 1

    def test_add_different_findings(self, aggregator, sample_finding, sample_finding_2):
        aggregator.add_finding(sample_finding)
        aggregator.add_finding(sample_finding_2)
        assert len(aggregator.findings) == 2


class TestAddFindings:
    def test_add_multiple_findings(self, aggregator, sample_finding, sample_finding_2, sample_finding_3):
        findings = [sample_finding, sample_finding_2, sample_finding_3]
        count = aggregator.add_findings(findings)
        assert count == 3
        assert len(aggregator.findings) == 3

    def test_add_empty_list(self, aggregator):
        count = aggregator.add_findings([])
        assert count == 0


class TestDeduplicate:
    def test_deduplicate_no_duplicates(self, aggregator, sample_finding, sample_finding_2):
        aggregator.findings = [sample_finding, sample_finding_2]
        aggregator._seen_keys = set()
        removed = aggregator.deduplicate()
        assert removed == 0
        assert len(aggregator.findings) == 2

    def test_deduplicate_with_duplicates(self, aggregator, sample_finding):
        aggregator.findings = [sample_finding, sample_finding]
        aggregator._seen_keys = set()
        removed = aggregator.deduplicate()
        assert removed == 1
        assert len(aggregator.findings) == 1

    def test_deduplicate_empty(self, aggregator):
        removed = aggregator.deduplicate()
        assert removed == 0


class TestSmartDeduplicate:
    def test_smart_deduplicate_empty(self, aggregator):
        result = aggregator.smart_deduplicate()
        assert result == []

    def test_smart_deduplicate_single(self, aggregator, sample_finding):
        aggregator.add_finding(sample_finding)
        result = aggregator.smart_deduplicate()
        assert len(result) == 1

    def test_smart_deduplicate_multiple(self, aggregator, sample_finding, sample_finding_2):
        aggregator.add_findings([sample_finding, sample_finding_2])
        result = aggregator.smart_deduplicate()
        assert len(result) <= 2


class TestSortBySeverity:
    def test_sort_descending(self, aggregator, sample_finding, sample_finding_2, sample_finding_3):
        aggregator.findings = [sample_finding_2, sample_finding, sample_finding_3]
        aggregator._seen_keys = set()
        aggregator.sort_by_severity(descending=False)
        assert aggregator.findings[0].severity == Severity.CRITICAL

    def test_sort_ascending(self, aggregator, sample_finding, sample_finding_2, sample_finding_3):
        aggregator.findings = [sample_finding_3, sample_finding, sample_finding_2]
        aggregator._seen_keys = set()
        aggregator.sort_by_severity(descending=True)
        assert aggregator.findings[-1].severity == Severity.CRITICAL


class TestSortByConfidence:
    def test_sort_descending(self, aggregator, sample_finding, sample_finding_2, sample_finding_3):
        aggregator.findings = [sample_finding_2, sample_finding, sample_finding_3]
        aggregator._seen_keys = set()
        aggregator.sort_by_confidence(descending=False)
        assert aggregator.findings[0].confidence >= aggregator.findings[-1].confidence


class TestSortByFile:
    def test_sort_by_file(self, aggregator, sample_finding, sample_finding_2, sample_finding_3):
        aggregator.add_findings([sample_finding_3, sample_finding, sample_finding_2])
        aggregator.sort_by_file()
        assert aggregator.findings[0].file_path <= aggregator.findings[-1].file_path


class TestFilterBySeverity:
    def test_filter_high_and_above(self, aggregator, sample_finding, sample_finding_2, sample_finding_3):
        aggregator.add_findings([sample_finding, sample_finding_2, sample_finding_3])
        filtered = aggregator.filter_by_severity(Severity.HIGH)
        assert len(filtered) >= 2
        assert all(f.severity.get_order() <= 1 for f in filtered)


class TestFilterByFile:
    def test_filter_by_file(self, aggregator, sample_finding, sample_finding_2):
        aggregator.add_findings([sample_finding, sample_finding_2])
        filtered = aggregator.filter_by_file("src/api/user.py")
        assert len(filtered) == 1
        assert filtered[0].file_path == "src/api/user.py"

    def test_filter_by_nonexistent_file(self, aggregator, sample_finding):
        aggregator.add_finding(sample_finding)
        filtered = aggregator.filter_by_file("nonexistent.py")
        assert len(filtered) == 0


class TestFilterByRule:
    def test_filter_by_rule(self, aggregator, sample_finding, sample_finding_2):
        aggregator.add_findings([sample_finding, sample_finding_2])
        filtered = aggregator.filter_by_rule("SQL_INJECTION")
        assert len(filtered) == 1

    def test_filter_by_nonexistent_rule(self, aggregator, sample_finding):
        aggregator.add_finding(sample_finding)
        filtered = aggregator.filter_by_rule("NONEXISTENT")
        assert len(filtered) == 0


class TestFilterByConfidence:
    def test_filter_by_confidence(self, aggregator, sample_finding, sample_finding_2):
        aggregator.add_findings([sample_finding, sample_finding_2])
        filtered = aggregator.filter_by_confidence(0.8)
        assert len(filtered) == 1
        assert filtered[0].confidence >= 0.8


class TestGetStatistics:
    def test_statistics_with_findings(self, aggregator, sample_finding, sample_finding_2, sample_finding_3):
        aggregator.add_findings([sample_finding, sample_finding_2, sample_finding_3])
        stats = aggregator.get_statistics()
        assert stats["total_findings"] == 3
        assert stats["avg_confidence"] > 0
        assert "severity_counts" in stats
        assert "rule_counts" in stats
        assert "file_counts" in stats

    def test_statistics_empty(self, aggregator):
        stats = aggregator.get_statistics()
        assert stats["total_findings"] == 0
        assert stats["avg_confidence"] == 0.0

    def test_statistics_without_verification(self, aggregator, sample_finding):
        aggregator.add_finding(sample_finding)
        stats = aggregator.get_statistics(include_verification=False)
        assert "verification_stats" not in stats


class TestAggregate:
    def test_aggregate_with_findings(self, aggregator, sample_finding, sample_finding_2):
        result = aggregator.aggregate(findings=[sample_finding, sample_finding_2])
        assert isinstance(result, AggregatedResult)
        assert result.summary["total_findings"] > 0

    def test_aggregate_empty(self, aggregator):
        result = aggregator.aggregate(findings=[])
        assert isinstance(result, AggregatedResult)

    def test_aggregate_with_dict_findings(self, aggregator):
        dict_finding = {
            "severity": "high",
            "file_path": "test.py",
            "line": 10,
            "rule_id": "TEST_RULE",
            "description": "Test description",
            "confidence": 0.8,
            "message": "Test message",
            "code_snippet": "test code",
            "fix_suggestion": "fix it",
        }
        result = aggregator.aggregate(findings=[dict_finding])
        assert isinstance(result, AggregatedResult)

    def test_aggregate_use_existing_findings(self, aggregator, sample_finding):
        aggregator.add_finding(sample_finding)
        result = aggregator.aggregate(findings=None)
        assert result.summary["total_findings"] == 1

    def test_aggregate_sort_by_confidence(self, aggregator, sample_finding, sample_finding_2, sample_finding_3):
        result = aggregator.aggregate(
            findings=[sample_finding, sample_finding_2, sample_finding_3],
            sort_by="confidence"
        )
        assert isinstance(result, AggregatedResult)

    def test_aggregate_sort_by_file(self, aggregator, sample_finding, sample_finding_2):
        result = aggregator.aggregate(
            findings=[sample_finding, sample_finding_2],
            sort_by="file"
        )
        assert isinstance(result, AggregatedResult)

    def test_aggregate_without_verification(self, aggregator, sample_finding):
        result = aggregator.aggregate(
            findings=[sample_finding],
            include_verification=False
        )
        assert "verification_stats" not in result.summary

    def test_aggregate_without_smart_dedup(self, aggregator, sample_finding):
        result = aggregator.aggregate(
            findings=[sample_finding],
            enable_smart_dedup=False
        )
        assert isinstance(result, AggregatedResult)

    def test_aggregate_without_semantic_merge(self, aggregator, sample_finding):
        result = aggregator.aggregate(
            findings=[sample_finding],
            enable_semantic_merge=False
        )
        assert isinstance(result, AggregatedResult)


class TestClear:
    def test_clear(self, aggregator, sample_finding):
        aggregator.add_finding(sample_finding)
        aggregator.clear()
        assert len(aggregator.findings) == 0
        assert len(aggregator._seen_keys) == 0


class TestConvertToAggregatedFinding:
    def test_convert_from_dict(self):
        data = {
            "severity": "high",
            "file_path": "test.py",
            "line": 10,
            "rule_id": "TEST_RULE",
            "description": "Test description",
            "confidence": 0.8,
            "message": "Test message",
            "code_snippet": "test code",
            "fix_suggestion": "fix it",
            "references": ["ref1"],
            "tags": ["tag1"],
            "metadata": {"key": "value"},
        }
        finding = convert_to_aggregated_finding(data)
        assert finding.severity == Severity.HIGH
        assert finding.file_path == "test.py"
        assert finding.line == 10
        assert finding.rule_id == "TEST_RULE"
        assert finding.confidence == 0.8

    def test_convert_default_values(self):
        data = {}
        finding = convert_to_aggregated_finding(data)
        assert finding.severity == Severity.MEDIUM
        assert finding.confidence == 0.5


class TestAggregatedResult:
    def test_to_dict(self, sample_finding):
        result = AggregatedResult(
            summary={"total_findings": 1},
            findings=[sample_finding],
            severity_counts={"high": 1},
            rule_counts={"SQL_INJECTION": 1},
            file_counts={"src/api/user.py": 1},
            metadata={"key": "value"},
            verification_stats={"verified": 1},
        )
        d = result.to_dict()
        assert "summary" in d
        assert "findings" in d
        assert "severity_counts" in d
        assert "rule_counts" in d
        assert "file_counts" in d
        assert "metadata" in d
        assert "verification_stats" in d


class TestSimilarityMethods:
    def test_levenshtein_distance_same(self):
        dist = ResultAggregator._levenshtein_distance("hello", "hello")
        assert dist == 0

    def test_levenshtein_distance_different(self):
        dist = ResultAggregator._levenshtein_distance("kitten", "sitting")
        assert dist > 0

    def test_levenshtein_distance_empty(self):
        dist = ResultAggregator._levenshtein_distance("", "hello")
        assert dist == 5

    def test_string_similarity_same(self):
        sim = ResultAggregator._string_similarity("hello", "hello")
        assert sim == 1.0

    def test_string_similarity_empty(self):
        sim = ResultAggregator._string_similarity("", "")
        assert sim == 1.0

    def test_string_similarity_one_empty(self):
        sim = ResultAggregator._string_similarity("hello", "")
        assert sim == 0.0

    def test_token_overlap_same(self):
        sim = ResultAggregator._token_overlap_similarity("hello world", "world hello")
        assert sim == 1.0

    def test_token_overlap_different(self):
        sim = ResultAggregator._token_overlap_similarity("hello world", "foo bar")
        assert sim == 0.0

    def test_code_pattern_similarity_same(self):
        sim = ResultAggregator._code_pattern_similarity("x = 1", "x = 1")
        assert sim == 1.0

    def test_code_pattern_similarity_different_ids(self):
        sim = ResultAggregator._code_pattern_similarity("x = 1", "y = 1")
        assert sim > 0.5

    def test_calculate_finding_similarity_same(self, sample_finding):
        aggregator = ResultAggregator()
        sim = aggregator._calculate_finding_similarity(sample_finding, sample_finding)
        assert sim == 1.0


class TestMergeMethods:
    def test_merge_title_single(self, sample_finding):
        title = ResultAggregator._merge_title([sample_finding])
        assert "SQL" in title or title == sample_finding.rule_name

    def test_merge_title_multiple(self, sample_finding, sample_finding_2):
        title = ResultAggregator._merge_title([sample_finding, sample_finding_2])
        assert "2 locations" in title or "2" in title

    def test_merge_description_single(self, sample_finding):
        desc = ResultAggregator._merge_description([sample_finding])
        assert "SQL" in desc or "injection" in desc.lower()

    def test_merge_description_multiple(self, sample_finding, sample_finding_2):
        desc = ResultAggregator._merge_description([sample_finding, sample_finding_2])
        assert "2" in desc or "位置" in desc

    def test_merge_code_snippet_single(self, sample_finding):
        snippet = ResultAggregator._merge_code_snippet([sample_finding])
        assert snippet == sample_finding.code_snippet

    def test_merge_code_snippet_multiple(self, sample_finding, sample_finding_2):
        snippet = ResultAggregator._merge_code_snippet([sample_finding, sample_finding_2])
        assert "示例来自" in snippet or sample_finding.code_snippet in snippet

    def test_merge_severity(self, sample_finding, sample_finding_2, sample_finding_3):
        severity = ResultAggregator._merge_severity([sample_finding_2, sample_finding, sample_finding_3])
        assert severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]

    def test_merge_confidence(self, sample_finding, sample_finding_2):
        conf = ResultAggregator._merge_confidence([sample_finding, sample_finding_2])
        assert conf == (0.85 + 0.75) / 2

    def test_merge_fix_suggestion_single(self, sample_finding):
        fix = ResultAggregator._merge_fix_suggestion([sample_finding])
        assert fix == sample_finding.fix_suggestion

    def test_merge_fix_suggestion_multiple(self, sample_finding, sample_finding_2):
        fix = ResultAggregator._merge_fix_suggestion([sample_finding, sample_finding_2])
        assert len(fix) > 0

    def test_merge_fix_suggestion_empty(self):
        f1 = AggregatedFinding(fix_suggestion="")
        f2 = AggregatedFinding(fix_suggestion="")
        fix = ResultAggregator._merge_fix_suggestion([f1, f2])
        assert "审查" in fix or "fix" in fix.lower() or len(fix) > 0

    def test_merge_references(self, sample_finding, sample_finding_2):
        refs = ResultAggregator._merge_references([sample_finding, sample_finding_2])
        assert len(refs) == 2

    def test_merge_references_duplicate(self, sample_finding):
        refs = ResultAggregator._merge_references([sample_finding, sample_finding])
        assert len(refs) == 1

    def test_merge_tags(self, sample_finding, sample_finding_2):
        tags = ResultAggregator._merge_tags([sample_finding, sample_finding_2])
        assert "injection" in tags
        assert "xss" in tags


class TestMergeSimilarFindings:
    def test_merge_no_duplicates(self, aggregator, sample_finding, sample_finding_2):
        aggregator.findings = [sample_finding, sample_finding_2]
        merged = aggregator._merge_similar_findings()
        assert len(merged) <= 2

    def test_merge_empty(self, aggregator):
        merged = aggregator._merge_similar_findings()
        assert len(merged) == 0


class TestGetSignalKey:
    def test_get_signal_key(self, aggregator, sample_finding):
        key = aggregator._get_signal_key(sample_finding)
        assert isinstance(key, str)
        assert "src/api/user.py" in key


class TestSelectBestFinding:
    def test_select_best_by_severity(self, aggregator, sample_finding, sample_finding_3):
        best = aggregator._select_best_finding([sample_finding, sample_finding_3])
        assert best.severity == Severity.CRITICAL

    def test_select_best_single(self, aggregator, sample_finding):
        best = aggregator._select_best_finding([sample_finding])
        assert best == sample_finding


class TestSelectBestFindingWithStrings:
    def test_select_best_string_severity(self, aggregator):
        f1 = AggregatedFinding()
        f1.severity = "high"
        f2 = AggregatedFinding()
        f2.severity = "low"
        best = aggregator._select_best_finding([f1, f2])
        assert best.severity == "high"
