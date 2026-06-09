"""Utils translation module tests"""

import pytest

from src.utils.translation import (
    translate_severity, translate_verdict,
    translate_vulnerability_title, translate_recommendation,
    format_finding_cn,
    SEVERITY_MAP, VERDICT_MAP, VULNERABILITY_TITLE_MAP,
    RECOMMENDATION_MAP, STATUS_MAP,
)


class TestTranslateSeverity:
    def test_translate_critical(self):
        assert translate_severity("critical") == "严重"
        assert translate_severity("CRITICAL") == "严重"

    def test_translate_high(self):
        assert translate_severity("high") == "高危"
        assert translate_severity("HIGH") == "高危"

    def test_translate_medium(self):
        assert translate_severity("medium") == "中危"
        assert translate_severity("MEDIUM") == "中危"

    def test_translate_low(self):
        assert translate_severity("low") == "低危"
        assert translate_severity("LOW") == "低危"

    def test_translate_info(self):
        assert translate_severity("info") == "信息"
        assert translate_severity("INFO") == "信息"

    def test_translate_unknown(self):
        assert translate_severity("unknown") == "unknown"


class TestTranslateVerdict:
    def test_translate_confirmed(self):
        assert translate_verdict("confirmed") == "确认漏洞"
        assert translate_verdict("valid") == "确认漏洞"

    def test_translate_refuted(self):
        assert translate_verdict("refuted") == "误报"
        assert translate_verdict("invalid") == "误报"

    def test_translate_needs_review(self):
        assert translate_verdict("needs_review") == "需人工复核"
        assert translate_verdict("uncertain") == "需人工复核"

    def test_translate_accept_refute(self):
        assert translate_verdict("ACCEPT") == "确认"
        assert translate_verdict("REFUTE") == "误报"
        assert translate_verdict("ESCALATE") == "需人工复核"

    def test_translate_unknown(self):
        assert translate_verdict("unknown") == "unknown"


class TestTranslateVulnerabilityTitle:
    def test_translate_sql_injection(self):
        assert translate_vulnerability_title("SQL Injection") == "SQL 注入"
        assert translate_vulnerability_title("sql injection") == "SQL 注入"
        assert translate_vulnerability_title("SQL_INJECTION") == "SQL 注入"

    def test_translate_xss(self):
        assert translate_vulnerability_title("XSS") == "XSS 跨站脚本"

    def test_translate_csrf(self):
        assert translate_vulnerability_title("CSRF") == "CSRF 跨站请求伪造"

    def test_translate_command_injection(self):
        assert translate_vulnerability_title("Command Injection") == "命令注入"

    def test_translate_unknown(self):
        assert translate_vulnerability_title("Unknown Vuln") == "Unknown Vuln"


class TestTranslateRecommendation:
    def test_translate_parameterized(self):
        assert translate_recommendation("Use parameterized queries") == "使用参数化查询"

    def test_translate_csrf_token(self):
        assert translate_recommendation("Use CSRF token") == "使用 CSRF Token"

    def test_translate_https(self):
        assert translate_recommendation("Use HTTPS") == "使用 HTTPS"

    def test_translate_unknown(self):
        assert translate_recommendation("Unknown recommendation") == "Unknown recommendation"


class TestFormatFindingCn:
    def test_format_with_all_fields(self):
        vuln = {
            "severity": "high",
            "vulnerability": "SQL Injection",
            "status": "confirmed",
            "verdict": "valid",
            "recommendation": "Use parameterized queries",
        }
        formatted = format_finding_cn(vuln, lang="zh")
        assert formatted["severity_cn"] == "高危"
        assert formatted["vulnerability_cn"] == "SQL 注入"
        assert formatted["status_cn"] == "确认漏洞"
        assert formatted["verdict_cn"] == "确认漏洞"
        assert formatted["recommendation_cn"] == "使用参数化查询"

    def test_format_with_list_recommendation(self):
        vuln = {
            "severity": "high",
            "recommendation": ["Use parameterized queries", "Use input validation"],
        }
        formatted = format_finding_cn(vuln, lang="zh")
        assert formatted["recommendation_cn"] == ["使用参数化查询", "进行输入校验"]

    def test_format_english_lang(self):
        vuln = {
            "severity": "high",
            "vulnerability": "SQL Injection",
        }
        formatted = format_finding_cn(vuln, lang="en")
        assert "severity_cn" not in formatted
        assert "vulnerability_cn" not in formatted

    def test_format_missing_fields(self):
        vuln = {}
        formatted = format_finding_cn(vuln, lang="zh")
        assert "severity_cn" not in formatted

    def test_format_partial_fields(self):
        vuln = {
            "severity": "critical",
        }
        formatted = format_finding_cn(vuln, lang="zh")
        assert formatted["severity_cn"] == "严重"


class TestTranslationMaps:
    def test_severity_map_completeness(self):
        assert "critical" in SEVERITY_MAP
        assert "high" in SEVERITY_MAP
        assert "medium" in SEVERITY_MAP
        assert "low" in SEVERITY_MAP
        assert "info" in SEVERITY_MAP

    def test_verdict_map_completeness(self):
        assert "confirmed" in VERDICT_MAP
        assert "refuted" in VERDICT_MAP
        assert "needs_review" in VERDICT_MAP

    def test_vulnerability_map_completeness(self):
        assert "SQL Injection" in VULNERABILITY_TITLE_MAP
        assert "XSS" in VULNERABILITY_TITLE_MAP
        assert "CSRF" in VULNERABILITY_TITLE_MAP

    def test_recommendation_map_completeness(self):
        assert "Use parameterized queries" in RECOMMENDATION_MAP
        assert "Use CSRF token" in RECOMMENDATION_MAP

    def test_status_map_completeness(self):
        assert "VALID" in STATUS_MAP
        assert "INVALID" in STATUS_MAP
        assert "UNCERTAIN" in STATUS_MAP
