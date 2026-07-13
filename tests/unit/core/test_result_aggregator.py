"""result_aggregator.py 单元测试

验证智能去重功能：
1. smart_deduplicate() 方法工作正常
2. 重复报告已消除
3. 语义去重功能正常
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from src.core.result_aggregator import (
    ResultAggregator, AggregatedFinding, Severity, convert_to_aggregated_finding
)


def test_basic_deduplication():
    """测试基础去重功能"""
    aggregator = ResultAggregator()
    
    finding1 = AggregatedFinding(
        rule_id="SQL_INJECTION",
        file_path="test.py",
        line=10,
        code_snippet="SELECT * FROM users WHERE id = " + "{user_id}",
        confidence=0.9,
        severity=Severity.CRITICAL
    )
    
    finding2 = AggregatedFinding(
        rule_id="SQL_INJECTION",
        file_path="test.py",
        line=10,
        code_snippet="SELECT * FROM users WHERE id = " + "{user_id}",
        confidence=0.8,
        severity=Severity.CRITICAL
    )
    
    aggregator.add_finding(finding1)
    result = aggregator.add_finding(finding2)
    
    assert result == False, "重复发现应该被拒绝"
    assert len(aggregator.findings) == 1, "应该只有1个发现"
    print("[PASS] test_basic_deduplication")


def test_smart_deduplicate_same_rule_adjacent_lines():
    """测试智能去重 - 相同规则相邻行号"""
    aggregator = ResultAggregator()
    
    findings = [
        AggregatedFinding(
            rule_id="SQL_INJECTION_1",
            file_path="api/users.py",
            line=10,
            code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            confidence=0.9,
            severity=Severity.CRITICAL,
            description="SQL注入漏洞"
        ),
        AggregatedFinding(
            rule_id="SQL_INJECTION_2",
            file_path="api/users.py",
            line=12,
            code_snippet="cursor.execute(query)",
            confidence=0.8,
            severity=Severity.HIGH,
            description="SQL注入风险"
        ),
        AggregatedFinding(
            rule_id="XSS_REFLECTED",
            file_path="api/users.py",
            line=50,
            code_snippet="return render_template('user.html', user=user_input)",
            confidence=0.85,
            severity=Severity.HIGH,
            description="XSS跨站脚本漏洞"
        ),
    ]
    
    aggregator.add_findings(findings)
    removed = aggregator.smart_deduplicate()
    
    assert removed == 1, f"应该移除1个重复发现，实际移除 {removed}"
    assert len(aggregator.findings) == 2, f"应该保留2个发现，实际保留 {len(aggregator.findings)}"
    
    best_finding = max(
        [f for f in findings if f.rule_id in ["SQL_INJECTION_1", "SQL_INJECTION_2"]],
        key=lambda f: f.confidence
    )
    assert best_finding in aggregator.findings, "应该保留置信度最高的发现"
    print("[PASS] test_smart_deduplicate_same_rule_adjacent_lines")


def test_smart_deduplicate_cross_files_semantic():
    """测试智能去重 - 跨文件语义去重"""
    aggregator = ResultAggregator()
    
    findings = [
        AggregatedFinding(
            rule_id="SQL_INJECTION",
            file_path="api/users.py",
            line=10,
            code_snippet="query = f'SELECT * FROM users'",
            confidence=0.9,
            severity=Severity.CRITICAL,
            description="SQL注入漏洞 - 用户查询"
        ),
        AggregatedFinding(
            rule_id="SQL_INJECTION_VULN",
            file_path="api/admin.py",
            line=25,
            code_snippet="cursor.execute(sql)",
            confidence=0.85,
            severity=Severity.HIGH,
            description="SQL注入风险 - 管理员查询"
        ),
        AggregatedFinding(
            rule_id="XSS_REFLECTED",
            file_path="api/users.py",
            line=50,
            code_snippet="return render_template('user.html')",
            confidence=0.8,
            severity=Severity.HIGH,
            description="XSS跨站脚本漏洞"
        ),
    ]
    
    aggregator.add_findings(findings)
    removed = aggregator.smart_deduplicate()
    
    assert len(aggregator.findings) <= 2, f"跨文件语义去重后应该最多2个发现，实际 {len(aggregator.findings)}"
    print("[PASS] test_smart_deduplicate_cross_files_semantic")


def test_normalize_rule_id():
    """测试规则ID规范化"""
    finding = AggregatedFinding(rule_id="RULE_windows")
    assert finding._normalize_rule_id() == "RULE"
    
    finding = AggregatedFinding(rule_id="SQL_INJECTION_1")
    assert finding._normalize_rule_id() == "SQL_INJECTION"
    
    finding = AggregatedFinding(rule_id="RemoteTokenServices_SSRF")
    assert finding._normalize_rule_id() == "SSRF"
    
    finding = AggregatedFinding(rule_id="Spring_Cloud_Vulnerability")
    assert finding._normalize_rule_id() == "SPRING_CLOUD_VULNERABILITY"
    
    print("[PASS] test_normalize_rule_id")


def test_aggregate_with_smart_dedup():
    """测试完整聚合流程（启用智能去重）"""
    aggregator = ResultAggregator()
    
    findings_data = [
        {
            "rule_id": "SQL_INJECTION_1",
            "file_path": "test.py",
            "line": 10,
            "severity": "critical",
            "confidence": 0.9,
            "description": "SQL注入"
        },
        {
            "rule_id": "SQL_INJECTION_2",
            "file_path": "test.py",
            "line": 12,
            "severity": "high",
            "confidence": 0.8,
            "description": "SQL注入风险"
        },
        {
            "rule_id": "XSS",
            "file_path": "test.py",
            "line": 50,
            "severity": "medium",
            "confidence": 0.7,
            "description": "XSS漏洞"
        },
    ]
    
    result = aggregator.aggregate(
        findings=[convert_to_aggregated_finding(f) for f in findings_data],
        enable_smart_dedup=True
    )
    
    assert result.summary["total_findings"] <= 2, f"去重后应该最多2个发现"
    print("[PASS] test_aggregate_with_smart_dedup")


if __name__ == "__main__":
    test_basic_deduplication()
    test_smart_deduplicate_same_rule_adjacent_lines()
    test_smart_deduplicate_cross_files_semantic()
    test_normalize_rule_id()
    test_aggregate_with_smart_dedup()
    print("\n[INFO] 所有 result_aggregator 测试通过！")
