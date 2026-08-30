from src.ai.pure_ai.agent_6 import _deterministic_final_decision
from src.ai.pure_ai.patch_detector import analyze


class _PipelineStub:
    def __init__(self):
        self.debug_logs = []

    @staticmethod
    def _verify_location_exists(location, context):
        return True, ""


def _confirmed_sql_finding(location):
    return {
        "title": "SQL 注入",
        "location": location,
        "severity": "HIGH",
        "cwe_id": "CWE-89",
        "signal_id": "risk-1",
        "verification_decision": "CONFIRMED",
        "signal_state": "CONFIRMED",
        "verification_reason": "受控输入流向 SQL 执行点",
    }


def test_fix_pattern_requires_a_nearby_reported_location():
    content = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    detection = analyze("sample.py", content)

    assert detection.has_fix_for("CWE-89")
    assert detection.has_fix_near_location("CWE-89", "sample.py:1")
    assert not detection.has_fix_near_location("CWE-89", "sample.py:20")
    assert not detection.has_fix_near_location("CWE-89", "sample.py")


def test_agent6_does_not_suppress_a_distant_same_cwe_finding():
    content = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    result = _deterministic_final_decision(
        _PipelineStub(),
        {"vulnerabilities": [_confirmed_sql_finding("sample.py:20")]},
        {"file_content": content},
        {},
        analyze("sample.py", content),
    )

    assert result["final_findings"][0]["status"] == "CONFIRMED"
    assert not result["final_findings"][0]["requires_human_review"]


def test_agent6_marks_a_nearby_matching_fix_for_review():
    content = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    result = _deterministic_final_decision(
        _PipelineStub(),
        {"vulnerabilities": [_confirmed_sql_finding("sample.py:1")]},
        {"file_content": content},
        {},
        analyze("sample.py", content),
    )

    assert result["final_findings"][0]["status"] == "WEAK"
    assert result["final_findings"][0]["requires_human_review"]
