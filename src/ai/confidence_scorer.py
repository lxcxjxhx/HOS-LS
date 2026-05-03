from typing import Any, Dict, List, Tuple

SENSITIVE_APIS = [
    "exec", "eval", "compile", "__import__", "open", "os.system", "os.popen",
    "subprocess.call", "subprocess.run", "subprocess.Popen", "os.execl",
    "os.execle", "os.execv", "os.execve", "os.spawnl", "os.spawnv",
    "sqlalchemy.text", "cursor.execute", "cursor.executemany",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "urllib.urlopen", "urllib.request.urlopen", "eval", "exec",
    "pickle.load", "pickle.loads", "yaml.load", "yaml.safe_load",
    "dom.parse", "ElementTree.parse", "SAX.parse", "JSON.parse"
]

DANGEROUS_PATTERNS = [
    "sql_injection", "command_injection", "path_traversal",
    "xss", "xxe", "deserialization", "eval_usage", "hardcoded_secret",
    "weak_crypto", "idor", "csrf", "ssrf", "ssti", "race_condition"
]

CRITICAL_PATTERNS = ["sql_injection", "command_injection", "deserialization", "eval_usage"]


class ConfidenceScorer:
    def __init__(self):
        self.max_evidence_score = 40
        self.max_pattern_score = 30
        self.max_dataflow_score = 30

    def score(self, finding: Dict[str, Any]) -> Tuple[int, str]:
        evidence_score = self._score_evidence(finding)
        pattern_score = self._score_pattern(finding)
        dataflow_score = self._score_dataflow(finding)

        total_score = evidence_score + pattern_score + dataflow_score
        total_score = min(total_score, 100)

        if total_score >= 70:
            level = "HIGH"
        elif total_score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        finding["confidence"] = {
            "score": total_score,
            "level": level,
            "breakdown": {
                "evidence_score": evidence_score,
                "pattern_score": pattern_score,
                "dataflow_score": dataflow_score
            }
        }

        return total_score, level

    def _score_evidence(self, finding: Dict[str, Any]) -> int:
        score = 0
        code_snippets = finding.get("code_snippets", [])
        if code_snippets and len(code_snippets) > 0:
            score += 15

        for snippet in code_snippets:
            snippet_lower = snippet.lower() if isinstance(snippet, str) else ""
            for api in SENSITIVE_APIS:
                if api in snippet_lower:
                    score += 10
                    break

        vulnerable_code = finding.get("vulnerable_code", "")
        if vulnerable_code:
            score += 15
            for api in SENSITIVE_APIS:
                if api in vulnerable_code.lower():
                    score += 10
                    break

        file_path = finding.get("file_path", "")
        line_number = finding.get("line_number", 0)
        if file_path and line_number > 0:
            score += 5

        return min(score, self.max_evidence_score)

    def _score_pattern(self, finding: Dict[str, Any]) -> int:
        score = 0
        vulnerability_type = finding.get("vulnerability_type", "").lower()
        vulnerability_name = finding.get("vulnerability_name", "").lower()

        for pattern in DANGEROUS_PATTERNS:
            if pattern in vulnerability_type or pattern in vulnerability_name:
                score += 15
                if pattern in CRITICAL_PATTERNS:
                    score += 10
                break

        cwe_id = finding.get("cwe_id", "")
        if cwe_id:
            score += 5

        return min(score, self.max_pattern_score)

    def _score_dataflow(self, finding: Dict[str, Any]) -> int:
        score = 0

        taint_sources = finding.get("taint_sources", [])
        if taint_sources and len(taint_sources) > 0:
            score += 10

        taint_sinks = finding.get("taint_sinks", [])
        if taint_sinks and len(taint_sinks) > 0:
            score += 10

        sanitizers = finding.get("sanitizers", [])
        if sanitizers and len(sanitizers) > 0:
            score -= 5

        data_flow_path = finding.get("data_flow_path", [])
        if data_flow_path and len(data_flow_path) > 2:
            score += 10
        elif data_flow_path and len(data_flow_path) > 0:
            score += 5

        entry_points = finding.get("entry_points", [])
        if entry_points and len(entry_points) > 0:
            score += 5

        return max(0, min(score, self.max_dataflow_score))


def is_high_confidence(finding: Dict[str, Any]) -> bool:
    if "confidence" not in finding:
        scorer = ConfidenceScorer()
        scorer.score(finding)
    return finding.get("confidence", {}).get("level") == "HIGH"


def filter_by_confidence(findings: List[Dict], min_level: str = "HIGH") -> List[Dict]:
    scorer = ConfidenceScorer()
    level_priority = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

    min_priority = level_priority.get(min_level.upper(), 3)

    filtered = []
    for finding in findings:
        if "confidence" not in finding:
            scorer.score(finding)
        level = finding.get("confidence", {}).get("level", "LOW")
        if level_priority.get(level, 0) >= min_priority:
            filtered.append(finding)

    return filtered