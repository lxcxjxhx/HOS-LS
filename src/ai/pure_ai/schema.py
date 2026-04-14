"""Schema定义模块

定义所有Agent输出的权威Schema，确保结构一致性。
"""

FINAL_DECISION_SCHEMA = {
    "type": "object",
    "required": ["final_findings", "summary"],
    "properties": {
        "final_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["vulnerability", "location", "severity", "status", "confidence", "evidence", "recommendation"],
                "properties": {
                    "vulnerability": {"type": "string"},
                    "location": {"type": "string"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                    "status": {"type": "string", "enum": ["VALID", "UNCERTAIN", "INVALID"]},
                    "confidence": {"type": "string"},
                    "cvss_score": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "evidence": {"type": "string"},
                    "requires_human_review": {"type": "boolean"}
                }
            }
        },
        "summary": {
            "type": "object",
            "required": ["total_vulnerabilities", "valid_vulnerabilities", "high_severity_count"],
            "properties": {
                "total_vulnerabilities": {"type": "integer"},
                "valid_vulnerabilities": {"type": "integer"},
                "uncertain_vulnerabilities": {"type": "integer"},
                "invalid_vulnerabilities": {"type": "integer"},
                "high_severity_count": {"type": "integer"},
                "medium_severity_count": {"type": "integer"},
                "low_severity_count": {"type": "integer"}
            }
        }
    }
}

VULNERABILITY_SCHEMA = {
    "type": "object",
    "required": ["vulnerabilities"],
    "properties": {
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["title", "severity", "location", "evidence"],
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                    "location": {"type": "string"},
                    "evidence": {"type": "string"},
                    "cwe_id": {"type": "string"},
                    "cvss_score": {"type": "string"}
                }
            }
        }
    }
}

ADVERSARIAL_SCHEMA = {
    "type": "object",
    "required": ["adversarial_analysis"],
    "properties": {
        "adversarial_analysis": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["attack_chain_name", "verdict", "confidence"],
                "properties": {
                    "attack_chain_name": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["REFUTE", "ACCEPT", "ESCALATE", "UNCERTAIN"]},
                    "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "reason": {"type": "string"},
                    "counter_arguments": {"type": "array", "items": {"type": "string"}},
                    "evidence": {"type": "string"},
                    "requires_human_review": {"type": "boolean"}
                }
            }
        }
    }
}

RISK_ENUMERATION_SCHEMA = {
    "type": "object",
    "required": ["risks"],
    "properties": {
        "risks": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["risk_type", "severity", "location"],
                "properties": {
                    "risk_type": {"type": "string"},
                    "severity": {"type": "string"},
                    "location": {"type": "string"},
                    "description": {"type": "string"}
                }
            }
        },
        "potential_vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "evidence"],
                "properties": {
                    "type": {"type": "string"},
                    "evidence": {"type": "string"}
                }
            }
        }
    }
}

ATTACK_CHAIN_SCHEMA = {
    "type": "object",
    "required": ["attack_chains"],
    "properties": {
        "attack_chains": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["chain_name", "steps"],
                "properties": {
                    "chain_name": {"type": "string"},
                    "steps": {"type": "array"},
                    "risk_level": {"type": "string"}
                }
            }
        }
    }
}

CONTEXT_ANALYSIS_SCHEMA = {
    "type": "object",
    "required": ["file_type", "frameworks"],
    "properties": {
        "file_type": {"type": "string"},
        "frameworks": {"type": "array", "items": {"type": "string"}},
        "security_relevant": {"type": "boolean"}
    }
}

CODE_UNDERSTANDING_SCHEMA = {
    "type": "object",
    "required": ["purpose", "security_controls"],
    "properties": {
        "purpose": {"type": "string"},
        "security_controls": {"type": "array", "items": {"type": "string"}},
        "data_flows": {"type": "array"}
    }
}
