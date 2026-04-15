"""Schema定义模块

定义所有Agent输出的权威Schema，确保结构一致性。
"""

from enum import Enum

class EvidenceType(str, Enum):
    """证据类型枚举"""
    CODE_LINE = "code_line"
    CONFIG = "config"
    FLOW = "flow"
    DEPENDENCY = "dependency"

class SignalState(str, Enum):
    """信号状态枚举 - 用于Agent之间语义一致性追踪"""
    NEW = "NEW"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    REFINED = "REFINED"
    UNCERTAIN = "UNCERTAIN"

class Verdict(str, Enum):
    """对抗验证裁决枚举"""
    REFUTE = "REFUTE"
    ACCEPT = "ACCEPT"
    ESCALATE = "ESCALATE"
    UNCERTAIN = "UNCERTAIN"

class Severity(str, Enum):
    """严重程度枚举"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

EVIDENCE_SCHEMA = {
    "type": "object",
    "required": ["type", "location", "reason", "confidence"],
    "properties": {
        "type": {"type": "string", "enum": [e.value for e in EvidenceType]},
        "location": {"type": "string"},
        "reason": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "code_snippet": {"type": "string"},
        "source_agent": {"type": "string"}
    }
}

CROSS_AGENT_AGREEMENT_SCHEMA = {
    "type": "object",
    "required": ["signal_id", "signal_type", "original_agent", "current_state", "evidence_chain"],
    "properties": {
        "signal_id": {"type": "string"},
        "signal_type": {"type": "string"},
        "original_agent": {"type": "string"},
        "current_state": {"type": "string", "enum": [s.value for s in SignalState]},
        "evidence_chain": {
            "type": "array",
            "items": EVIDENCE_SCHEMA
        },
        "confirmed_by": {"type": "array", "items": {"type": "string"}},
        "rejected_by": {"type": "array", "items": {"type": "string"}},
        "refined_by": {"type": "array", "items": {"type": "string"}}
    }
}

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
                    "status": {"type": "string", "enum": ["CONFIRMED", "WEAK", "REJECTED"]},
                    "confidence": {"type": "string"},
                    "cvss_score": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "items": EVIDENCE_SCHEMA
                    },
                    "evidence_chain_summary": {"type": "string"},
                    "requires_human_review": {"type": "boolean"},
                    "signal_state": {"type": "string", "enum": [s.value for s in SignalState]}
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
                "low_severity_count": {"type": "integer"},
                "signals_confirmed": {"type": "integer"},
                "signals_rejected": {"type": "integer"},
                "signals_refined": {"type": "integer"}
            }
        }
    }
}

VULNERABILITY_SCHEMA = {
    "type": "object",
    "required": ["vulnerabilities", "signal_tracking"],
    "properties": {
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["title", "severity", "location", "evidence", "signal_state"],
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                    "location": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "items": EVIDENCE_SCHEMA
                    },
                    "cwe_id": {"type": "string"},
                    "cvss_score": {"type": "string"},
                    "signal_state": {"type": "string", "enum": [s.value for s in SignalState]},
                    "verification_decision": {"type": "string", "enum": ["CONFIRMED", "REJECTED", "REFINED"]},
                    "verification_reason": {"type": "string"}
                }
            }
        },
        "signal_tracking": {
            "type": "object",
            "properties": {
                "signals_confirmed": {"type": "integer"},
                "signals_rejected": {"type": "integer"},
                "signals_refined": {"type": "integer"},
                "signals_new": {"type": "integer"}
            }
        }
    }
}

ADVERSARIAL_SCHEMA = {
    "type": "object",
    "required": ["adversarial_analysis", "cross_agent_agreement"],
    "properties": {
        "adversarial_analysis": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["attack_chain_name", "verdict", "confidence", "evidence"],
                "properties": {
                    "attack_chain_name": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["REFUTE", "ACCEPT", "ESCALATE", "UNCERTAIN"]},
                    "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "reason": {"type": "string"},
                    "counter_arguments": {"type": "array", "items": {"type": "string"}},
                    "evidence": {
                        "type": "array",
                        "items": EVIDENCE_SCHEMA
                    },
                    "requires_human_review": {"type": "boolean"},
                    "challenged_signal_id": {"type": "string"}
                }
            }
        },
        "cross_agent_agreement": {
            "type": "array",
            "items": CROSS_AGENT_AGREEMENT_SCHEMA
        }
    }
}

RISK_ENUMERATION_SCHEMA = {
    "type": "object",
    "required": ["risks", "signal_tracking"],
    "properties": {
        "risks": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["risk_type", "severity", "location", "signal_id", "evidence"],
                "properties": {
                    "risk_type": {"type": "string"},
                    "severity": {"type": "string"},
                    "location": {"type": "string"},
                    "description": {"type": "string"},
                    "signal_id": {"type": "string"},
                    "signal_state": {"type": "string", "enum": [s.value for s in SignalState]},
                    "evidence": {
                        "type": "array",
                        "items": EVIDENCE_SCHEMA
                    }
                }
            }
        },
        "potential_vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "evidence", "signal_id"],
                "properties": {
                    "type": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "items": EVIDENCE_SCHEMA
                    },
                    "signal_id": {"type": "string"}
                }
            }
        },
        "signal_tracking": {
            "type": "object",
            "properties": {
                "total_signals": {"type": "integer"},
                "signals_new": {"type": "integer"},
                "signals_confirmed": {"type": "integer"},
                "signals_rejected": {"type": "integer"},
                "signals_refined": {"type": "integer"}
            }
        }
    }
}

ATTACK_CHAIN_SCHEMA = {
    "type": "object",
    "required": ["attack_chains", "signal_tracking"],
    "properties": {
        "attack_chains": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["chain_name", "steps", "signal_id"],
                "properties": {
                    "chain_name": {"type": "string"},
                    "steps": {"type": "array"},
                    "risk_level": {"type": "string"},
                    "signal_id": {"type": "string"},
                    "signal_state": {"type": "string", "enum": [s.value for s in SignalState]},
                    "evidence": {
                        "type": "array",
                        "items": EVIDENCE_SCHEMA
                    }
                }
            }
        },
        "signal_tracking": {
            "type": "object",
            "properties": {
                "total_signals": {"type": "integer"},
                "signals_new": {"type": "integer"},
                "signals_confirmed": {"type": "integer"},
                "signals_rejected": {"type": "integer"}
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
