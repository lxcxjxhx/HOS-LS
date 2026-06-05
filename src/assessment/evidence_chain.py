"""证据链构建器模块

提供证据链的构建、验证和绑定功能。
"""

from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from src.core.engine import Evidence, Finding


class EvidenceChainBuilder:
    def __init__(self):
        self._evidence: List[Evidence] = []

    def add_evidence(
        self,
        source: str,
        raw_output: str,
        confidence: float,
        command: Optional[str] = None,
        tool: Optional[str] = None
    ) -> 'EvidenceChainBuilder':
        evidence = Evidence(
            source=source,
            raw_output=raw_output,
            confidence=confidence,
            command=command,
            tool=tool,
            timestamp=datetime.now()
        )
        self._evidence.append(evidence)
        return self

    def bind_to_finding(self, finding: Finding) -> Finding:
        finding.evidence = list(self._evidence)
        return finding

    def validate_evidence_chain(self) -> Tuple[bool, List[str]]:
        errors = []
        for e in self._evidence:
            if e.confidence < 0.0 or e.confidence > 1.0:
                errors.append(f"Invalid confidence {e.confidence}")
            if not e.raw_output:
                errors.append("Empty raw_output")
            if not e.source:
                errors.append("Missing source")
        return len(errors) == 0, errors

    def clear(self) -> None:
        self._evidence.clear()

    def get_evidence(self) -> List[Evidence]:
        return list(self._evidence)
