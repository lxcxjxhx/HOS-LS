"""Existing-tooling-first resolver."""
from dataclasses import dataclass
TERMINAL={"RESOLVED","UNRESOLVED","INAPPLICABLE","UNAVAILABLE","FAILED"}
@dataclass(frozen=True)
class ResolutionBundle: records:tuple; unknown_api:bool; llm_attempt:object=None
class ToolingFirstResolver:
    def resolve(self,capabilities,llm=None):
        records=[]; resolved=False
        for capability in capabilities:
            try: record=capability(); records.append(record); resolved|=record.outcome=="RESOLVED"
            except Exception: records.append(None)
        complete=all(r is None or r.outcome in TERMINAL for r in records)
        unknown=complete and not resolved
        attempt=llm(tuple(r for r in records if r)) if unknown and llm else None
        return ResolutionBundle(tuple(records),unknown,attempt)
