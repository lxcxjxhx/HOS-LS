"""Pure policy decisions."""
from dataclasses import dataclass
from .models import CandidateState
@dataclass(frozen=True)
class PolicyDecision: state:CandidateState; confidence:float; outcome:str
def evaluate_acceptance(record,policy):
    met=set(record.evidence_ids); required=set(policy.conditions); ok=required.issubset(met) and record.state is not CandidateState.REJECTED
    return PolicyDecision(CandidateState.ACCEPTED if ok else CandidateState.UNACCEPTED,record.confidence,"accepted" if ok else "insufficient_evidence")
def apply_validation(record,result,policy):
    mapping={x.name:x.value for x in policy.result_mappings}; action=mapping.get(result.kind,"unaccepted")
    if action=="reject": return PolicyDecision(CandidateState.REJECTED,0.0,"rejected")
    delta=-0.2 if action in {"decrease","unaccepted"} else 0.0
    return PolicyDecision(CandidateState.UNACCEPTED if delta else record.state,max(0,record.confidence+delta),action)
