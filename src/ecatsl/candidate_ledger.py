"""Immutable candidate lifecycle."""
from datetime import datetime,timezone
from .models import Attribute
class CandidateLedger:
    def __init__(self,repository): self.repository=repository
    def create(self,record):
        try:return self.repository.append(record)
        except Exception as exc:self.repository.audit_failure("candidate_creation",exc); raise
    def apply(self,record,decision,cause,policy_version,input_ids=()):
        changed=(Attribute(name="policy_outcome",value=decision.outcome),Attribute(name="policy_inputs",value=",".join(input_ids)))
        successor=record.model_copy(update={"version":str(int(record.version)+1),"created_at":datetime.now(timezone.utc),"predecessor_id":record.artifact_id,"state":decision.state,"confidence":decision.confidence,"update_cause":cause,"changed_data":changed,"acceptance_policy_version":policy_version})
        return self.repository.append(successor)
