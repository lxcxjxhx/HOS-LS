"""Safe declarative-only compiler."""
from datetime import datetime,timezone
from .models import CandidateState,ConstrainedDeclarativeSpecification,ValidationResult
ALLOWED={"role","api_signature","parameter_positions","applicability","taint_semantics"}
class CompilationInputValidator:
    def validate(self,data):
        bad=set(data)-ALLOWED
        unsafe=bad or any(k in data for k in ("callback","code","runtime_generation")) or any("exec" in str(x).lower() for x in data.get("taint_semantics",()))
        return not unsafe,"unsafe or unknown fields" if unsafe else "valid"
class DeclarativeCompiler:
    def __init__(self,validator=None): self.validator=validator or CompilationInputValidator()
    def compile(self,record,data,provenance):
        ok,reason=self.validator.validate(data)
        if record.state is not CandidateState.ACCEPTED or not ok:
            return None,ValidationResult(version="1",created_at=datetime.now(timezone.utc),provenance=provenance,kind="INPUT_VALIDATION",outcome=reason,linked_artifact_ids=(record.artifact_id,))
        return ConstrainedDeclarativeSpecification(version="1",created_at=datetime.now(timezone.utc),provenance=provenance,candidate_record_id=record.artifact_id,**data),None
