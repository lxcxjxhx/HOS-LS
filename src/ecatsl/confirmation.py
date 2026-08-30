"""Exclusive static-path confirmation gate."""
from datetime import datetime,timezone
from .models import FindingClassification,FindingStatus,SanitizerStatus
class FindingConfirmationService:
    def classify(self,*,provenance,path=None,candidate_ids=(),specification_ids=(),validation_ids=(),explanatory_ids=(),missing_metadata=()):
        qualifies=bool(path and path.supported_adapter and path.source_provenance.content_identity and path.propagation_steps and path.sink and path.sanitizer_status in {SanitizerStatus.ABSENT,SanitizerStatus.FAILED})
        return FindingClassification(version="1",created_at=datetime.now(timezone.utc),provenance=provenance,status=FindingStatus.CONFIRMED if qualifies else FindingStatus.UNCONFIRMED,reason="supported complete static path" if qualifies else "no qualifying supported static path",path_evidence_id=path.artifact_id if qualifies else None,candidate_record_ids=tuple(candidate_ids),specification_ids=tuple(specification_ids),validation_result_ids=tuple(validation_ids),explanatory_support_ids=tuple(explanatory_ids),missing_metadata=tuple(missing_metadata))
