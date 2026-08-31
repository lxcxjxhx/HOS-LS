"""Exclusive static-path confirmation gate.

Task 4.5: implement :class:`FindingConfirmationService`. A finding is
confirmed if and only if a supported adapter produced complete
provenance-backed :class:`PathEvidence` whose sanitizer status is ABSENT or
FAILED. Blocking sanitizers and any missing or incompatible element remain
unconfirmed. CWE/NVD records are attached only as explanatory support, every
available candidate/specification/validation/path identity is retained, and a
partially failed lineage persistence preserves the classification while
enumerating the missing metadata.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Sequence

from .artifact_repository import (
    ArtifactRepository,
    ClassificationPersistenceResult,
)
from .models import (
    FindingClassification,
    FindingStatus,
    PathEvidence,
    SanitizerStatus,
)


class FindingConfirmationService:
    """Confirm findings only on complete supported static-path evidence.

    The service keeps a pure decision function for direct callers and an
    optional repository-backed path that persists the classification and its
    lineage. Persistence failures for optional lineage elements never roll
    back the decision: the classification is retained with matching
    ``missing_metadata`` entries and one ``AuditFailureRecord`` per missing
    element.
    """

    def __init__(self, repository: Optional[ArtifactRepository] = None) -> None:
        if repository is not None and not isinstance(repository, ArtifactRepository):
            raise TypeError("repository must be an ArtifactRepository or None")
        self.repository = repository

    @staticmethod
    def _qualifies(path: Optional[PathEvidence]) -> bool:
        """Strict static-path confirmation predicate (pure, no persistence)."""
        return bool(
            path is not None
            and path.supported_adapter
            and path.source_provenance.content_identity
            and path.propagation_steps
            and path.sink
            and path.sanitizer_status in (SanitizerStatus.ABSENT, SanitizerStatus.FAILED)
        )

    def _decision(
        self,
        *,
        provenance,
        path: Optional[PathEvidence],
        candidate_record_ids: Sequence[str],
        specification_ids: Sequence[str],
        validation_result_ids: Sequence[str],
        explanatory_support_ids: Sequence[str],
        missing_metadata: Sequence[str],
    ) -> FindingClassification:
        qualifies = self._qualifies(path)
        return FindingClassification(
            version="1",
            created_at=datetime.now(timezone.utc),
            provenance=provenance,
            status=FindingStatus.CONFIRMED if qualifies else FindingStatus.UNCONFIRMED,
            reason=(
                "supported complete static path"
                if qualifies
                else "no qualifying supported static path"
            ),
            path_evidence_id=path.artifact_id if (qualifies and path is not None) else None,
            candidate_record_ids=tuple(candidate_record_ids),
            specification_ids=tuple(specification_ids),
            validation_result_ids=tuple(validation_result_ids),
            explanatory_support_ids=tuple(explanatory_support_ids),
            missing_metadata=tuple(dict.fromkeys(missing_metadata)),
        )

    def classify(
        self,
        *,
        provenance,
        path: Optional[PathEvidence] = None,
        candidate_record_ids: Sequence[str] = (),
        specification_ids: Sequence[str] = (),
        validation_result_ids: Sequence[str] = (),
        explanatory_support_ids: Sequence[str] = (),
        explanatory_ids: Sequence[str] = (),
        missing_metadata: Sequence[str] = (),
        idempotency_key: Optional[str] = None,
    ) -> FindingClassification | ClassificationPersistenceResult:
        """Classify a finding from strict static-path evidence alone.

        ``explanatory_ids`` is a backward-compatible alias for
        ``explanatory_support_ids`` (the existing ECATSL Service and property
        tests call it that). Callers that persist through a repository
        receive the durable classification together with any audit failures
        for unavailable lineage elements.
        """
        if explanatory_ids and explanatory_support_ids:
            raise ValueError("pass explanatory_support_ids or explanatory_ids, not both")
        supports = tuple(explanatory_support_ids or explanatory_ids)
        decision = self._decision(
            provenance=provenance,
            path=path,
            candidate_record_ids=candidate_record_ids,
            specification_ids=specification_ids,
            validation_result_ids=validation_result_ids,
            explanatory_support_ids=supports,
            missing_metadata=missing_metadata,
        )
        if self.repository is None:
            return decision
        return self.repository.persist_classification(
            decision, idempotency_key=idempotency_key
        )