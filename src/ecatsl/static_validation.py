"""Persist static feedback and apply the recorded validation policy.

Task 4.4: connect normalized static feedback to candidate updates. Every
adapter result is retained first, then the recorded validation policy is applied
for compilation errors, no paths, parameter mismatches, sanitizer evidence, and
role/applicability invalidation. Observed and declared parameter positions,
sanitizer/blocking data, unsupported-adapter outcomes, candidate lineage, and
recovery flags are retained without manufacturing a path. Missing path elements
are never inferred from discovery, catalog, RAG, or LLM data.
"""

from __future__ import annotations

from typing import Optional, Sequence

from .artifact_repository import ArtifactRepository
from .candidate_ledger import CandidateLedger, CandidateValidationResult
from .models import (
    Attribute,
    CandidateRecord,
    Counterexample,
    ValidationPolicy,
    ValidationResult,
)
from .static_adapters import NormalizationResult


class StaticValidationService:
    """Bridge one normalized static-adapter result into candidate lifecycle updates."""

    def __init__(self, repository: ArtifactRepository, ledger: CandidateLedger) -> None:
        if repository is None or ledger is None:
            raise ValueError("StaticValidationService requires both repository and ledger")
        self.repository = repository
        self.ledger = ledger

    @staticmethod
    def _observed_data(normalized: NormalizationResult) -> tuple[Attribute, ...]:
        """Flatten adapter-retained evidence into observable validation attributes.

        Only values already retained on the normalization result are copied;
        nothing is synthesized or inferred from discovery/catalog/RAG/LLM.
        """
        attributes = []
        if normalized.raw_output_identity:
            attributes.append(Attribute(name="raw_output_identity", value=normalized.raw_output_identity))
        if normalized.reason:
            attributes.append(Attribute(name="reason", value=normalized.reason))
        if normalized.observed_location_identities:
            attributes.append(
                Attribute(
                    name="observed_location_identities",
                    value=",".join(normalized.observed_location_identities),
                )
            )
        if normalized.path_evidence is not None:
            attributes.append(Attribute(name="path_evidence_id", value=normalized.path_evidence.artifact_id))
        return tuple(attributes)

    def apply(
        self,
        candidate: CandidateRecord,
        normalized: NormalizationResult,
        policy: ValidationPolicy,
        *,
        counterexamples: Sequence[Counterexample] = (),
        idempotency_key: Optional[str] = None,
    ) -> CandidateValidationResult:
        """Retain the adapter result and apply the validation policy.

        The ``ValidationResult`` embedded in the normalization outcome is always
        persisted first (with its observed data), then the recorded policy maps
        compilation errors, no paths, parameter mismatches, sanitizer evidence,
        and role/applicability invalidation to non-promoting lifecycle effects.
        """
        validation = normalized.validation
        enriched_validation = ValidationResult(
            version=validation.version,
            created_at=validation.created_at,
            provenance=validation.provenance,
            kind=validation.kind,
            outcome=validation.outcome,
            adapter_id=validation.adapter_id,
            adapter_version=validation.adapter_version,
            linked_artifact_ids=validation.linked_artifact_ids,
            observed_data=(
                *validation.observed_data,
                *self._observed_data(normalized),
            ),
        )
        return self.ledger.apply_validation(
            candidate,
            enriched_validation,
            policy,
            counterexamples=counterexamples,
            idempotency_key=idempotency_key,
        )
