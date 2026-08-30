"""Deterministic, non-confirmatory candidate acceptance and validation policies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Sequence, Tuple

from .models import (
    AcceptancePolicy,
    Artifact,
    Attribute,
    CandidateRecord,
    CandidateState,
    Counterexample,
    Evidence,
    ValidationPolicy,
    ValidationResult,
)


class PolicyConfigurationError(ValueError):
    """A policy contains an unsupported, ambiguous, or proof-bearing predicate."""


class PolicyKind(str, Enum):
    ACCEPTANCE = "ACCEPTANCE"
    VALIDATION = "VALIDATION"


@dataclass(frozen=True)
class PolicyEvaluation:
    """A complete, persistence-ready policy decision without a proof claim."""

    kind: PolicyKind
    policy_version: str
    candidate_record_id: str
    outcome: str
    resulting_state: CandidateState
    resulting_confidence: float
    input_artifact_ids: Tuple[str, ...]
    audit_metadata: Tuple[Attribute, ...]
    unmet_conditions: Tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        return self.resulting_state is CandidateState.ACCEPTED


# Fail closed: only evidence emitted by explicitly local, reviewed producers can
# satisfy an independent-evidence predicate. Catalog, discovery, LLM/RAG
# providers, unknown external producers, and future origin labels remain
# non-confirmatory unless an acceptance policy explicitly selects them by origin.
_INDEPENDENT_EVIDENCE_ORIGINS = frozenset(
    {
        "repository",
        "validation",
        "input-tracer",
        "sast-prefilter-codeql",
    }
)
_PROOF_TERMS = ("confirm", "controllab", "path_evidence", "static_path")


def _artifact_ids(artifacts: Iterable[Artifact]) -> Tuple[str, ...]:
    return tuple(sorted({item.artifact_id for item in artifacts}))


def _normalized_origin(evidence: Evidence) -> str:
    return evidence.provenance.origin.strip().casefold()


def _is_independent_evidence(evidence: Evidence) -> bool:
    """Accept independent evidence only from the closed local-producer taxonomy."""

    return _normalized_origin(evidence) in _INDEPENDENT_EVIDENCE_ORIGINS


def _parse_confidence(value: str, condition: str) -> float:
    try:
        confidence = float(value)
    except ValueError as error:
        raise PolicyConfigurationError(
            f"{condition!r} requires a numeric confidence"
        ) from error
    if not 0.0 <= confidence <= 1.0:
        raise PolicyConfigurationError(
            f"{condition!r} confidence must be between zero and one"
        )
    return confidence


def _acceptance_conditions(policy: AcceptancePolicy) -> Tuple[str, ...]:
    if not policy.conditions:
        raise PolicyConfigurationError("acceptance policy requires at least one condition")
    normalized = tuple(item.strip() for item in policy.conditions)
    if any(not item for item in normalized) or len(normalized) != len(set(normalized)):
        raise PolicyConfigurationError("acceptance policy conditions must be unique and non-blank")
    for condition in normalized:
        if any(term in condition.casefold() for term in _PROOF_TERMS):
            raise PolicyConfigurationError(
                "acceptance policy cannot establish controllability or confirmation"
            )
    return normalized


def _require_recorded_inputs(
    candidate: CandidateRecord,
    evidence: Sequence[Evidence],
    counterexamples: Sequence[Counterexample],
) -> None:
    evidence_ids = _artifact_ids(evidence)
    counterexample_ids = _artifact_ids(counterexamples)
    if not set(evidence_ids).issubset(candidate.evidence_ids):
        raise PolicyConfigurationError("acceptance evidence is not linked to the candidate")
    if not set(counterexample_ids).issubset(candidate.counterexample_ids):
        raise PolicyConfigurationError("acceptance counterexample is not linked to the candidate")


def evaluate_acceptance(
    candidate: CandidateRecord,
    policy: AcceptancePolicy,
    *,
    evidence: Sequence[Evidence],
    counterexamples: Sequence[Counterexample] = (),
) -> PolicyEvaluation:
    """Evaluate evidence conditions without granting confirmation authority.

    ``origin:<name>`` predicates are allowed only as explicit hypothesis/ranking
    metadata. They never replace independent repository/static evidence and no
    predicate may mention confirmation, controllability, or a static-path proof.
    """

    conditions = _acceptance_conditions(policy)
    _require_recorded_inputs(candidate, evidence, counterexamples)
    unmet = []
    has_independent_evidence = any(_is_independent_evidence(item) for item in evidence)

    for condition in conditions:
        if condition == "independent_evidence":
            if not has_independent_evidence:
                unmet.append(condition)
        elif condition == "no_counterexamples":
            if counterexamples:
                unmet.append(condition)
        elif condition.startswith("minimum_confidence:"):
            minimum = _parse_confidence(condition.partition(":")[2], condition)
            if candidate.confidence < minimum:
                unmet.append(condition)
        elif condition.startswith("evidence_kind:"):
            kind = condition.partition(":")[2]
            if not kind:
                raise PolicyConfigurationError("evidence_kind condition requires a kind")
            if not any(
                item.evidence_kind == kind and _is_independent_evidence(item)
                for item in evidence
            ):
                unmet.append(condition)
        elif condition.startswith("origin:"):
            origin = condition.partition(":")[2].casefold()
            if not origin:
                raise PolicyConfigurationError("origin condition requires an origin")
            if not any(_normalized_origin(item) == origin for item in evidence):
                unmet.append(condition)
        else:
            raise PolicyConfigurationError(f"unsupported acceptance condition {condition!r}")

    if candidate.state is CandidateState.REJECTED:
        state = CandidateState.REJECTED
        outcome = "REJECTED"
        unmet.append("candidate_rejected")
    elif unmet:
        state = CandidateState.UNACCEPTED
        outcome = "UNACCEPTED"
    else:
        state = CandidateState.ACCEPTED
        outcome = "ACCEPTED"

    inputs = _artifact_ids((candidate, policy, *evidence, *counterexamples))
    return PolicyEvaluation(
        kind=PolicyKind.ACCEPTANCE,
        policy_version=policy.version,
        candidate_record_id=candidate.artifact_id,
        outcome=outcome,
        resulting_state=state,
        resulting_confidence=candidate.confidence,
        input_artifact_ids=inputs,
        audit_metadata=(
            Attribute(name="policy_kind", value=PolicyKind.ACCEPTANCE.value),
            Attribute(name="independent_evidence", value=str(has_independent_evidence).lower()),
            Attribute(name="condition_count", value=str(len(conditions))),
        ),
        unmet_conditions=tuple(sorted(set(unmet))),
    )


def _validation_mapping(policy: ValidationPolicy, result: ValidationResult) -> str | None:
    mappings = {item.name: item.value for item in policy.result_mappings}
    if len(mappings) != len(policy.result_mappings):
        raise PolicyConfigurationError("validation policy mappings must have unique names")
    return mappings.get(result.kind) or mappings.get(result.outcome) or mappings.get("*")


def _validation_effect(action: str, confidence: float) -> tuple[CandidateState, float]:
    normalized = action.strip().upper()
    if normalized == "REJECT":
        return CandidateState.REJECTED, 0.0
    if normalized == "UNACCEPT":
        return CandidateState.UNACCEPTED, confidence
    if normalized == "PRESERVE":
        return CandidateState.UNACCEPTED, confidence
    if normalized.startswith("UNACCEPT:"):
        return CandidateState.UNACCEPTED, _parse_confidence(
            normalized.partition(":")[2], action
        )
    if normalized.startswith("REJECT:"):
        return CandidateState.REJECTED, _parse_confidence(
            normalized.partition(":")[2], action
        )
    raise PolicyConfigurationError(f"unsupported validation policy action {action!r}")


def apply_validation(
    candidate: CandidateRecord,
    result: ValidationResult,
    policy: ValidationPolicy,
) -> PolicyEvaluation:
    """Map validation feedback to a non-promoting candidate lifecycle effect.

    Validation can retain or reduce acceptance only; confirmation remains the
    responsibility of the later supported-static-path confirmation service.
    """

    action = _validation_mapping(policy, result)
    if action is None:
        state, confidence, outcome = (
            CandidateState.UNACCEPTED,
            candidate.confidence,
            "UNACCEPTED_UNMAPPED_VALIDATION",
        )
        audit_action = "UNMAPPED"
    else:
        state, confidence = _validation_effect(action, candidate.confidence)
        outcome = state.value
        audit_action = action
    if candidate.state is CandidateState.REJECTED:
        state, confidence, outcome = CandidateState.REJECTED, 0.0, "REJECTED"

    return PolicyEvaluation(
        kind=PolicyKind.VALIDATION,
        policy_version=policy.version,
        candidate_record_id=candidate.artifact_id,
        outcome=outcome,
        resulting_state=state,
        resulting_confidence=confidence,
        input_artifact_ids=_artifact_ids((candidate, result, policy)),
        audit_metadata=(
            Attribute(name="policy_kind", value=PolicyKind.VALIDATION.value),
            Attribute(name="mapping", value=audit_action),
            Attribute(name="validation_kind", value=result.kind),
            Attribute(name="validation_outcome", value=result.outcome),
        ),
    )
