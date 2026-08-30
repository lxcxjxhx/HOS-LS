"""Safe, declarative-only candidate compiler.

This module deliberately emits data contracts only. It never evaluates Python,
creates callbacks, generates runtime code, or acts as a static-analysis runner.
Compilation and validation status are retained through ``ArtifactRepository``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Optional, Tuple

from .artifact_repository import ArtifactRepository, ValidationRetentionResult
from .models import (
    Applicability,
    Attribute,
    CandidateRecord,
    CandidateState,
    CandidateType,
    ConstrainedDeclarativeSpecification,
    Evidence,
    Provenance,
    ValidationResult,
)


_ALLOWED_FIELDS = frozenset(
    {"role", "api_signature", "parameter_positions", "applicability", "taint_semantics"}
)
_UNSAFE_FIELD_NAMES = frozenset(
    {
        "callback",
        "callbacks",
        "code",
        "executable",
        "executable_logic",
        "generated_code",
        "runtime_generation",
        "runtime_code",
        "source_code",
    }
)
_UNSAFE_TERMS = (
    "__import__",
    "eval(",
    "exec(",
    "lambda ",
    "compile(",
    "runtime_generation",
    "runtime code",
    "generated code",
)
_QUALIFIED_SIGNATURE = re.compile(
    r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+(?:\([^;\n]*\))?$"
)


@dataclass(frozen=True)
class CompilationValidation:
    """Pure validation outcome before persistence."""

    valid: bool
    outcome: str
    reason: str
    normalized_input: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class CompilationResult:
    """Compilation artifacts and retained validation statuses."""

    specification: Optional[ConstrainedDeclarativeSpecification]
    validation_results: Tuple[ValidationResult, ...]
    validation_retentions: Tuple[ValidationRetentionResult, ...] = ()

    @property
    def compiled(self) -> bool:
        return self.specification is not None

    @property
    def rejected(self) -> bool:
        return self.specification is None


class CompilationInputValidator:
    """Validate a closed, non-executable declarative input representation."""

    def validate(
        self,
        data: Mapping[str, Any],
        *,
        candidate: Optional[CandidateRecord] = None,
        evidence: Sequence[Evidence] = (),
    ) -> CompilationValidation:
        if not isinstance(data, Mapping):
            return self._invalid("INPUT_NOT_MAPPING", "compilation input must be a mapping")

        unknown = sorted(set(data) - _ALLOWED_FIELDS)
        if unknown:
            return self._invalid(
                "UNKNOWN_FIELDS", f"unknown compilation fields: {', '.join(unknown)}"
            )
        if self._contains_unsafe(data):
            return self._invalid("EXECUTABLE_INPUT", "executable logic or runtime generation is forbidden")

        missing = sorted(_ALLOWED_FIELDS - set(data))
        if missing:
            return self._invalid(
                "MISSING_DECLARATION", f"missing declarative fields: {', '.join(missing)}"
            )

        role = self._role(data["role"])
        if role is None:
            return self._invalid("INVALID_ROLE", "role must be a supported CandidateType")
        signature = data["api_signature"]
        if not isinstance(signature, str) or not _QUALIFIED_SIGNATURE.fullmatch(signature.strip()):
            return self._invalid(
                "INVALID_API_SIGNATURE",
                "api_signature must be a qualified declarative API signature",
            )

        positions = data["parameter_positions"]
        if not isinstance(positions, Sequence) or isinstance(positions, (str, bytes)):
            return self._invalid("INVALID_PARAMETER_POSITIONS", "parameter_positions must be a sequence")
        if any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in positions):
            return self._invalid(
                "INVALID_PARAMETER_POSITIONS",
                "parameter positions must be unique non-negative integers",
            )
        normalized_positions = tuple(positions)
        if len(set(normalized_positions)) != len(normalized_positions):
            return self._invalid(
                "INVALID_PARAMETER_POSITIONS",
                "parameter positions must not contain duplicates",
            )

        applicability = data["applicability"]
        if not isinstance(applicability, Applicability):
            return self._invalid(
                "INVALID_APPLICABILITY",
                "applicability must be the immutable Applicability contract",
            )
        semantics = data["taint_semantics"]
        if not isinstance(semantics, Sequence) or isinstance(semantics, (str, bytes)):
            return self._invalid("INVALID_TAINT_SEMANTICS", "taint_semantics must be a sequence")
        if not semantics or any(not isinstance(item, str) or not item.strip() for item in semantics):
            return self._invalid(
                "INVALID_TAINT_SEMANTICS",
                "taint_semantics must contain non-blank declarative strings",
            )
        if len(set(semantics)) != len(semantics):
            return self._invalid(
                "INVALID_TAINT_SEMANTICS",
                "taint_semantics must not contain duplicates",
            )

        if candidate is not None:
            if applicability != candidate.applicability:
                return self._invalid(
                    "APPLICABILITY_MISMATCH",
                    "compilation applicability must match the candidate declaration",
                )
            if signature != candidate.applicability.api_signature:
                return self._invalid(
                    "API_SIGNATURE_MISMATCH",
                    "compilation API signature must match candidate applicability",
                )
            if role is not candidate.candidate_type:
                return self._invalid(
                    "ROLE_MISMATCH",
                    "compilation role must match the candidate declaration",
                )
            if not set(candidate.evidence_ids).issubset(
                {item.artifact_id for item in evidence}
            ):
                return self._invalid(
                    "EVIDENCE_NOT_RETAINED",
                    "all candidate evidence must be supplied and retained",
                )
            supported_semantics = {
                value
                for item in evidence
                for attribute in item.payload
                if attribute.name in {"taint_semantics", "semantic", "semantics"}
                for value in (attribute.value,)
            }
            if not set(semantics).issubset(supported_semantics):
                return self._invalid(
                    "UNSUPPORTED_TAINT_SEMANTICS",
                    "taint semantics are not supported by candidate evidence",
                )

        normalized = {
            "role": role,
            "api_signature": signature.strip(),
            "parameter_positions": normalized_positions,
            "applicability": applicability,
            "taint_semantics": tuple(semantics),
        }
        return CompilationValidation(True, "VALID", "declarative input is valid", normalized)

    @staticmethod
    def _role(value: Any) -> Optional[CandidateType]:
        if isinstance(value, CandidateType):
            return value
        if isinstance(value, str):
            try:
                return CandidateType(value)
            except ValueError:
                return None
        return None

    @staticmethod
    def _contains_unsafe(value: Any, field_name: str = "") -> bool:
        if field_name.casefold() in _UNSAFE_FIELD_NAMES:
            return True
        if isinstance(value, Mapping):
            return any(
                CompilationInputValidator._contains_unsafe(item, str(key))
                for key, item in value.items()
            )
        if isinstance(value, (tuple, list, set, frozenset)):
            return any(CompilationInputValidator._contains_unsafe(item) for item in value)
        if isinstance(value, str):
            lowered = value.casefold()
            return any(term in lowered for term in _UNSAFE_TERMS)
        return False

    @staticmethod
    def _invalid(outcome: str, reason: str) -> CompilationValidation:
        return CompilationValidation(False, outcome, reason)


class DeclarativeCompiler:
    """Compile accepted candidates into constrained declarative specifications."""

    def __init__(
        self,
        repository: ArtifactRepository,
        *,
        validator: Optional[CompilationInputValidator] = None,
        compiler_version: str = "1",
    ) -> None:
        if not compiler_version.strip():
            raise ValueError("compiler_version must not be blank")
        self.repository = repository
        self.validator = validator or CompilationInputValidator()
        self.compiler_version = compiler_version

    @staticmethod
    def _provenance(candidate: CandidateRecord, stage: str) -> Provenance:
        return Provenance(
            origin="ecatsl:declarative-compiler",
            retrieved_at=datetime.now(timezone.utc),
            source_identifier=f"candidate:{candidate.candidate_id}",
            source_revision="compiler:v1",
            content_identity=f"{stage}:{candidate.artifact_id}",
            transformation_history=("declarative-compilation:v1",),
        )

    def _status(
        self,
        candidate: CandidateRecord,
        *,
        kind: str,
        outcome: str,
        observed_data: Sequence[Attribute] = (),
        linked_artifact_ids: Sequence[str] = (),
    ) -> ValidationResult:
        return ValidationResult(
            version=self.compiler_version,
            created_at=datetime.now(timezone.utc),
            provenance=self._provenance(candidate, kind.lower()),
            kind=kind,
            outcome=outcome,
            linked_artifact_ids=tuple(dict.fromkeys((candidate.artifact_id, *linked_artifact_ids))),
            observed_data=tuple(observed_data),
        )

    def _retain(
        self,
        candidate: CandidateRecord,
        validation: ValidationResult,
        *,
        idempotency_key: str,
    ) -> ValidationRetentionResult:
        return self.repository.retain_validation(
            candidate.artifact_id,
            validation,
            idempotency_key=idempotency_key,
        )

    def compile(
        self,
        candidate: CandidateRecord,
        compilation_input: Mapping[str, Any],
        *,
        evidence: Sequence[Evidence] = (),
        adapter_eligible: bool = True,
        adapter_supported: bool = True,
        idempotency_key: Optional[str] = None,
    ) -> CompilationResult:
        """Validate, retain status artifacts, and emit no executable behavior."""
        if candidate.state is not CandidateState.ACCEPTED:
            validation = self._status(
                candidate,
                kind="COMPILATION_EXCLUSION",
                outcome="CANDIDATE_NOT_ACCEPTED",
            )
            retained = self._retain(
                candidate,
                validation,
                idempotency_key=f"compile-exclusion:{candidate.artifact_id}",
            )
            return CompilationResult(None, (retained.validation,), (retained,))

        if not adapter_eligible or not adapter_supported:
            validation = self._status(
                candidate,
                kind="UNSUPPORTED_ADAPTER",
                outcome="UNSUPPORTED_ADAPTER",
                observed_data=(
                    Attribute(name="adapter_eligible", value=str(adapter_eligible).lower()),
                    Attribute(name="adapter_supported", value=str(adapter_supported).lower()),
                ),
            )
            retained = self._retain(
                candidate,
                validation,
                idempotency_key=f"compile-unsupported-adapter:{candidate.artifact_id}",
            )
            return CompilationResult(None, (retained.validation,), (retained,))

        checked = self.validator.validate(
            compilation_input,
            candidate=candidate,
            evidence=evidence,
        )
        if not checked.valid or checked.normalized_input is None:
            validation = self._status(
                candidate,
                kind="INPUT_VALIDATION",
                outcome=checked.outcome,
                observed_data=(Attribute(name="reason", value=checked.reason),),
            )
            retained = self._retain(
                candidate,
                validation,
                idempotency_key=f"compile-input-invalid:{candidate.artifact_id}:{validation.artifact_id}",
            )
            return CompilationResult(None, (retained.validation,), (retained,))

        trigger = self._status(
            candidate,
            kind="COMPILATION_TRIGGER",
            outcome="TRIGGERED",
            observed_data=(Attribute(name="compiler_version", value=self.compiler_version),),
        )
        trigger_retained = self._retain(
            candidate,
            trigger,
            idempotency_key=(idempotency_key or f"compile-trigger:{candidate.artifact_id}"),
        )
        values = checked.normalized_input
        specification = ConstrainedDeclarativeSpecification(
            version=self.compiler_version,
            created_at=datetime.now(timezone.utc),
            provenance=self._provenance(candidate, "specification"),
            candidate_record_id=candidate.artifact_id,
            role=values["role"],
            api_signature=values["api_signature"],
            parameter_positions=values["parameter_positions"],
            applicability=values["applicability"],
            taint_semantics=values["taint_semantics"],
        )
        persisted_specification = self.repository.persist_specification(
            specification,
            idempotency_key=f"compile-specification:{specification.artifact_id}",
        )
        completion = self._status(
            candidate,
            kind="COMPILATION_COMPLETION",
            outcome="COMPLETED",
            linked_artifact_ids=(
                trigger_retained.validation.artifact_id,
                persisted_specification.artifact_id,
            ),
        )
        completion_retained = self._retain(
            candidate,
            completion,
            idempotency_key=f"compile-completion:{persisted_specification.artifact_id}",
        )
        return CompilationResult(
            persisted_specification,
            (trigger_retained.validation, completion_retained.validation),
            (trigger_retained, completion_retained),
        )
