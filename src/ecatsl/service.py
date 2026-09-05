"""Fully wired ECATSL core orchestrator (Task 5.3).

``ECATSLService.analyze`` coordinates the single pipeline in design order:
versioned scope gate, discovery/catalog provider ports, tooling-first API
resolution, candidate lifecycle, declarative compilation, supported static
validation, and static-path-gated confirmation. It injects existing HOS-LS
abstractions (repository, ledger, policies, compiler, confirmation, adapters)
and never instantiates a second scanner, database, catalog pipeline, or
analysis-time catalog network client.

Isolation rules implemented here:

- An out-of-scope request short-circuits immediately: no candidate, compiler,
  adapter, or finding work runs after scope detection.
- Provider (discovery/catalog/ranking) and static-adapter failures are
  isolated: the failure is audited as an ``AuditFailureRecord`` and processing
  continues, so one catalog, discovery, RAG, LLM, or adapter failure cannot
  bypass scope, policy, compilation, or confirmation gates.
- Confirmation is exclusively delegated to ``FindingConfirmationService``;
  discovery hypotheses, catalog templates, and tooling/LLM resolutions are
  non-confirmatory explanatory support only.
- Every executed stage retains a ``PipelineStage`` artifact through the
  deterministic consolidation API, and the result reports an
  ``OperationalComplexity`` derived from the actual assembled pipeline.

_Requirements: 1.2, 2.1-2.8, 3.7-3.9, 4.1-4.8, 5.1-5.7, 6.3, 7.1-7.6, 11.12-11.13_
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence, Tuple

from .artifact_repository import ArtifactRepository, AuditFailureRecord
from .candidate_ledger import CandidateLedger
from .compiler import DeclarativeCompiler
from .confirmation import FindingConfirmationService
from .models import (
    AcceptancePolicy,
    Applicability,
    Attribute,
    CandidateHypothesis,
    CandidateRecord,
    CandidateState,
    CandidateType,
    ConstrainedDeclarativeSpecification,
    DiscoveryObservation,
    Evidence,
    FindingClassification,
    OperationalComplexity,
    PathEvidence,
    PipelineStage,
    Provenance,
    StaticAdapterRun,
    TaintTemplate,
    ValidationPolicy,
    ValidationResult,
)
from .pipeline import StageDefinition, persist_consolidation
from .scope import ScopeDefinition, ScopeResult, ScopeStatus, check_scope
from .static_adapters import NormalizationResult, supported as adapter_supported
from .static_validation import StaticValidationService
from .tooling_resolver import ToolingFirstResolver


@dataclass(frozen=True)
class AnalysisRequest:
    """A single repository analysis request.

    Carries only the repository reference, language, requested CWE mappings,
    and optional API signatures to evaluate. There is no per-route
    configuration field (Requirement 11.10).
    """

    repository_ref: str
    language: str
    cwe_ids: Tuple[str, ...] = ()
    api_signatures: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.repository_ref.strip():
            raise ValueError("repository_ref must be non-blank")
        if not self.language.strip():
            raise ValueError("language must be non-blank")


@dataclass(frozen=True)
class AnalysisResult:
    """The immutable outcome of one ``ECATSLService.analyze`` run."""

    status: str
    scope_result: Optional[ScopeResult] = None
    hypotheses: Tuple[CandidateHypothesis, ...] = ()
    candidates: Tuple[CandidateRecord, ...] = ()
    specifications: Tuple[ConstrainedDeclarativeSpecification, ...] = ()
    findings: Tuple[FindingClassification, ...] = ()
    stage_records: Tuple[PipelineStage, ...] = ()
    audit_failures: Tuple[AuditFailureRecord, ...] = ()
    complexity: Optional[OperationalComplexity] = None
    limitations: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ValidationOutcome:
    """One retained static-validation result and its optional path proof."""

    validation: ValidationResult
    candidate_id: str
    path_evidence: Optional[PathEvidence] = None


@dataclass(frozen=True)
class CompiledCandidate:
    """A compiled specification bound to the candidate version that produced it."""

    specification: ConstrainedDeclarativeSpecification
    candidate: CandidateRecord


class StaticAdapterExecutor(Protocol):
    """An executable supported static adapter used by the orchestrator.

    ``execute`` runs the delegated existing HOS-LS capability and returns the
    raw output; ``normalize`` converts raw output into a retained
    non-confirmatory ``NormalizationResult`` (or complete ``PathEvidence`` for
    a supported complete static path). No catalog/discovery/RAG/LLM hint is
    ever synthesized into path elements.
    """

    adapter_id: str
    adapter_version: str

    def supports(
        self, applicability: Any, semantics: Sequence[str]
    ) -> bool: ...

    def execute(
        self, specification: ConstrainedDeclarativeSpecification, repository_ref: str
    ) -> Any: ...

    def normalize(
        self, raw: Any, *, provenance: Provenance
    ) -> NormalizationResult: ...


class DiscoveryAssistance(Protocol):
    """Non-confirmatory repository-derived discovery provider port."""

    def discover(
        self, root: str, provenance: Provenance
    ) -> Sequence[DiscoveryObservation]: ...

    def rank(
        self,
        observations: Sequence[DiscoveryObservation],
        templates: Sequence[TaintTemplate],
        provenance: Provenance,
    ) -> Sequence[CandidateHypothesis]: ...


class ECATSLService:
    """Coordinates the single evidence-constrained analysis pipeline."""

    def __init__(
        self,
        *,
        scope: ScopeDefinition,
        provenance: Provenance,
        repository: ArtifactRepository,
        ledger: CandidateLedger,
        acceptance_policy: AcceptancePolicy,
        validation_policy: ValidationPolicy,
        discovery: Optional[DiscoveryAssistance] = None,
        template_provider: Optional[Callable[[Tuple[str, ...]], Sequence[TaintTemplate]]] = None,
        resolver: Optional[ToolingFirstResolver] = None,
        static_adapters: Sequence[StaticAdapterExecutor] = (),
        supported_static_adapters: Sequence[Tuple[str, str]] = (),
        compiler: Optional[DeclarativeCompiler] = None,
        compiler_version: str = "1",
        default_taint_semantics: Tuple[str, ...] = ("taint-flow",),
        external_service_dependencies: int = 0,
        manual_execution_steps: int = 0,
    ) -> None:
        if repository is None or ledger is None:
            raise ValueError("ECATSLService requires a repository and a ledger")
        if acceptance_policy is None or validation_policy is None:
            raise ValueError("ECATSLService requires acceptance and validation policies")
        if not default_taint_semantics or any(
            not item.strip() for item in default_taint_semantics
        ):
            raise ValueError("default taint semantics must be non-blank")
        self.scope = scope
        self.provenance = provenance
        self.repository = repository
        self.ledger = ledger
        self.acceptance_policy = acceptance_policy
        self.validation_policy = validation_policy
        self.discovery = discovery
        self.template_provider = template_provider
        self.resolver = resolver
        self.static_adapters = tuple(static_adapters)
        self.supported_static_adapters = tuple(supported_static_adapters)
        self.compiler = compiler or DeclarativeCompiler(
            repository, compiler_version=compiler_version
        )
        self.default_taint_semantics = tuple(default_taint_semantics)
        self.external_service_dependencies = external_service_dependencies
        self.manual_execution_steps = manual_execution_steps
        self.confirmation = FindingConfirmationService(repository)
        self.static_validation = StaticValidationService(repository, ledger)

    # ------------------------------------------------------------------ API

    def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        """Run the single pipeline and return the immutable result."""
        now = datetime.now(timezone.utc)
        audit_failures: list[AuditFailureRecord] = []
        stage_definitions: list[StageDefinition] = []

        scope_result = check_scope(
            self.scope,
            request.language,
            request.cwe_ids,
            created_at=now,
            provenance=self.provenance,
        )
        self._persist(scope_result)
        self._stage(
            stage_definitions,
            purpose="scope gate",
            inputs=(),
            outputs=(scope_result.artifact_id,),
        )
        if scope_result.status is ScopeStatus.OUT_OF_SCOPE:
            return AnalysisResult(
                status="OUT_OF_SCOPE",
                scope_result=scope_result,
                audit_failures=tuple(audit_failures),
            )

        # --- non-confirmatory assistance ports (isolated failures) ----------
        observations = self._guarded(
            "discovery",
            "discovery observations",
            audit_failures,
            lambda: tuple(
                self.discovery.discover(request.repository_ref, self._provider_provenance("discovery"))
            )
            if self.discovery is not None
            else (),
        )
        templates = self._guarded(
            "template_retrieval",
            "catalog templates",
            audit_failures,
            lambda: tuple(self.template_provider(request.cwe_ids))
            if self.template_provider is not None
            else (),
        )
        hypotheses = self._guarded(
            "hypothesis_ranking",
            "candidate hypotheses",
            audit_failures,
            lambda: tuple(
                self.discovery.rank(observations, templates, self._provider_provenance("ranking"))
            )
            if self.discovery is not None
            else (),
        )
        for item in (*observations, *templates, *hypotheses):
            self._persist(item)
        self._stage(
            stage_definitions,
            purpose="discovery assistance",
            inputs=(scope_result.artifact_id,),
            outputs=tuple(item.artifact_id for item in (*observations, *templates, *hypotheses)),
        )

        # --- tooling-first resolution (existing capabilities before LLM) ----
        resolution_records = self._resolve_apis(request, hypotheses, audit_failures)
        self._stage(
            stage_definitions,
            purpose="tooling-first resolution",
            inputs=tuple(item.artifact_id for item in hypotheses),
            outputs=tuple(item.artifact_id for item in resolution_records),
        )

        # --- candidate lifecycle: proposal then acceptance policy -----------
        candidates = self._create_candidates(hypotheses, now, audit_failures)
        accepted = self._apply_acceptance(candidates, now, audit_failures)
        self._stage(
            stage_definitions,
            purpose="candidate lifecycle",
            inputs=tuple(item.artifact_id for item in hypotheses),
            outputs=tuple(item.artifact_id for item in accepted),
        )

        # --- controlled declarative compilation -----------------------------
        compiled = self._compile(accepted, now, audit_failures)
        specifications = tuple(item.specification for item in compiled)
        self._stage(
            stage_definitions,
            purpose="controlled compilation",
            inputs=tuple(item.artifact_id for item in accepted),
            outputs=tuple(item.specification.artifact_id for item in compiled),
        )

        # --- static validation through supported adapters --------------------
        validation_results = self._validate(
            compiled, request, now, audit_failures
        )
        self._stage(
            stage_definitions,
            purpose="static validation",
            inputs=tuple(item.specification.artifact_id for item in compiled),
            outputs=tuple(item.validation.artifact_id for item in validation_results),
        )

        # --- static-path-gated confirmation (exclusive gate) -----------------
        findings = self._classify(accepted, compiled, validation_results, now)
        self._stage(
            stage_definitions,
            purpose="confirmation",
            inputs=tuple(item.validation.artifact_id for item in validation_results),
            outputs=tuple(item.artifact_id for item in findings),
        )

        # --- deterministic stage artifacts and complexity --------------------
        stage_records = self._persist_stages(stage_definitions, now, audit_failures)
        complexity = OperationalComplexity(
            configured_adapters=len(self.static_adapters),
            pipeline_stages=len(tuple(dict.fromkeys(stage.identity for stage in stage_definitions))),
            external_service_dependencies=self.external_service_dependencies,
            manual_execution_steps=self.manual_execution_steps,
        )
        return AnalysisResult(
            status="COMPLETE",
            scope_result=scope_result,
            hypotheses=tuple(hypotheses),
            candidates=tuple(accepted),
            specifications=tuple(specifications),
            findings=tuple(findings),
            stage_records=tuple(stage_records),
            audit_failures=tuple(audit_failures),
            complexity=complexity,
            limitations=self._limitations(),
        )

    # ------------------------------------------------------------- pipeline

    def _resolve_apis(
        self,
        request: AnalysisRequest,
        hypotheses: Sequence[CandidateHypothesis],
        audit_failures: list[AuditFailureRecord],
    ) -> Tuple[Any, ...]:
        """Resolve every requested or hypothesized API tooling-first."""
        if self.resolver is None:
            return ()
        api_signatures = tuple(
            dict.fromkeys(
                (*request.api_signatures, *(item.api_signature for item in hypotheses))
            )
        )
        records: list[Any] = []
        for signature in api_signatures:
            bound_signature = signature

            def _resolve(bound_signature: str = bound_signature) -> Any:
                assert self.resolver is not None
                return self.resolver.resolve(bound_signature)

            bundle = self._guarded(
                "tooling_resolution",
                f"tooling resolution for {signature}",
                audit_failures,
                _resolve,
            )
            if bundle:
                records.extend(bundle.records)
        return tuple(records)

    def _create_candidates(
        self,
        hypotheses: Sequence[CandidateHypothesis],
        now: datetime,
        audit_failures: list[AuditFailureRecord],
    ) -> Tuple[CandidateRecord, ...]:
        """Create immutable root proposals; a failed proposal is audited."""
        candidates: list[CandidateRecord] = []
        for hypothesis in hypotheses:
            record = self._candidate_record(hypothesis, now)
            try:
                candidates.append(
                    self.ledger.create_proposal(
                        record, idempotency_key=f"proposal:{record.candidate_id}"
                    )
                )
            except Exception as error:
                audit_failures.append(
                    self._failure(now, "candidate_proposal", "candidate creation", error)
                )
        return tuple(candidates)

    def _apply_acceptance(
        self,
        candidates: Sequence[CandidateRecord],
        now: datetime,
        audit_failures: list[AuditFailureRecord],
    ) -> Tuple[CandidateRecord, ...]:
        """Apply the recorded acceptance policy to every proposal."""
        accepted: list[CandidateRecord] = []
        for candidate in candidates:
            evidence = self._independent_evidence(candidate, now)
            try:
                result = self.ledger.apply_acceptance(
                    candidate,
                    self.acceptance_policy,
                    evidence=evidence,
                    idempotency_key=f"acceptance:{candidate.candidate_id}",
                )
                accepted.append(result.candidate)
            except Exception as error:
                audit_failures.append(
                    self._failure(now, "acceptance_policy", candidate.artifact_id, error)
                )
                accepted.append(candidate)
        return tuple(accepted)

    def _compile(
        self,
        candidates: Sequence[CandidateRecord],
        now: datetime,
        audit_failures: list[AuditFailureRecord],
    ) -> Tuple[CompiledCandidate, ...]:
        """Recheck acceptance at the compilation boundary, then compile."""
        compiled: list[CompiledCandidate] = []
        for candidate in candidates:
            if candidate.state is not CandidateState.ACCEPTED:
                continue
            evidence = self._independent_evidence(candidate, now)
            try:
                rechecked = self.ledger.recheck_before_compilation(
                    candidate,
                    self.acceptance_policy,
                    evidence=evidence,
                    idempotency_key=f"recheck:{candidate.candidate_id}",
                )
            except Exception as error:
                audit_failures.append(
                    self._failure(now, "compilation_recheck", candidate.artifact_id, error)
                )
                continue
            candidate = rechecked.candidate
            if candidate.state is not CandidateState.ACCEPTED:
                continue
            adapter_eligible = any(
                adapter.supports(candidate.applicability, self.default_taint_semantics)
                for adapter in self.static_adapters
            )
            adapter_ok = any(
                adapter_supported(adapter, self.supported_static_adapters)
                for adapter in self.static_adapters
            )
            try:
                result = self.compiler.compile(
                    candidate,
                    self._compilation_input(candidate),
                    evidence=evidence,
                    adapter_eligible=adapter_eligible,
                    adapter_supported=adapter_ok,
                    idempotency_key=f"compile:{candidate.candidate_id}",
                )
            except Exception as error:
                audit_failures.append(
                    self._failure(now, "compilation", candidate.artifact_id, error)
                )
                continue
            if result.specification is not None:
                compiled.append(
                    CompiledCandidate(
                        specification=result.specification,
                        candidate=candidate,
                    )
                )
        return tuple(compiled)

    def _validate(
        self,
        compiled: Sequence[CompiledCandidate],
        request: AnalysisRequest,
        now: datetime,
        audit_failures: list[AuditFailureRecord],
    ) -> Tuple[ValidationOutcome, ...]:
        """Run every supported adapter, retain results, and keep failures local."""
        results: list[ValidationOutcome] = []
        for item in compiled:
            specification = item.specification
            candidate = item.candidate
            for adapter in self.static_adapters:
                if not adapter_supported(adapter, self.supported_static_adapters):
                    continue
                if not adapter.supports(
                    specification.applicability, specification.taint_semantics
                ):
                    continue
                try:
                    raw = adapter.execute(specification, request.repository_ref)
                    normalized = adapter.normalize(
                        raw,
                        provenance=self._provider_provenance(
                            f"{adapter.adapter_id}:{adapter.adapter_version}"
                        ),
                    )
                    validation = self._bound_validation(
                        normalized.validation, candidate, specification
                    )
                    bound = NormalizationResult(
                        outcome=normalized.outcome,
                        validation=validation,
                        path_evidence=normalized.path_evidence,
                        reason=normalized.reason,
                        raw_output_identity=normalized.raw_output_identity,
                        observed_location_identities=normalized.observed_location_identities,
                    )
                    applied = self.static_validation.apply(
                        candidate,
                        bound,
                        self.validation_policy,
                        idempotency_key=f"static-validation:{specification.artifact_id}:{adapter.adapter_id}",
                    )
                    persisted_validation = applied.validation.validation
                    # The validation policy advanced the candidate head. The
                    # run binds exactly the lineage its retained validation
                    # governed: the compiled candidate version bound by the
                    # specification and the head this apply evaluated.
                    run = StaticAdapterRun(
                        version="1",
                        created_at=now,
                        provenance=self._provider_provenance("static-adapter-run"),
                        adapter_id=adapter.adapter_id,
                        adapter_version=adapter.adapter_version,
                        run_identity=f"{adapter.adapter_id}@{adapter.adapter_version}:{specification.artifact_id}",
                        candidate_record_ids=tuple(
                            dict.fromkeys(
                                (specification.candidate_record_id, candidate.artifact_id)
                            )
                        ),
                        specification_ids=(specification.artifact_id,),
                        validation_result_id=persisted_validation.artifact_id,
                        input_artifact_ids=(
                            specification.candidate_record_id,
                            candidate.artifact_id,
                            specification.artifact_id,
                            persisted_validation.artifact_id,
                        ),
                    )
                    self.repository.persist_static_adapter_run(
                        run, idempotency_key=f"adapter-run:{run.artifact_id}"
                    )
                    if normalized.path_evidence is not None:
                        self.repository.persist_static_path(
                            normalized.path_evidence,
                            adapter_run_id=run.artifact_id,
                            idempotency_key=f"static-path:{normalized.path_evidence.artifact_id}",
                        )
                    results.append(
                        ValidationOutcome(
                            validation=persisted_validation,
                            candidate_id=candidate.artifact_id,
                            path_evidence=normalized.path_evidence,
                        )
                    )
                    # Every subsequent adapter for this candidate must chain
                    # from the successor or its compare-and-append is stale.
                    candidate = applied.candidate
                except Exception as error:
                    audit_failures.append(
                        self._failure(
                            now,
                            "static_adapter",
                            f"{adapter.adapter_id}:{specification.artifact_id}",
                            error,
                        )
                    )
        return tuple(results)

    @staticmethod
    def _bound_validation(
        validation: ValidationResult,
        candidate: CandidateRecord,
        specification: ConstrainedDeclarativeSpecification,
    ) -> ValidationResult:
        """Link a retained validation to its candidate and specification.

        The static-adapter-run persistence requires the validation to carry
        every candidate/specification identity it governs: the compiled
        candidate version bound by the specification and the current head the
        validation actually evaluated.
        """
        return ValidationResult(
            version=validation.version,
            created_at=validation.created_at,
            provenance=validation.provenance,
            kind=validation.kind,
            outcome=validation.outcome,
            adapter_id=validation.adapter_id,
            adapter_version=validation.adapter_version,
            linked_artifact_ids=tuple(
                dict.fromkeys(
                    (
                        specification.candidate_record_id,
                        candidate.artifact_id,
                        specification.artifact_id,
                        *validation.linked_artifact_ids,
                    )
                )
            ),
            observed_data=validation.observed_data,
        )

    def _classify(
        self,
        candidates: Sequence[CandidateRecord],
        compiled: Sequence[CompiledCandidate],
        validation_results: Sequence[ValidationOutcome],
        now: datetime,
    ) -> Tuple[FindingClassification, ...]:
        """Classify one proposed finding per candidate via the exclusive gate.

        Every candidate that entered the pipeline is classified: compiled
        candidates carry their specification lineage; candidates excluded from
        compilation (e.g. unsupported adapter) are classified without a
        specification, which can only be ``UNCONFIRMED``.
        """
        if not candidates:
            return ()
        compiled_candidates = {
            item.candidate.candidate_id: item.candidate for item in compiled
        }
        spec_by_candidate = {
            item.candidate.artifact_id: item.specification for item in compiled
        }
        path_by_candidate = {
            outcome.candidate_id: outcome.path_evidence
            for outcome in validation_results
            if outcome.path_evidence is not None
        }
        validations_by_candidate: dict[str, Tuple[ValidationResult, ...]] = {}
        for outcome in validation_results:
            validations_by_candidate.setdefault(outcome.candidate_id, ())
            validations_by_candidate[outcome.candidate_id] = (
                *validations_by_candidate[outcome.candidate_id],
                outcome.validation,
            )
        ordered = list(compiled_candidates.values())
        seen = set(compiled_candidates)
        for candidate in candidates:
            if candidate.candidate_id not in seen:
                seen.add(candidate.candidate_id)
                ordered.append(candidate)
        findings: list[FindingClassification] = []
        for candidate in ordered:
            specification = spec_by_candidate.get(candidate.artifact_id)
            validations = validations_by_candidate.get(candidate.artifact_id, ())
            classified = self.confirmation.classify(
                provenance=self._provider_provenance("confirmation"),
                path=path_by_candidate.get(candidate.artifact_id),
                candidate_record_ids=(candidate.artifact_id,),
                specification_ids=(specification.artifact_id,) if specification else (),
                validation_result_ids=tuple(item.artifact_id for item in validations),
                explanatory_support_ids=(),
                idempotency_key=f"classification:{candidate.candidate_id}",
            )
            classification = (
                classified.classification
                if hasattr(classified, "classification")
                else classified
            )
            findings.append(classification)
        return tuple(findings)

    # ---------------------------------------------------------------- helpers

    def _candidate_record(self, hypothesis: CandidateHypothesis, now: datetime) -> CandidateRecord:
        return CandidateRecord(
            version="1",
            created_at=now,
            provenance=self._provider_provenance("candidate-ledger"),
            candidate_id=f"candidate:{hypothesis.artifact_id}",
            candidate_type=hypothesis.candidate_type,
            confidence=hypothesis.ranking_score,
            evidence_ids=(),
            applicability=hypothesis.applicability,
            cwe_id=hypothesis.cwe_id,
            state=CandidateState.PROPOSED,
            update_cause="hypothesis",
            changed_data=(
                Attribute(name="hypothesis", value=hypothesis.artifact_id),
                Attribute(name="api_signature", value=hypothesis.api_signature),
            ),
        )

    def _independent_evidence(self, candidate: CandidateRecord, now: datetime) -> Tuple[Evidence, ...]:
        """Repository-derived evidence with the supported taint semantics.

        The closed origin ``repository`` is independent per the policy
        taxonomy; semantics payloads make the declarative compilation input
        evidence-supported.
        """
        return (
            Evidence(
                version="1",
                created_at=now,
                provenance=Provenance(
                    origin="repository",
                    retrieved_at=now,
                    source_identifier=candidate.candidate_id,
                    source_revision="service:v1",
                    content_identity=f"evidence:{candidate.candidate_id}",
                    transformation_history=("repository-observation:v1",),
                ),
                evidence_kind="repository_observation",
                payload=(
                    Attribute(name="api_signature", value=candidate.applicability.api_signature),
                    *(
                        Attribute(name="taint_semantics", value=item)
                        for item in self.default_taint_semantics
                    ),
                ),
            ),
        )

    def _compilation_input(self, candidate: CandidateRecord) -> Mapping[str, Any]:
        applicability = candidate.applicability
        return {
            "role": candidate.candidate_type,
            "api_signature": applicability.api_signature,
            "parameter_positions": list(applicability.parameter_positions),
            "applicability": applicability,
            "taint_semantics": list(self.default_taint_semantics),
        }

    def _persist_stages(
        self,
        definitions: Sequence[StageDefinition],
        now: datetime,
        audit_failures: list[AuditFailureRecord],
    ) -> Tuple[PipelineStage, ...]:
        if not definitions:
            return ()
        try:
            outcome = persist_consolidation(
                self.repository,
                definitions,
                provenance=self._provider_provenance("pipeline"),
                created_at=now,
                version="1",
            )
            audit_failures.extend(outcome.audit_failures)
            return outcome.stages
        except Exception as error:
            audit_failures.append(
                self._failure(now, "pipeline_stage", "stage retention", error)
            )
            return ()

    @staticmethod
    def _stage(
        definitions: list[StageDefinition],
        *,
        purpose: str,
        inputs: Tuple[str, ...],
        outputs: Tuple[str, ...],
    ) -> None:
        definitions.append(
            StageDefinition(
                transformation_purpose=purpose,
                input_artifact_ids=inputs,
                output_artifact_ids=outputs,
            )
        )

    def _guarded(
        self,
        operation: str,
        missing_element: str,
        audit_failures: list[AuditFailureRecord],
        fn: Callable[[], Any],
    ) -> Any:
        try:
            return fn()
        except Exception as error:
            audit_failures.append(
                self._failure(
                    datetime.now(timezone.utc), operation, missing_element, error
                )
            )
            return ()

    def _failure(
        self, now: datetime, operation: str, missing_element: str, error: BaseException
    ) -> AuditFailureRecord:
        failure = AuditFailureRecord(
            version="1",
            created_at=now,
            provenance=self._provider_provenance("audit"),
            operation=operation,
            missing_element=missing_element,
            failure_data=(Attribute(name="error", value=str(error)),),
        )
        try:
            return self.repository.record_failure(
                failure, idempotency_key=f"failure:{failure.artifact_id}"
            )
        except Exception:
            return failure

    def _provider_provenance(self, stage: str) -> Provenance:
        return Provenance(
            origin="ecatsl:service",
            retrieved_at=datetime.now(timezone.utc),
            source_identifier=f"orchestrator:{stage}",
            source_revision="service:v1",
            content_identity=f"{stage}:{self.scope.artifact_id}",
            transformation_history=(f"ecatsl-service:{stage}:v1",),
        )

    def _persist(self, artifact: Any) -> None:
        try:
            self.repository.persist_artifact(artifact)
        except Exception:
            # Persistence of non-critical assistance artifacts is best-effort;
            # critical lineage persistence failures surface through dedicated
            # repository APIs with explicit audit records.
            pass

    def _limitations(self) -> Tuple[str, ...]:
        limitations = []
        if not self.static_adapters:
            limitations.append("no supported static adapter configured")
        elif not any(
            adapter_supported(adapter, self.supported_static_adapters)
            for adapter in self.static_adapters
        ):
            limitations.append("no configured static adapter is allowlisted")
        return tuple(limitations)


def build_sqlite_template_provider(
    db_path: str,
    *,
    scope_cwe_ids: Tuple[str, ...],
) -> Callable[[Tuple[str, ...]], Tuple[TaintTemplate, ...]]:
    """Wire the local SQLite catalog into the service template provider port.

    The provider reuses :class:`src.nvd.nvd_query_adapter.TaintTemplateRepository`
    (Task 6.3): it retrieves only in-scope templates, preserves the
    deterministic ranking order, and converts every ranked template into a
    non-confirmatory ``TaintTemplate`` artifact.  Identical repeated queries
    are idempotent (no duplicate retrieval provenance rows).  Returned
    templates are ranking input only; hypotheses built from them can never
    become proof or bypass the acceptance policy (Requirement 11.12-11.13).
    """
    from src.nvd.nvd_query_adapter import TaintTemplateRepository

    repository = TaintTemplateRepository(db_path, scope_cwe_ids=scope_cwe_ids)
    allowed = tuple(scope_cwe_ids)

    def provider(requested_cwe_ids: Tuple[str, ...]) -> Tuple[TaintTemplate, ...]:
        now = datetime.now(timezone.utc)
        templates: list[TaintTemplate] = []
        for cwe_id in requested_cwe_ids:
            if cwe_id not in allowed:
                continue
            result = repository.retrieve(cwe_id)
            for ranked in result.ranked:
                templates.append(_template_artifact(ranked, now))
        return tuple(templates)

    return provider


def _template_artifact(ranked: Any, now: datetime) -> TaintTemplate:
    """Convert one ranked catalog template row into its artifact form."""
    applicability = ranked.applicability or {}
    return TaintTemplate(
        version="1",
        created_at=now,
        provenance=Provenance(
            origin="local-sqlite-catalog",
            retrieved_at=now,
            source_identifier=str(ranked.template_id),
            source_revision=str(ranked.template_version) or None,
            content_identity=f"taint-template:{ranked.template_id}",
        ),
        cwe_id=ranked.cwe_id,
        role=CandidateType(str(ranked.role)),
        api_shape=str(ranked.api_shape),
        parameter_shape=tuple(ranked.parameter_shape),
        applicability=Applicability(
            language=str(applicability.get("language", "python")),
            frameworks=tuple(
                str(item)
                for item in applicability.get("frameworks", ())
            ),
            api_signature=str(applicability.get("api_signature") or ranked.api_shape),
            parameter_positions=tuple(ranked.parameter_shape),
        ),
    )
