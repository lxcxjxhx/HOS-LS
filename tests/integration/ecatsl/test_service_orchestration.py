"""Task 5.4 integration tests: ECATSLService orchestration and failure isolation.

Exercises the fully wired orchestrator over a real on-disk artifact repository
and asserts stage order and retained artifacts for every design failure mode:
happy path, out-of-scope short-circuit, unsupported adapter, catalog outage,
discovery failure, LLM failure, adapter exception, acceptance-policy
persistence failure, classification metadata failure, and restart/replay.
Provider/adapter failures stay audited and local; confirmation is reached only
through complete supported static ``PathEvidence``.

_Requirements: 5.1-5.7, 3.7-3.9_
"""

from datetime import datetime, timezone

from src.ecatsl.artifact_repository import (
    ArtifactRepository,
    OptionalMetadataPersistenceError,
)
from src.ecatsl.candidate_ledger import CandidateLedger
from src.ecatsl.models import (
    AcceptancePolicy,
    Applicability,
    Attribute,
    CandidateHypothesis,
    CandidateState,
    CandidateType,
    DiscoveryObservation,
    FindingStatus,
    PathEvidence,
    PathLocation,
    Provenance,
    SanitizerStatus,
    ValidationPolicy,
    ValidationResult,
)
from src.ecatsl.scope import ScopeResult, initial_scope
from src.ecatsl.service import AnalysisRequest, ECATSLService
from src.ecatsl.static_adapters import NormalizationOutcome, NormalizationResult
from src.ecatsl.tooling_resolver import CapabilityRun, ToolingFirstResolver

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)

SUPPORTED = (("fake-adapter", "1"),)

EXPECTED_STAGE_ORDER = (
    "scope gate",
    "discovery assistance",
    "tooling-first resolution",
    "candidate lifecycle",
    "controlled compilation",
    "static validation",
    "confirmation",
)


def _prov(identity: str) -> Provenance:
    return Provenance(
        origin="test",
        retrieved_at=NOW,
        source_identifier=identity,
        source_revision="v1",
        content_identity=identity,
        transformation_history=("orchestration-test:v1",),
    )


def _hypothesis(api: str = "pkg.mod.sink") -> CandidateHypothesis:
    return CandidateHypothesis(
        version="1",
        created_at=NOW,
        provenance=_prov("hypothesis"),
        candidate_type=CandidateType.SINK,
        api_signature=api,
        applicability=Applicability(
            language="python", api_signature=api, parameter_positions=(0,)
        ),
        cwe_id="CWE-89",
        evidence_ids=(),
        ranking_score=0.8,
        ranking_profile_version="v1",
    )


class FakeDiscovery:
    def __init__(self, fail=False, api="pkg.mod.sink"):
        self.fail = fail
        self.api = api

    def discover(self, root, provenance):
        if self.fail:
            raise RuntimeError("discovery outage")
        return (
            DiscoveryObservation(
                version="1",
                created_at=NOW,
                provenance=_prov("observation"),
                derivation_kind="call-graph",
                locations=("app.py:1",),
                source_content_identities=("app.py:1",),
                producer="fake-discovery",
                producer_version="1",
            ),
        )

    def rank(self, observations, templates, provenance):
        if self.fail or not observations:
            return ()
        return (_hypothesis(self.api),)


class FakeAdapter:
    adapter_id = "fake-adapter"
    adapter_version = "1"

    def __init__(self, fail=False, outcome=NormalizationOutcome.COMPLETE_PATH):
        self.fail = fail
        self.outcome = outcome

    def supports(self, applicability, semantics):
        return True

    def execute(self, specification, repository_ref):
        if self.fail:
            raise RuntimeError("adapter outage")
        return {"raw": True}

    def normalize(self, raw, *, provenance):
        validation = ValidationResult(
            version="1",
            created_at=NOW,
            provenance=provenance,
            kind="static_path",
            outcome=self.outcome.value,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            linked_artifact_ids=(),
            observed_data=(),
        )
        path = None
        if self.outcome is NormalizationOutcome.COMPLETE_PATH:
            path = PathEvidence(
                version="1",
                created_at=NOW,
                provenance=provenance,
                adapter_id=self.adapter_id,
                adapter_version=self.adapter_version,
                supported_adapter=True,
                source=PathLocation(location="app.py:1", symbol="src"),
                source_provenance=provenance,
                propagation_steps=(PathLocation(location="app.py:2"),),
                sink=PathLocation(location="app.py:3", symbol="sink"),
                sanitizer_status=SanitizerStatus.ABSENT,
                static_evidence_identity="raw-identity",
            )
        return NormalizationResult(
            outcome=self.outcome,
            validation=validation,
            path_evidence=path,
            reason="",
            raw_output_identity="raw-identity",
            observed_location_identities=("app.py:1",),
        )


def _policies():
    acceptance = AcceptancePolicy(
        version="1",
        created_at=NOW,
        provenance=_prov("acceptance"),
        conditions=("independent_evidence",),
    )
    validation = ValidationPolicy(
        version="1",
        created_at=NOW,
        provenance=_prov("validation"),
        result_mappings=(
            Attribute(name="COMPLETE_PATH", value="PRESERVE"),
            Attribute(name="NO_PATH", value="UNACCEPT"),
            Attribute(name="*", value="UNACCEPT"),
        ),
    )
    return acceptance, validation


def _repository(tmp_path, name="orchestration.db", supported=SUPPORTED):
    return ArtifactRepository(tmp_path / name, supported_static_adapters=supported)


def _service(repository, *, discovery=None, adapters=(), supported=SUPPORTED,
             template_provider=None, resolver=None):
    acceptance, validation = _policies()
    return ECATSLService(
        scope=initial_scope(created_at=NOW, provenance=_prov("scope")),
        provenance=_prov("service"),
        repository=repository,
        ledger=CandidateLedger(repository),
        acceptance_policy=acceptance,
        validation_policy=validation,
        discovery=discovery,
        template_provider=template_provider,
        static_adapters=adapters,
        supported_static_adapters=supported,
        resolver=resolver,
    )


def _wired(repository, discovery, adapters=(FakeAdapter(),), **overrides):
    return _service(repository, discovery=discovery, adapters=adapters, **overrides)


def _request(**overrides):
    values = {
        "repository_ref": "repo://demo",
        "language": "python",
        "cwe_ids": ("CWE-89",),
    }
    values.update(overrides)
    return AnalysisRequest(**values)


def _count(repository, table, where="", params=()):
    return int(
        repository.connection.execute(
            f"SELECT COUNT(*) FROM {table} {where}", params
        ).fetchone()[0]
    )


def _stage_purposes(result):
    return tuple(stage.transformation_purpose for stage in result.stage_records)


class _FrozenDatetime(datetime):
    """Deterministic clock so a replayed analyze reproduces committed content."""

    @classmethod
    def now(cls, tz=None):
        return NOW if tz is not None else NOW.replace(tzinfo=None)


def _freeze_pipeline_clock(monkeypatch):
    for module in ("service", "candidate_ledger", "compiler", "confirmation"):
        monkeypatch.setattr(f"src.ecatsl.{module}.datetime", _FrozenDatetime)


# --------------------------------------------------------------- happy path


def test_happy_path_stage_order_and_retained_artifacts(tmp_path):
    repository = _repository(tmp_path)
    try:
        result = _wired(repository, FakeDiscovery()).analyze(_request())

        assert result.status == "COMPLETE"
        assert result.audit_failures == ()
        assert result.limitations == ()
        assert _stage_purposes(result) == EXPECTED_STAGE_ORDER
        assert result.candidates[0].state is CandidateState.ACCEPTED
        assert result.findings[0].status is FindingStatus.CONFIRMED
        assert result.findings[0].path_evidence_id is not None
        assert result.complexity.configured_adapters == 1
        # Every stage output identity is retained and reloadable from SQLite.
        for stage in result.stage_records:
            for artifact_id in stage.output_artifact_ids:
                assert repository.load(artifact_id).artifact_id == artifact_id
        assert _count(repository, "ecatsl_path_evidence") >= 1
    finally:
        repository.close()


def test_restart_replay_reproduces_committed_artifacts(tmp_path, monkeypatch):
    """Reopen the same database and replay the request through a new service."""
    _freeze_pipeline_clock(monkeypatch)
    database = tmp_path / "replay.db"
    first_repository = ArtifactRepository(database, supported_static_adapters=SUPPORTED)
    first = _wired(first_repository, FakeDiscovery()).analyze(_request())
    first_repository.close()

    second_repository = ArtifactRepository(database, supported_static_adapters=SUPPORTED)
    try:
        second = _wired(second_repository, FakeDiscovery()).analyze(_request())

        assert second.status == "COMPLETE"
        assert second.audit_failures == ()
        assert [stage.artifact_id for stage in second.stage_records] == [
            stage.artifact_id for stage in first.stage_records
        ]
        assert [item.artifact_id for item in second.candidates] == [
            item.artifact_id for item in first.candidates
        ]
        assert [item.artifact_id for item in second.specifications] == [
            item.artifact_id for item in first.specifications
        ]
        assert [item.artifact_id for item in second.findings] == [
            item.artifact_id for item in first.findings
        ]
        assert second.findings[0].status is FindingStatus.CONFIRMED
        # Restart persistence: the first run's classification survives reopen.
        reloaded = second_repository.load(
            first.findings[0].artifact_id, type(first.findings[0])
        )
        assert reloaded.status is FindingStatus.CONFIRMED
    finally:
        second_repository.close()


# ------------------------------------------------------------- short circuit


def test_out_of_scope_retains_scope_only(tmp_path):
    repository = _repository(tmp_path)
    try:
        result = _wired(repository, FakeDiscovery()).analyze(_request(language="java"))

        assert result.status == "OUT_OF_SCOPE"
        assert result.hypotheses == ()
        assert result.candidates == ()
        assert result.specifications == ()
        assert result.findings == ()
        assert result.stage_records == ()
        assert result.complexity is None
        assert _count(repository, "ecatsl_candidate_version") == 0
        retained = repository.load(result.scope_result.artifact_id, ScopeResult)
        assert retained.status.value == "OUT_OF_SCOPE"
    finally:
        repository.close()


# ------------------------------------------------------- unsupported adapter


def test_unsupported_adapter_stays_unconfirmed_without_path(tmp_path):
    repository = _repository(tmp_path, supported=())
    try:
        result = _wired(repository, FakeDiscovery(), supported=()).analyze(_request())

        assert result.status == "COMPLETE"
        assert any("adapter" in item for item in result.limitations)
        assert result.specifications == ()
        assert result.candidates[0].state is CandidateState.ACCEPTED
        assert result.findings[0].status is FindingStatus.UNCONFIRMED
        assert result.findings[0].path_evidence_id is None
        assert _count(repository, "ecatsl_path_evidence") == 0
    finally:
        repository.close()


# ------------------------------------------------------- assistance failures


def test_assistance_only_support_never_confirms_without_static_path(tmp_path):
    """Catalog/discovery/LLM support is explanatory; only a complete static
    path confirms. The same fully assisted request stays unconfirmed with a
    NO_PATH outcome and confirms with one complete supported static path."""
    repository = _repository(tmp_path)

    def unresolved_capability(input_identity):
        return CapabilityRun(
            identity="static-suite",
            version="1",
            input_identity=input_identity,
            outcome="UNRESOLVED",
            latency_seconds=0.1,
        )

    resolver = ToolingFirstResolver(
        capabilities=(unresolved_capability,),
        repository=repository,
        provenance=_prov("tooling"),
    )
    try:
        unconfirmed = _wired(
            repository,
            FakeDiscovery(api="pkg.one.sink"),
            adapters=(FakeAdapter(outcome=NormalizationOutcome.NO_PATH),),
            resolver=resolver,
        ).analyze(_request(api_signatures=("pkg.one.sink",)))
        assert unconfirmed.status == "COMPLETE"
        assert unconfirmed.audit_failures == ()
        assert unconfirmed.findings[0].status is FindingStatus.UNCONFIRMED
        assert unconfirmed.findings[0].path_evidence_id is None

        confirming = _wired(
            repository,
            FakeDiscovery(api="pkg.two.sink"),
            adapters=(FakeAdapter(),),
            resolver=resolver,
        ).analyze(_request(api_signatures=("pkg.two.sink",)))
        assert confirming.findings[0].status is FindingStatus.CONFIRMED
        assert confirming.findings[0].path_evidence_id is not None
    finally:
        repository.close()


def test_catalog_outage_is_audited_and_gates_hold(tmp_path):
    repository = _repository(tmp_path)

    def exploding_templates(cwe_ids):
        raise RuntimeError("catalog outage")

    try:
        outcome = _wired(
            repository, FakeDiscovery(), template_provider=exploding_templates
        ).analyze(_request())

        assert any(
            failure.operation == "template_retrieval"
            for failure in outcome.audit_failures
        )
        assert outcome.status == "COMPLETE"
        assert len(outcome.hypotheses) == 1
        assert outcome.findings[0].status is FindingStatus.CONFIRMED
        assert outcome.findings[0].explanatory_support_ids == ()
    finally:
        repository.close()


def test_discovery_failure_is_audited_and_downstream_empty(tmp_path):
    repository = _repository(tmp_path)
    try:
        outcome = _wired(repository, FakeDiscovery(fail=True)).analyze(_request())

        operations = {failure.operation for failure in outcome.audit_failures}
        assert "discovery" in operations
        assert outcome.status == "COMPLETE"
        assert outcome.hypotheses == ()
        assert outcome.candidates == ()
        assert outcome.findings == ()
        assert _stage_purposes(outcome) == EXPECTED_STAGE_ORDER
    finally:
        repository.close()


def test_llm_failure_is_audited_and_gates_hold(tmp_path):
    repository = _repository(tmp_path)

    def unresolved_capability(input_identity):
        return CapabilityRun(
            identity="static-suite",
            version="1",
            input_identity=input_identity,
            outcome="UNRESOLVED",
            latency_seconds=0.1,
        )

    def exploding_llm(records):
        raise RuntimeError("LLM outage")

    resolver = ToolingFirstResolver(
        capabilities=(unresolved_capability,),
        llm=exploding_llm,
        repository=repository,
        provenance=_prov("tooling"),
    )
    try:
        outcome = _wired(repository, FakeDiscovery(), resolver=resolver).analyze(
            _request(api_signatures=("pkg.mod.sink",))
        )

        assert any(
            failure.operation == "tooling_resolution"
            for failure in outcome.audit_failures
        )
        assert outcome.status == "COMPLETE"
        assert outcome.findings[0].status is FindingStatus.CONFIRMED
        # Terminal tooling telemetry was retained before the LLM attempt failed.
        assert _count(
            repository,
            "ecatsl_artifact",
            "WHERE artifact_type LIKE '%ToolingResolutionRecord%'",
        ) >= 1
    finally:
        repository.close()


# ------------------------------------------------------------ adapter outage


def test_adapter_exception_is_audited_and_confirmation_gate_holds(tmp_path):
    repository = _repository(tmp_path)
    try:
        outcome = _wired(
            repository, FakeDiscovery(), adapters=(FakeAdapter(fail=True),)
        ).analyze(_request())

        assert any(
            failure.operation == "static_adapter"
            for failure in outcome.audit_failures
        )
        assert outcome.status == "COMPLETE"
        assert len(outcome.candidates) == 1
        assert len(outcome.specifications) == 1
        assert outcome.findings[0].status is FindingStatus.UNCONFIRMED
        assert outcome.findings[0].path_evidence_id is None
        assert _count(repository, "ecatsl_path_evidence") == 0
    finally:
        repository.close()


# --------------------------------------------------- policy/metadata failure


def test_policy_persistence_failure_preserves_accepted_outcome(tmp_path):
    def policy_hook(point, transaction_id):
        if point == "policy.optional_audit_metadata":
            raise OptionalMetadataPersistenceError("acceptance_evidence")

    repository = ArtifactRepository.for_testing(
        tmp_path / "policy.db", failure_hook=policy_hook,
        supported_static_adapters=SUPPORTED,
    )
    try:
        outcome = _wired(repository, FakeDiscovery()).analyze(_request())

        assert outcome.status == "COMPLETE"
        assert outcome.candidates[0].state is CandidateState.ACCEPTED
        assert "acceptance_evidence" in outcome.candidates[0].missing_audit_elements
        assert outcome.findings[0].status is FindingStatus.CONFIRMED
        assert _count(
            repository, "ecatsl_audit_failure", "WHERE operation = 'policy_audit'"
        ) >= 1
    finally:
        repository.close()


def test_classification_metadata_failure_flags_missing_elements(tmp_path):
    def metadata_hook(point, transaction_id):
        if point == "classification.optional_audit_metadata":
            raise OptionalMetadataPersistenceError("path_evidence:app.py:1")

    repository = ArtifactRepository.for_testing(
        tmp_path / "metadata.db", failure_hook=metadata_hook,
        supported_static_adapters=SUPPORTED,
    )
    try:
        outcome = _wired(repository, FakeDiscovery()).analyze(_request())

        finding = outcome.findings[0]
        assert finding.status is FindingStatus.CONFIRMED
        assert finding.missing_metadata == ("path_evidence:app.py:1",)
        assert finding.path_evidence_id is not None
        assert finding.candidate_record_ids
        assert finding.specification_ids
        assert _count(repository, "ecatsl_finding_lineage") >= 1
    finally:
        repository.close()
