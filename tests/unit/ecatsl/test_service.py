"""Task 5.3 tests: fully wired ECATSLService orchestrator.

Covers the design-order pipeline: scope short-circuit with no downstream
artifacts, non-confirmatory discovery/catalog assistance with isolated
failures, tooling-first resolution, candidate lifecycle and policy checks,
declarative compilation, supported static validation, and confirmation only
through supported complete static ``PathEvidence``. Asserts provider/adapter
failures are audited and never bypass the confirmation gate, and that stage
records and complexity are derived from the actual assembled pipeline.

_Requirements: 1.2, 2.1-2.8, 3.7-3.9, 4.1-4.8, 5.1-5.7, 6.3, 7.1-7.6, 11.12-11.13_
"""

from datetime import datetime, timezone

from src.ecatsl.artifact_repository import ArtifactRepository
from src.ecatsl.candidate_ledger import CandidateLedger
from src.ecatsl.models import (
    AcceptancePolicy,
    Applicability,
    Attribute,
    CandidateHypothesis,
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
from src.ecatsl.scope import initial_scope
from src.ecatsl.service import AnalysisRequest, ECATSLService
from src.ecatsl.static_adapters import NormalizationOutcome, NormalizationResult

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)


def _prov(identity: str = "service") -> Provenance:
    return Provenance(
        origin="test",
        retrieved_at=NOW,
        source_identifier=identity,
        source_revision="v1",
        content_identity=identity,
        transformation_history=("service-test:v1",),
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
    def __init__(self, hypothesis=None, fail=False):
        self.hypothesis = hypothesis or _hypothesis()
        self.fail = fail

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
        return (self.hypothesis,)


class FakeAdapter:
    adapter_id = "fake-adapter"
    adapter_version = "1"

    def __init__(self, outcome=NormalizationOutcome.COMPLETE_PATH, fail=False):
        self.outcome = outcome
        self.fail = fail

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
            kind=self.outcome.value,
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


def _service(tmp_path, *, discovery=None, adapters=(), supported=()):
    database = tmp_path / "service.db"
    repository = ArtifactRepository(database, supported_static_adapters=supported)
    ledger = CandidateLedger(repository)
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
    service = ECATSLService(
        scope=initial_scope(created_at=NOW, provenance=_prov("scope")),
        provenance=_prov("service"),
        repository=repository,
        ledger=ledger,
        acceptance_policy=acceptance,
        validation_policy=validation,
        discovery=discovery,
        static_adapters=adapters,
        supported_static_adapters=supported,
    )
    return service, repository


def _request(**overrides):
    values = {
        "repository_ref": "repo://demo",
        "language": "python",
        "cwe_ids": ("CWE-89",),
    }
    values.update(overrides)
    return AnalysisRequest(**values)


def test_happy_path_confirms_only_through_complete_static_path(tmp_path):
    service, repository = _service(
        tmp_path,
        discovery=FakeDiscovery(),
        adapters=(FakeAdapter(),),
        supported=(("fake-adapter", "1"),),
    )
    result = service.analyze(_request())
    assert result.status == "COMPLETE"
    assert result.scope_result is not None
    assert len(result.hypotheses) == 1
    assert len(result.candidates) == 1
    assert len(result.specifications) == 1
    assert len(result.findings) == 1
    assert result.findings[0].status is FindingStatus.CONFIRMED
    assert result.findings[0].path_evidence_id is not None
    assert result.audit_failures == ()
    assert result.complexity is not None
    assert result.complexity.configured_adapters == 1


def test_out_of_scope_short_circuits_all_downstream_work(tmp_path):
    service, repository = _service(
        tmp_path,
        discovery=FakeDiscovery(),
        adapters=(FakeAdapter(),),
        supported=(("fake-adapter", "1"),),
    )
    result = service.analyze(_request(language="java"))
    assert result.status == "OUT_OF_SCOPE"
    assert result.scope_result is not None
    assert result.hypotheses == ()
    assert result.candidates == ()
    assert result.specifications == ()
    assert result.findings == ()
    assert result.stage_records == ()
    assert result.complexity is None


def test_no_path_result_remains_unconfirmed(tmp_path):
    service, repository = _service(
        tmp_path,
        discovery=FakeDiscovery(),
        adapters=(FakeAdapter(outcome=NormalizationOutcome.NO_PATH),),
        supported=(("fake-adapter", "1"),),
    )
    result = service.analyze(_request())
    assert len(result.findings) == 1
    assert result.findings[0].status is FindingStatus.UNCONFIRMED
    assert result.findings[0].path_evidence_id is None


def test_adapter_failure_is_audited_and_does_not_bypass_confirmation(tmp_path):
    service, repository = _service(
        tmp_path,
        discovery=FakeDiscovery(),
        adapters=(FakeAdapter(fail=True),),
        supported=(("fake-adapter", "1"),),
    )
    result = service.analyze(_request())
    assert any(failure.operation == "static_adapter" for failure in result.audit_failures)
    assert result.status == "COMPLETE"
    # The candidate/spec pipeline still completed; only the adapter failed.
    assert len(result.candidates) == 1
    assert len(result.specifications) == 1
    assert len(result.findings) == 1
    assert result.findings[0].status is FindingStatus.UNCONFIRMED


def test_discovery_failure_is_isolated_and_audited(tmp_path):
    service, repository = _service(tmp_path, discovery=FakeDiscovery(fail=True))
    result = service.analyze(_request())
    assert any(failure.operation == "discovery" for failure in result.audit_failures)
    assert result.status == "COMPLETE"
    assert result.hypotheses == ()
    assert result.candidates == ()
    assert result.findings == ()


def test_missing_supported_adapter_records_limitation_and_stays_unconfirmed(tmp_path):
    service, repository = _service(
        tmp_path,
        discovery=FakeDiscovery(),
        adapters=(FakeAdapter(),),
        supported=(),
    )
    result = service.analyze(_request())
    assert any("adapter" in item for item in result.limitations)
    assert result.specifications == ()
    assert len(result.findings) == 1
    assert result.findings[0].status is FindingStatus.UNCONFIRMED


def test_stage_records_and_complexity_from_assembled_pipeline(tmp_path):
    service, repository = _service(
        tmp_path,
        discovery=FakeDiscovery(),
        adapters=(FakeAdapter(),),
        supported=(("fake-adapter", "1"),),
    )
    result = service.analyze(_request())
    assert len(result.stage_records) >= 6
    purposes = {
        stage.transformation_purpose for stage in result.stage_records
    }
    assert {"scope gate", "controlled compilation", "confirmation"} <= purposes
    assert result.complexity is not None
    assert result.complexity.pipeline_stages == len(
        {stage.stage_identity for stage in result.stage_records}
    )
    assert result.complexity.configured_adapters == 1


def test_api_signatures_flow_through_tooling_first_resolution(tmp_path):
    from src.ecatsl.tooling_resolver import CapabilityRun, ToolingFirstResolver

    def resolved_capability(input_identity: str):
        return CapabilityRun(
            identity="sast",
            version="1",
            input_identity=input_identity,
            outcome="RESOLVED",
            latency_seconds=0.1,
        )

    resolver = ToolingFirstResolver(
        capabilities=(resolved_capability,),
        provenance=_prov("tooling"),
    )
    service, repository = _service(
        tmp_path,
        discovery=FakeDiscovery(),
        adapters=(FakeAdapter(),),
        supported=(("fake-adapter", "1"),),
    )
    service.resolver = resolver
    result = service.analyze(
        _request(api_signatures=("pkg.mod.sink", "pkg.other.api"))
    )
    assert result.status == "COMPLETE"
    assert len(result.findings) == 1
    assert result.findings[0].status is FindingStatus.CONFIRMED
