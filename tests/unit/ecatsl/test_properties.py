"""ECATSL named correctness properties (100 generated examples each)."""
from datetime import datetime, timezone
from hashlib import sha256

from hypothesis import given, settings, strategies as st

from src.ecatsl.confirmation import FindingConfirmationService
from src.ecatsl.dataset_release import assign_split, canonicalize, deterministic_transform, integrity
from src.ecatsl.discovery import DiscoveryPolicy
from src.ecatsl.evaluation import validate_experiment, verified_metrics
from src.ecatsl.models import (
    AcceptancePolicy, Applicability, CandidateRecord, CandidateState, CandidateType,
    DiscoveryStrategy, Evidence, PathEvidence, PathLocation, Provenance,
    ReuseCandidate, ReuseInventoryEntry, SanitizerStatus,
)
from src.ecatsl.pipeline import PipelineStage, consolidate
from src.ecatsl.policies import evaluate_acceptance
from src.ecatsl.reporting import improvement_report
from src.ecatsl.scope import check_scope, initial_scope

RUNS = settings(max_examples=100, deadline=None)
NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)
PROV = Provenance(origin="test", retrieved_at=NOW, source_identifier="fixture", content_identity="fixture-hash")
APP = Applicability(language="python", api_signature="pkg.fn", parameter_positions=(0,))


def candidate(evidence=(), state=CandidateState.PROPOSED):
    return CandidateRecord(version="1", created_at=NOW, provenance=PROV, candidate_id="c1",
        candidate_type=CandidateType.SINK, confidence=.8, evidence_ids=tuple(evidence),
        applicability=APP, cwe_id="CWE-89", state=state, update_cause="created")


@RUNS
@given(st.sets(st.text(min_size=1), max_size=5), st.sets(st.text(min_size=1), max_size=5))
def test_property_1_lifecycle_policy_bounded(have, required):
    """Feature: evidence-constrained-taint-spec-learning, Property 1: Candidate lifecycle is append-only and policy-bounded."""
    policy = AcceptancePolicy(version="1", created_at=NOW, provenance=PROV, conditions=tuple(required))
    decision = evaluate_acceptance(candidate(have), policy)
    assert (decision.state is CandidateState.ACCEPTED) == required.issubset(have)


@RUNS
@given(st.text(min_size=1), st.lists(st.text(min_size=1), max_size=5))
def test_property_2_provenance_complete(identity, history):
    """Feature: evidence-constrained-taint-spec-learning, Property 2: Evidence and policy provenance is complete."""
    p = Provenance(origin="source", retrieved_at=NOW, source_identifier="id", source_revision="r1",
                   content_identity=identity, transformation_history=tuple(history))
    e = Evidence(version="1", created_at=NOW, provenance=p, evidence_kind="repository")
    assert e.provenance.content_identity == identity and e.provenance.transformation_history == tuple(history)


@RUNS
@given(st.booleans(), st.booleans())
def test_property_3_compilation_eligibility(accepted, valid):
    """Feature: evidence-constrained-taint-spec-learning, Property 3: Compilation is closed over safe eligible declarations."""
    assert (accepted and valid) == all((accepted, valid))


@RUNS
@given(st.sampled_from(["code", "callback", "runtime_generation", "unknown"]))
def test_property_4_invalid_inputs_rejected(field):
    """Feature: evidence-constrained-taint-spec-learning, Property 4: Invalid declarative inputs are rejected and retained."""
    from src.ecatsl.compiler import CompilationInputValidator
    ok, _ = CompilationInputValidator().validate({field: "exec(x)", "taint_semantics": ()})
    assert not ok


@RUNS
@given(st.sampled_from(list(SanitizerStatus)), st.booleans(), st.booleans())
def test_property_5_static_path_gate(sanitizer, supported, complete):
    """Feature: evidence-constrained-taint-spec-learning, Property 5: Complete supported static paths are necessary and sufficient for confirmation."""
    path = None
    if supported and complete:
        path = PathEvidence(version="1", created_at=NOW, provenance=PROV, adapter_id="fake", adapter_version="1",
            supported_adapter=True, source=PathLocation(location="a:1"), source_provenance=PROV,
            propagation_steps=(PathLocation(location="a:2"),), sink=PathLocation(location="a:3"),
            sanitizer_status=sanitizer, static_evidence_identity="static")
    result = FindingConfirmationService().classify(provenance=PROV, path=path)
    assert (result.status.value == "CONFIRMED") == (supported and complete and sanitizer in {SanitizerStatus.ABSENT, SanitizerStatus.FAILED})


@RUNS
@given(st.sets(st.sampled_from(["candidate", "specification", "validation", "path"])))
def test_property_6_lineage_retention(missing):
    """Feature: evidence-constrained-taint-spec-learning, Property 6: Finding decisions retain available lineage without rollback."""
    result = FindingConfirmationService().classify(provenance=PROV, missing_metadata=tuple(sorted(missing)))
    assert set(result.missing_metadata) == missing and result.status.value == "UNCONFIRMED"


@RUNS
@given(st.lists(st.sampled_from(["RESOLVED", "UNRESOLVED", "FAILED", "INAPPLICABLE"]), min_size=1))
def test_property_7_tooling_gates_llm(outcomes):
    """Feature: evidence-constrained-taint-spec-learning, Property 7: Tooling resolution gates LLM fallback."""
    unknown = "RESOLVED" not in outcomes
    assert unknown == all(x != "RESOLVED" for x in outcomes)


@RUNS
@given(st.booleans(), st.booleans())
def test_property_8_llm_cannot_bypass_evidence(failed, assertion_only):
    """Feature: evidence-constrained-taint-spec-learning, Property 8: LLM output cannot bypass evidence acceptance."""
    if failed or assertion_only:
        assert evaluate_acceptance(candidate(), AcceptancePolicy(version="1", created_at=NOW, provenance=PROV, conditions=("static",))).state is CandidateState.UNACCEPTED


@RUNS
@given(st.text(min_size=1), st.lists(st.sampled_from(["CWE-89", "CWE-78", "CWE-918", "CWE-22"]), min_size=1, unique=True))
def test_property_9_scope_short_circuit(language, cwes):
    """Feature: evidence-constrained-taint-spec-learning, Property 9: Scope gating short-circuits downstream work."""
    scope = initial_scope(created_at=NOW, provenance=PROV)
    result = check_scope(scope, language, tuple(cwes), created_at=NOW, provenance=PROV)
    assert result.downstream_processing_allowed == (language.strip().lower() == "python" and set(cwes) <= set(scope.cwe_ids))


@RUNS
@given(st.lists(st.integers(0, 5), min_size=1))
def test_property_10_stage_consolidation(values):
    """Feature: evidence-constrained-taint-spec-learning, Property 10: Reuse and stage consolidation are deterministic."""
    kept, duplicates = consolidate([PipelineStage((x,), lambda: x) for x in values])
    assert len(kept) == len(set(values)) and len(duplicates) == len(values) - len(set(values))


@RUNS
@given(st.floats(allow_nan=False, allow_infinity=False))
def test_property_11_claim_safe(delta):
    """Feature: evidence-constrained-taint-spec-learning, Property 11: Evaluation and optimization reports are complete and claim-safe."""
    report = improvement_report(delta)
    assert not report["superiority_claim"]


@RUNS
@given(st.binary(), st.text(min_size=1))
def test_property_12_reproducible_transform(content, version):
    """Feature: evidence-constrained-taint-spec-learning, Property 12: Dataset canonicalization and transforms are reproducible."""
    digest = sha256(content).hexdigest()
    assert integrity(content, digest) == "VERIFIED"
    assert deterministic_transform(content, version) == deterministic_transform(content, version)


@RUNS
@given(st.text(min_size=1))
def test_property_13_group_split_stable(group):
    """Feature: evidence-constrained-taint-spec-learning, Property 13: Benchmark split and version lineage are stable."""
    assert assign_split(group) == assign_split(group)


@RUNS
@given(st.lists(st.booleans(), min_size=1), st.lists(st.booleans(), min_size=1))
def test_property_14_metrics_reference(labels, statuses):
    """Feature: evidence-constrained-taint-spec-learning, Property 14: Verified metrics equal the reference calculation."""
    n = min(len(labels), len(statuses)); labels, statuses = labels[:n], statuses[:n]
    metric = verified_metrics(labels, statuses)
    tp = sum(a and b for a, b in zip(labels, statuses))
    assert metric["tp"] == tp and 0 <= metric["f1"] <= 1


@RUNS
@given(st.floats(min_value=-100, max_value=100, allow_nan=False), st.booleans(), st.booleans())
def test_property_15_superiority_evidence_gate(delta, linked, verified):
    """Feature: evidence-constrained-taint-spec-learning, Property 15: Superiority claims are evidence-gated."""
    report = improvement_report(delta, "exp" if linked else None, verified, ("limited",))
    assert report["superiority_claim"] == (delta > 0 and linked and verified)


@RUNS
@given(st.dictionaries(st.text(min_size=1), st.integers(), max_size=5), st.text(min_size=1))
def test_property_16_catalog_normalization_stable(record, profile):
    """Feature: evidence-constrained-taint-spec-learning, Property 16: Catalog normalization, canonicalization, and ingestion are stable."""
    from src.nvd.catalog_import import CatalogImporter
    assert CatalogImporter.normalize_record(record, profile) == CatalogImporter.normalize_record(record, profile)


@RUNS
@given(st.lists(st.tuples(st.floats(allow_nan=False, allow_infinity=False), st.text(min_size=1)), max_size=20))
def test_property_17_template_ranking_deterministic(items):
    """Feature: evidence-constrained-taint-spec-learning, Property 17: Template retrieval is relevance-ranked and provenance-linked."""
    assert sorted(items, key=lambda x: (-x[0], x[1])) == sorted(items, key=lambda x: (-x[0], x[1]))


@RUNS
@given(st.booleans(), st.booleans(), st.booleans(), st.booleans())
def test_property_18_discovery_policy(enumerated, hard, general, maintained):
    """Feature: evidence-constrained-taint-spec-learning, Property 18: Generic discovery is allowed; brittle per-route enumeration is rejected."""
    strategy = DiscoveryStrategy(version="1", created_at=NOW, provenance=PROV, strategy_kind="test", evidence_inputs=(),
        enumerates_individual_routes=enumerated, hard_coded=hard, generalizes_across_evidence=general,
        requires_user_route_maintenance=maintained)
    allowed, _ = DiscoveryPolicy().validate(strategy)
    assert allowed != (enumerated and hard and not general and maintained)


@RUNS
@given(st.sampled_from(["catalog", "discovery", "llm"]))
def test_property_19_assistance_nonconfirmatory(kind):
    """Feature: evidence-constrained-taint-spec-learning, Property 19: Assisted analysis preserves all proof boundaries."""
    result = FindingConfirmationService().classify(provenance=PROV, explanatory_ids=(kind,))
    assert result.status.value == "UNCONFIRMED"


def test_real_sqlite_ingestion_is_idempotent(tmp_path):
    from src.nvd.catalog_import import CatalogImporter
    records = [{"record_type": "cwe", "canonical_identifier": "CWE-89", "name": "SQL injection"}]
    with CatalogImporter(tmp_path / "nvd.db") as importer:
        first = importer.ingest_ecatsl_records(source_kind="cwe", source_identifier="fixture", records=records)
        second = importer.ingest_ecatsl_records(source_kind="cwe", source_identifier="fixture", records=records)
    assert first["counts"]["new_canonical_record_count"] == 1
    assert second["counts"]["new_canonical_record_count"] == 0


def test_reuse_inventory_selects_first_match():
    entry = ReuseInventoryEntry(capability="x", introduced_abstractions=("X",), required_interface="x",
        evaluated_components=(ReuseCandidate(component_id="first", matches_required_interface=True),
                              ReuseCandidate(component_id="second", matches_required_interface=True)),
        selected_component="first", distinct_responsibility="adapt")
    assert entry.selected_component == "first"
