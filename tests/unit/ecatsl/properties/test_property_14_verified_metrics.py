"""Feature: evidence-constrained-taint-spec-learning, Property 14 tests.

Property 14: Verified metrics equal the reference calculation.
Generate vulnerable/fixed/clean labels, verified statuses, and strata and
compare every non-empty result to a reference confusion matrix.

Validates: Requirements 10.1-10.4.
"""

from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from src.ecatsl.dataset_release import build_release  # noqa: E402
from src.ecatsl.evaluation import (  # noqa: E402
    SAMPLE_CLASSES,
    STRATUM_DIMENSIONS,
    build_evaluation_report,
    verified_metrics,
)
from src.ecatsl.models import (  # noqa: E402
    Attribute,
    BenchmarkManifest,
    ConfusionMatrix,
    EvaluationTelemetry,
    FindingStatus,
    OperationalComplexity,
    Provenance,
)

OFFSET_TIME = datetime(2026, 2, 3, 12, 30, tzinfo=timezone(timedelta(hours=5)))

_LABELS = st.sampled_from(("vulnerable", "fixed", "clean"))
_STATUSES = st.sampled_from((FindingStatus.CONFIRMED, FindingStatus.UNCONFIRMED, None))
_PROJECTS = st.sampled_from(("proj-a", "proj-b", "proj-c"))
_LANGUAGES = st.sampled_from(("python", "java", ""))
_FRAMEWORKS = st.sampled_from(("flask", "django", ""))
_CWES = st.sampled_from(("CWE-89", "CWE-78", "CWE-918", ""))


def provenance() -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=OFFSET_TIME,
        source_identifier="bench/datasets/VulnGym",
        source_revision="v0.1.4",
        content_identity="dataset:v1",
    )


def telemetry() -> EvaluationTelemetry:
    return EvaluationTelemetry(
        latency_seconds=0.0,
        llm_tokens=0,
        llm_monetary_cost=0.0,
        complexity=OperationalComplexity(
            configured_adapters=0,
            pipeline_stages=0,
            external_service_dependencies=0,
            manual_execution_steps=0,
        ),
    )


@st.composite
def _case(draw):
    """Labels, verified statuses, and full per-sample stratum attributes."""
    size = draw(st.integers(min_value=1, max_value=10))
    labels = [draw(_LABELS) for _ in range(size)]
    statuses = [draw(_STATUSES) for _ in range(size)]
    projects = [draw(_PROJECTS) for _ in range(size)]
    languages = [draw(_LANGUAGES) for _ in range(size)]
    frameworks = [draw(_FRAMEWORKS) for _ in range(size)]
    cwes = [draw(_CWES) for _ in range(size)]
    return labels, statuses, projects, languages, frameworks, cwes


def _reference_matrix(labels, statuses):
    """Independent reference confusion matrix (Req 10.1)."""
    tp = fp = fn = tn = 0
    for label, status in zip(labels, statuses):
        predicted = status is not None and status == FindingStatus.CONFIRMED
        vulnerable = label == "vulnerable"
        if vulnerable and predicted:
            tp += 1
        elif predicted:
            fp += 1
        elif vulnerable:
            fn += 1
        else:
            tn += 1
    return ConfusionMatrix(tp=tp, fp=fp, fn=fn, tn=tn)


def _build(labels, statuses, projects, languages, frameworks, cwes):
    rows = []
    attributes = []
    for index in range(len(labels)):
        rid = f"r{index}"
        rows.append(
            dict(
                id=rid,
                content=rid.encode(),
                content_hash=sha256(rid.encode()).hexdigest(),
                classification=labels[index],
                project_id=projects[index],
                project_time_group=f"{projects[index]}:t1",
            )
        )
        attributes.append(Attribute(name=f"project_id:{rid}", value=projects[index]))
        attributes.append(
            Attribute(name=f"classification:{rid}", value=labels[index])
        )
        if languages[index]:
            attributes.append(Attribute(name=f"language:{rid}", value=languages[index]))
        if frameworks[index]:
            attributes.append(
                Attribute(name=f"framework:{rid}", value=frameworks[index])
            )
        if cwes[index]:
            attributes.append(Attribute(name=f"cwe:{rid}", value=cwes[index]))
    manifest, quality = build_release(
        rows,
        version="1",
        created_at=OFFSET_TIME,
        provenance=provenance(),
        data_type="vulngym_entry",
    )
    manifest = BenchmarkManifest(
        version=manifest.version,
        created_at=manifest.created_at,
        provenance=manifest.provenance,
        samples=manifest.samples,
        catalog_record_ids=manifest.catalog_record_ids,
        split_assignments=manifest.split_assignments,
        sample_attributes=tuple(attributes),
    )
    classifications = {
        f"r{i}": status for i, status in enumerate(statuses) if status is not None
    }
    report = build_evaluation_report(
        manifest,
        quality,
        classifications,
        version="1",
        created_at=OFFSET_TIME,
        provenance=provenance(),
        telemetry=telemetry(),
    )
    return report


def _stratum_case(parts, index, labels, projects, languages, frameworks, cwes):
    """Does sample ``index`` belong to the stratum parsed from ``parts``?"""
    if "cwe" in parts and parts["cwe"] != cwes[index]:
        return False
    if "language" in parts and parts["language"] != languages[index]:
        return False
    if "framework" in parts and parts["framework"] != frameworks[index]:
        return False
    if "project" in parts and parts["project"] != projects[index]:
        return False
    if "sample_class" in parts and parts["sample_class"] != labels[index]:
        return False
    return True


@settings(max_examples=100, deadline=None)
@given(case=_case())
def test_property_14_verified_metrics_equal_reference(case):
    """Feature: evidence-constrained-taint-spec-learning, Property 14: every reported metric, global and per-stratum, equals the reference confusion-matrix calculation (Req 10.1-10.4)."""
    labels, statuses, projects, languages, frameworks, cwes = case
    report = _build(labels, statuses, projects, languages, frameworks, cwes)

    reference = _reference_matrix(labels, statuses)
    reference_metrics = verified_metrics(reference)
    reported = {
        a.name: float(a.value) for a in report.verified_metrics if ":" not in a.name
    }
    assert (reported["tp"], reported["fp"], reported["fn"], reported["tn"]) == (
        reference.tp, reference.fp, reference.fn, reference.tn,
    )
    for name in ("precision", "recall", "f1"):
        assert reported[name] == reference_metrics[name]
    # Zero-inclusive: zero denominators yield 0.0, never errors or omissions.
    assert reported["sample_count"] == float(len(labels))
    confirmed = reference.tp + reference.fp
    assert reported["confirmed"] == float(confirmed)
    for name in ("precision", "recall", "f1", "tp", "fp", "fn", "tn"):
        assert name in reported

    # Every reported stratum is non-empty and disjoint per definition.
    keys = [s.key for s in report.strata]
    assert len(keys) == len(set(keys))
    for stratum in report.strata:
        parts = dict(part.split("=", 1) for part in stratum.definition)
        assert all(dim in STRATUM_DIMENSIONS for dim in parts)
        matching = [
            index
            for index in range(len(labels))
            if _stratum_case(parts, index, labels, projects, languages, frameworks, cwes)
        ]
        assert matching, "every reported stratum must contain at least one sample"
        assert stratum.sample_count == len(matching)
        assert stratum.sample_ids == tuple(f"r{i}" for i in matching)
        stratum_reference = _reference_matrix(
            [labels[i] for i in matching], [statuses[i] for i in matching]
        )
        assert (stratum.matrix.tp, stratum.matrix.fp,
                stratum.matrix.fn, stratum.matrix.tn) == (
            stratum_reference.tp, stratum_reference.fp,
            stratum_reference.fn, stratum_reference.tn,
        )
        stratum_metrics = verified_metrics(stratum_reference)
        assert stratum.precision == stratum_metrics["precision"]
        assert stratum.recall == stratum_metrics["recall"]
        assert stratum.f1 == stratum_metrics["f1"]

    # Every populated dimension value has exactly one stratum (Req 10.2).
    expected = set()
    for dim, values in (
        ("project", projects),
        ("language", languages),
        ("framework", frameworks),
        ("cwe", cwes),
        ("sample_class", labels),
    ):
        expected.update(f"{dim}={v}" for v in values if v)
    assert set(keys) == expected
    # Sample-class taxonomy is the paired benchmark contract (Req 9.2).
    assert SAMPLE_CLASSES == ("vulnerable", "fixed", "clean")
