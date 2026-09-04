"""Generic repository discovery and discovery-policy validation (Task 6.4).

Covers Requirements 1.4, 4.2-4.3, 7.1-7.3, 11.9-11.13: framework-agnostic
code/config/import-graph discovery without route configuration, rejection of
exactly the brittle enumerated strategies, provenance-linked non-confirmatory
observations and hypotheses, and per-run data-quality telemetry.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.ecatsl.discovery import (
    DERIVATION_KINDS,
    RANKING_PROFILE_VERSION,
    DiscoveryPolicy,
    DiscoveryTelemetry,
    RepositoryDiscovery,
)
from src.ecatsl.models import (
    Applicability,
    CandidateHypothesis,
    CandidateType,
    DiscoveryObservation,
    DiscoveryStrategy,
    Provenance,
    TaintTemplate,
)

NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)


def _prov(label: str) -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=NOW,
        source_identifier=label,
        source_revision="v1",
        content_identity=label,
    )


def _template(
    api_shape: str, cwe_id: str, role: CandidateType, language: str = "python"
) -> TaintTemplate:
    return TaintTemplate(
        version="1",
        created_at=NOW,
        provenance=_prov(api_shape),
        cwe_id=cwe_id,
        role=role,
        api_shape=api_shape,
        applicability=Applicability(language=language, api_signature=api_shape),
        semantic_features=("sql",),
    )


def _strategy(**overrides) -> DiscoveryStrategy:
    traits = {
        "enumerates_individual_routes": True,
        "hard_coded": True,
        "generalizes_across_evidence": False,
        "requires_user_route_maintenance": True,
    }
    traits.update(overrides)
    return DiscoveryStrategy(
        version="1",
        created_at=NOW,
        provenance=_prov("strategy"),
        strategy_kind="route-list",
        evidence_inputs=(),
        **traits,
    )


def _repository(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import json\n"
        "import helpers\n"
        "\n"
        "def helper():\n"
        "    return 1\n"
        "\n"
        "@app.route('/x')\n"
        "def handler(request):\n"
        "    return json.dumps({})\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    handler(None)\n"
    )
    (tmp_path / "helpers.py").write_text("VALUE = 1\n")
    (tmp_path / "broken.py").write_text("def broken(:\n")
    (tmp_path / "config.json").write_text(
        json.dumps({"api_path": "/api/v1", "endpoint": "/health", "database": "x"})
    )
    (tmp_path / "settings.ini").write_text(
        "url_prefix = https://example.test\n[extra]\nother = 1\n"
    )
    (tmp_path / "bad.json").write_text("{not json")
    (tmp_path / "notes.txt").write_text("not scanned\n")
    return tmp_path


def test_discovery_policy_rejects_exactly_brittle_enumeration():
    policy = DiscoveryPolicy()
    allowed, reason = policy.validate(_strategy())
    assert allowed is False
    assert "per-route" in reason

    for override in (
        {"enumerates_individual_routes": False},
        {"hard_coded": False},
        {"generalizes_across_evidence": True},
        {"requires_user_route_maintenance": False},
    ):
        allowed, _ = policy.validate(_strategy(**override))
        assert allowed is True

    # Trait mappings are accepted as well as strategy artifacts.
    allowed, _ = policy.validate(
        {
            "enumerates_individual_routes": False,
            "hard_coded": True,
            "generalizes_across_evidence": False,
            "requires_user_route_maintenance": True,
        }
    )
    assert allowed is True


def test_discover_emits_code_entrypoint_and_import_observations(tmp_path):
    root = _repository(tmp_path)
    discovery = RepositoryDiscovery()
    provenance = _prov("discovery")
    observations = discovery.discover(str(root), provenance)

    by_kind = {}
    for observation in observations:
        by_kind.setdefault(observation.derivation_kind, []).append(observation)
        assert observation.provenance == provenance
        assert observation.derivation_kind in DERIVATION_KINDS
        assert observation.source_content_identities

    names = {
        attribute.value
        for observation in by_kind.get("repository_code", [])
        for attribute in observation.context
        if attribute.name == "name"
    }
    assert "helper" in names
    assert "handler" in names
    kinds = {
        attribute.value
        for observation in by_kind.get("repository_code", [])
        for attribute in observation.context
        if attribute.name == "kind"
    }
    assert "function" in kinds
    assert "entrypoint" in kinds
    assert "__main__ entrypoint" in names

    import_obs = by_kind.get("repository_import_graph", [])
    assert import_obs, "local import edges must be surfaced as call-graph input"
    imports = {
        attribute.value
        for observation in import_obs
        for attribute in observation.context
        if attribute.name == "imports"
    }
    assert any("helpers" in value for value in imports)

    # Every observation is non-confirmatory by model contract.
    assert all(observation.confirmatory is False for observation in observations)


def test_discover_finds_config_entrypoints_without_route_lists(tmp_path):
    root = _repository(tmp_path)
    discovery = RepositoryDiscovery()
    observations = discovery.discover(str(root), _prov("discovery"))

    config_observations = [
        observation
        for observation in observations
        if observation.derivation_kind == "repository_config"
    ]
    assert len(config_observations) == 2  # config.json and settings.ini
    values = {
        attribute.value
        for observation in config_observations
        for attribute in observation.context
        if attribute.name == "values"
    }
    joined = ",".join(sorted(values))
    assert "/api/v1" in joined
    assert "/health" in joined
    assert "https://example.test" in joined
    # Values that are not endpoint keys are ignored.
    assert "x" not in joined.split(",")


def test_discovery_telemetry_counts_files(tmp_path):
    root = _repository(tmp_path)
    discovery = RepositoryDiscovery()
    discovery.discover(str(root), _prov("discovery"))
    telemetry = discovery.last_telemetry
    assert isinstance(telemetry, DiscoveryTelemetry)
    # 2 python files parsed, broken.py invalid, bad.json invalid,
    # 2 configs parsed, notes.txt skipped.
    assert telemetry.parsed == 4
    assert telemetry.invalid == 2
    assert telemetry.skipped == 1
    assert telemetry.failed == 0
    assert telemetry.total_files == telemetry.files_scanned
    assert telemetry.observations == len(
        discovery.discover(str(root), _prov("discovery"))
    )


def test_rank_pairs_observations_with_templates_deterministically(tmp_path):
    discovery = RepositoryDiscovery()
    root = tmp_path / "single.py"
    root.write_text("def handler():\n    return 1\n")
    observations = discovery.discover(str(root), _prov("discovery"))
    templates = (
        _template("sink_89()", "CWE-89", CandidateType.SINK),
        _template("source_78()", "CWE-78", CandidateType.SOURCE, language="java"),
    )
    provenance = _prov("ranking")
    hypotheses = discovery.rank(observations, templates, provenance)

    assert len(hypotheses) == len(observations) * len(templates)
    assert all(isinstance(item, CandidateHypothesis) for item in hypotheses)
    assert all(item.confirmatory is False for item in hypotheses)
    assert all(
        item.ranking_profile_version == RANKING_PROFILE_VERSION
        for item in hypotheses
    )
    # Deterministic ordering: final score desc, then identity tie-breaks.
    keys = [
        (-item.ranking_score, item.cwe_id, item.api_signature, item.evidence_ids)
        for item in hypotheses
    ]
    assert keys == sorted(keys)
    for hypothesis in hypotheses:
        assert hypothesis.candidate_type in {CandidateType.SINK, CandidateType.SOURCE}
        assert len(hypothesis.evidence_ids) == 2

    assert discovery.rank(observations, (), provenance) == ()


def test_rank_score_combines_catalog_rank_applicability_and_observation(tmp_path):
    discovery = RepositoryDiscovery(language="python")
    root = tmp_path / "single.py"
    root.write_text(
        "import json\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    return json.dumps({})\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    handler()\n"
    )
    observations = discovery.discover(str(root), _prov("discovery"))
    entrypoint = next(
        observation
        for observation in observations
        if any(
            attribute.name == "kind" and attribute.value == "entrypoint"
            for attribute in observation.context
        )
    )
    functions = [
        observation
        for observation in observations
        if all(
            attribute.value != "entrypoint"
            for attribute in observation.context
            if attribute.name == "kind"
        )
    ]
    templates = (
        _template("first_89()", "CWE-89", CandidateType.SOURCE),
        _template("second_89()", "CWE-89", CandidateType.SOURCE, language="java"),
    )
    hypotheses = discovery.rank(
        (entrypoint, *functions), templates, _prov("ranking")
    )
    by_key = {
        (item.api_signature, item.evidence_ids): item for item in hypotheses
    }
    first_entrypoint = by_key[("first_89()", (entrypoint.artifact_id, templates[0].artifact_id))]
    second_entrypoint = by_key[
        ("second_89()", (entrypoint.artifact_id, templates[1].artifact_id))
    ]
    # Catalog rank 1.0 + language match 1.0 + entrypoint weight 1.0.
    assert first_entrypoint.ranking_score == pytest.approx(1.0)
    # Second template: catalog rank 0.5 and java applicability 0.0.
    expected_second = 0.4 * 0.5 + 0.3 * 0.0 + 0.3 * 1.0
    assert second_entrypoint.ranking_score == pytest.approx(expected_second)
    # Function observations rank below the entrypoint for the same template.
    function_first = by_key[
        ("first_89()", (functions[0].artifact_id, templates[0].artifact_id))
    ]
    assert function_first.ranking_score < first_entrypoint.ranking_score
    # Deterministic across repeated ranking.
    again = discovery.rank(
        (entrypoint, *functions), templates, _prov("ranking")
    )
    assert [item.ranking_score for item in again] == [
        item.ranking_score for item in hypotheses
    ]


def test_rank_ignores_unknown_derivation_kinds(tmp_path):
    discovery = RepositoryDiscovery()
    observation = DiscoveryObservation(
        version="1",
        created_at=NOW,
        provenance=_prov("observation"),
        derivation_kind="unknown-kind",
        locations=("x.py:1",),
        source_content_identities=("identity",),
        producer="test",
        producer_version="1",
    )
    templates = (_template("src_89()", "CWE-89", CandidateType.SOURCE),)
    assert discovery.rank((observation,), templates, _prov("ranking")) == ()
