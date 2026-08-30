"""End-to-end ECATSL proof-boundary smoke coverage."""
from datetime import datetime, timezone

from src.ecatsl.confirmation import FindingConfirmationService
from src.ecatsl.discovery import DiscoveryAssistance
from src.ecatsl.models import PathEvidence, PathLocation, Provenance, SanitizerStatus
from src.ecatsl.scope import initial_scope
from src.ecatsl.service import AnalysisRequest, ECATSLService

NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)
PROV = Provenance(origin="smoke", retrieved_at=NOW, source_identifier="repo", content_identity="repo-hash")


def test_discovery_alone_is_unconfirmed_and_scope_is_shipped(tmp_path):
    (tmp_path / "app.py").write_text("def endpoint(value):\n    return value\n", encoding="utf-8")
    scope = initial_scope(created_at=NOW, provenance=PROV)
    service = ECATSLService(scope, PROV, discovery=DiscoveryAssistance(), templates=lambda _: [])
    result = service.analyze(AnalysisRequest(str(tmp_path), "python", ("CWE-89",)))
    assert result.status == "COMPLETE"
    assert result.findings[0].status.value == "UNCONFIRMED"
    assert scope.language == "python" and len(scope.cwe_ids) == 3


def test_only_supported_complete_static_path_confirms():
    path = PathEvidence(version="1", created_at=NOW, provenance=PROV,
        adapter_id="fake-supported-static", adapter_version="1", supported_adapter=True,
        source=PathLocation(location="app.py:1", symbol="endpoint"), source_provenance=PROV,
        propagation_steps=(PathLocation(location="app.py:2", symbol="value"),),
        sink=PathLocation(location="app.py:3", symbol="execute"),
        sanitizer_status=SanitizerStatus.ABSENT, static_evidence_identity="sarif:path:1")
    result = FindingConfirmationService().classify(provenance=PROV, path=path)
    assert result.status.value == "CONFIRMED"


def test_out_of_scope_stops_before_discovery():
    class MustNotRun:
        def discover(self, *_):
            raise AssertionError("downstream discovery ran")
    service = ECATSLService(initial_scope(created_at=NOW, provenance=PROV), PROV, discovery=MustNotRun())
    result = service.analyze(AnalysisRequest("repo", "javascript", ("CWE-89",)))
    assert result.status == "OUT_OF_SCOPE" and not result.findings
