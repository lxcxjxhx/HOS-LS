"""Framework-neutral, hypothesis-only discovery."""
import ast
from datetime import datetime,timezone
from hashlib import sha256
from pathlib import Path
from .models import CandidateHypothesis,CandidateType,DiscoveryObservation
class DiscoveryPolicy:
    def validate(self,strategy):
        rejected=strategy.enumerates_individual_routes and strategy.hard_coded and not strategy.generalizes_across_evidence and strategy.requires_user_route_maintenance
        return not rejected,"brittle user-maintained per-route enumeration" if rejected else "allowed generic discovery"
class DiscoveryAssistance:
    def discover(self,root,provenance):
        out=[]
        for path in sorted(Path(root).rglob("*.py")):
            text=path.read_text(encoding="utf-8",errors="ignore")
            try: tree=ast.parse(text)
            except SyntaxError: continue
            for node in ast.walk(tree):
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    out.append(DiscoveryObservation(version="1",created_at=datetime.now(timezone.utc),provenance=provenance,derivation_kind="repository_code",locations=(f"{path}:{node.lineno}",),source_content_identities=(sha256(text.encode()).hexdigest(),),producer="python-ast",producer_version="1"))
        return out
    def rank(self,observations,templates,provenance):
        ranked=[]
        for o in observations:
            for t in templates:
                ranked.append(CandidateHypothesis(version="1",created_at=datetime.now(timezone.utc),provenance=provenance,candidate_type=t.role,api_signature=t.api_shape,applicability=t.applicability,cwe_id=t.cwe_id,evidence_ids=(o.artifact_id,t.artifact_id),ranking_score=1.0,ranking_profile_version="1"))
        return ranked
