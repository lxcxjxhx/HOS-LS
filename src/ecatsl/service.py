"""Minimal ECATSL orchestration with an early scope gate."""
from dataclasses import dataclass
from datetime import datetime,timezone
from .scope import check_scope,ScopeStatus
from .confirmation import FindingConfirmationService
@dataclass(frozen=True)
class AnalysisRequest: repository_ref:str; language:str; cwe_ids:tuple[str,...]
@dataclass(frozen=True)
class AnalysisResult: status:str; hypotheses:tuple=(); findings:tuple=(); artifacts:tuple=()
class ECATSLService:
    def __init__(self,scope,provenance,discovery=None,templates=None,adapter=None):
        self.scope=scope;self.provenance=provenance;self.discovery=discovery;self.templates=templates;self.adapter=adapter
    def analyze(self,request):
        gate=check_scope(self.scope,request.language,request.cwe_ids,created_at=datetime.now(timezone.utc),provenance=self.provenance)
        if gate.status is ScopeStatus.OUT_OF_SCOPE:return AnalysisResult("OUT_OF_SCOPE",artifacts=(gate,))
        observations=self.discovery.discover(request.repository_ref,self.provenance) if self.discovery else []
        templates=self.templates(request.cwe_ids) if self.templates else []
        hypotheses=self.discovery.rank(observations,templates,self.provenance) if self.discovery else []
        path=self.adapter(hypotheses) if self.adapter and hypotheses else None
        finding=FindingConfirmationService().classify(provenance=self.provenance,path=path,explanatory_ids=tuple(h.artifact_id for h in hypotheses))
        return AnalysisResult("COMPLETE",tuple(hypotheses),(finding,),(gate,))
