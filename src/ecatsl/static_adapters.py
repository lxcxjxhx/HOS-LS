"""Thin adapters over existing InputTracer and SastPrefilter."""
from datetime import datetime,timezone
from .models import PathEvidence,PathLocation,SanitizerStatus,ValidationResult
class InputTracerAdapter:
    adapter_id="input-tracer"; version="1"
    def __init__(self,tracer): self.tracer=tracer
    def supports(self,applicability,semantics): return applicability.language=="python"
    def analyze(self,spec,repository_ref,provenance):
        raw=self.tracer.trace_controllability(repository_ref,spec.api_signature,0)
        path=getattr(raw,"path",None) or getattr(raw,"trace_path",None)
        if not path or len(path)<2:return ValidationResult(version="1",created_at=datetime.now(timezone.utc),provenance=provenance,kind="NO_PATH",outcome="unreachable",adapter_id=self.adapter_id,adapter_version=self.version)
        return PathEvidence(version="1",created_at=datetime.now(timezone.utc),provenance=provenance,adapter_id=self.adapter_id,adapter_version=self.version,supported_adapter=True,source=PathLocation(location=str(path[0])),source_provenance=provenance,propagation_steps=tuple(PathLocation(location=str(x)) for x in path[1:-1]) or (PathLocation(location=str(path[0])),),sink=PathLocation(location=str(path[-1])),sanitizer_status=SanitizerStatus.ABSENT,static_evidence_identity=str(getattr(raw,"evidence_id","trace")))
class CodeQLSastAdapter:
    adapter_id="sast-prefilter-codeql"; version="1"
    def __init__(self,prefilter): self.prefilter=prefilter
    def supports(self,applicability,semantics): return applicability.language=="python"
    def analyze(self,spec,repository_ref,provenance): return self.prefilter.cascade(repository_ref,[])
