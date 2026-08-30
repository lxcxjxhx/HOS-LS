"""Deterministic stage consolidation and complexity."""
from dataclasses import dataclass
from .models import OperationalComplexity
@dataclass(frozen=True)
class PipelineStage: identity:tuple; run:object
def consolidate(stages):
    seen=set(); kept=[]; duplicates=[]
    for stage in stages:
        if stage.identity in seen: duplicates.append(stage.identity)
        else: seen.add(stage.identity); kept.append(stage)
    return tuple(kept),tuple(duplicates)
def complexity(adapters,stages,dependencies=0,manual_steps=0): return OperationalComplexity(configured_adapters=len(adapters),pipeline_stages=len(stages),external_service_dependencies=dependencies,manual_execution_steps=manual_steps)
