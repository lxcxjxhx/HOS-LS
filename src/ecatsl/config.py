"""ECATSL configuration validation."""
from pydantic import BaseModel,ConfigDict,Field,model_validator
from .scope import INITIAL_CWES,INITIAL_LANGUAGE
class ECATSLConfig(BaseModel):
    model_config=ConfigDict(extra="forbid",frozen=True)
    database_path:str; language:str=INITIAL_LANGUAGE; cwe_ids:tuple[str,...]=INITIAL_CWES
    discovery_strategies:tuple[dict,...]=(); confirmation_provider:str="static_adapter"
    @model_validator(mode="after")
    def boundaries(self):
        if self.language!=INITIAL_LANGUAGE or tuple(self.cwe_ids)!=INITIAL_CWES: raise ValueError("unsupported initial scope")
        if self.confirmation_provider!="static_adapter": raise ValueError("only static adapters may confirm")
        for item in self.discovery_strategies:
            if item.get("routes"): raise ValueError("user-authored per-route configuration unsupported")
        return self
