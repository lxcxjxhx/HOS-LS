"""Persist static feedback and apply validation policy."""
from .policies import apply_validation
class StaticValidationService:
    def __init__(self,repository,ledger):self.repository=repository;self.ledger=ledger
    def apply(self,record,result,policy):
        self.repository.append(result); decision=apply_validation(record,result,policy)
        return self.ledger.apply(record,decision,"static validation",policy.version,(result.artifact_id,))
