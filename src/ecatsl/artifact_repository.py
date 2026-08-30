"""Append-only ECATSL tables sharing the configured SQLite catalog file."""
import sqlite3
from typing import Type
from .models import Artifact
class ArtifactRepository:
    def __init__(self,path):
        self.connection=sqlite3.connect(str(path)); self.connection.execute("CREATE TABLE IF NOT EXISTS ecatsl_artifact(artifact_id TEXT PRIMARY KEY,type TEXT NOT NULL,predecessor_id TEXT,content_hash TEXT NOT NULL,payload TEXT NOT NULL)"); self.connection.execute("CREATE TABLE IF NOT EXISTS ecatsl_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,payload TEXT)"); self.connection.commit()
    def append(self,artifact:Artifact):
        if artifact.predecessor_id and not self.connection.execute("SELECT 1 FROM ecatsl_artifact WHERE artifact_id=?",(artifact.predecessor_id,)).fetchone(): raise ValueError("missing predecessor")
        with self.connection: self.connection.execute("INSERT INTO ecatsl_artifact VALUES(?,?,?,?,?)",(artifact.artifact_id,type(artifact).__name__,artifact.predecessor_id,artifact.content_hash,artifact.canonical_json()))
        return artifact
    def load(self,artifact_id:str,model:Type[Artifact]):
        row=self.connection.execute("SELECT payload FROM ecatsl_artifact WHERE artifact_id=?",(artifact_id,)).fetchone(); return model.model_validate_json(row[0]) if row else None
    def audit_failure(self,kind,payload):
        with self.connection: self.connection.execute("INSERT INTO ecatsl_audit(kind,payload) VALUES(?,?)",(kind,str(payload)))
    def close(self): self.connection.close()
