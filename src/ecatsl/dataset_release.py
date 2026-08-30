"""Reproducible benchmark release helpers."""
from hashlib import sha256
def integrity(content,expected): return "VERIFIED" if sha256(content).hexdigest()==expected else "FAILED"
def deterministic_transform(content,version): return sha256(version.encode()+b"\0"+content).hexdigest()
def canonicalize(records):
    canonical={}; duplicates={}
    for record in records:
        key=(record["content_hash"],record["data_type"])
        if key in canonical: duplicates.setdefault(canonical[key]["id"],[]).append(record["id"])
        else: canonical[key]=record
    return tuple(canonical.values()),duplicates
def assign_split(project_time_group): return ("train","validation","evaluation")[int(sha256(project_time_group.encode()).hexdigest(),16)%3]
