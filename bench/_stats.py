"""统计 VulnGym 数据资产"""
import json
from collections import Counter
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

with open('datasets/VulnGym/data/entries.jsonl', 'r', encoding='utf-8') as f:
    entries = [json.loads(l) for l in f]

print(f"=== VulnGym 数据总览 ===")
print(f"Total entries: {len(entries)}")

# Language
langs = Counter(e.get('language','unknown') for e in entries)
print(f"\nLanguages: {dict(langs)}")

# Vuln type
vtypes = Counter(e.get('vuln_category_l1','unknown') for e in entries)
print(f"\nVulnerability types (L1):")
for k, v in vtypes.most_common():
    print(f"  {k}: {v}")

# Entry type
etypes = Counter(e.get('entry_type','unknown') for e in entries)
print(f"\nEntry types: {dict(etypes)}")

# Projects
projects = Counter(e.get('project','unknown') for e in entries)
print(f"\nProjects ({len(projects)} total):")
for p, cnt in projects.most_common(15):
    print(f"  {p}: {cnt} entries")
if len(projects) > 15:
    print(f"  ... and {len(projects)-15} more")

# Advisories/CVEs
advisories = set()
cves = set()
for e in entries:
    a = e.get('advisory_id') or e.get('cve_id')
    if a: advisories.add(a)
    if e.get('cve_id'): cves.add(e.get('cve_id'))
print(f"\nUnique advisories: {len(advisories)}")
print(f"Unique CVEs: {len(cves)}")

# Code length
code_field = None
for e in entries:
    if e.get('critical_operation',{}).get('code'):
        code_field = 'critical_operation.code'
        break
    elif e.get('code'):
        code_field = 'code'
        break
    elif e.get('snippet'):
        code_field = 'snippet'
        break

if code_field:
    if code_field == 'critical_operation.code':
        lengths = [len(e['critical_operation']['code']) for e in entries if e.get('critical_operation',{}).get('code')]
    else:
        lengths = [len(e.get(code_field, '')) for e in entries]
    lengths.sort()
    print(f"\nCode from '{code_field}':")
    print(f"  Count: {len(lengths)}")
    print(f"  Min: {min(lengths)}, Max: {max(lengths)}")
    print(f"  Mean: {sum(lengths)/len(lengths):.0f}")
    print(f"  Median: {lengths[len(lengths)//2]}")
    print(f"  P25: {lengths[len(lengths)//4]}, P75: {lengths[3*len(lengths)//4]}")

# Has context
has_context = sum(1 for e in entries if e.get('context') or e.get('code_context'))
print(f"\nEntries with context: {has_context}/{len(entries)}")

# Trace info
has_trace = sum(1 for e in entries if e.get('trace') or e.get('entry_point'))
print(f"Entries with trace/entry_point: {has_trace}/{len(entries)}")

# EP/CO/Trace classification
ep = sum(1 for e in entries if e.get('entry_type') == 'EP')
co = sum(1 for e in entries if e.get('entry_type') == 'CO')
trace = sum(1 for e in entries if e.get('entry_type') == 'TRACE')
print(f"\nEP/CO/TRACE classification:")
print(f"  Entry Point: {ep}")
print(f"  Critical Op: {co}")
print(f"  Trace: {trace}")
print(f"  Other: {len(entries) - ep - co - trace}")

# Static-detectable subset (simple heuristics)
static_keywords = ['SQL注入','命令注入','XSS','路径遍历','文件包含','SSRF','代码注入']
static = sum(1 for e in entries if e.get('vuln_category_l1') in static_keywords)
print(f"\nRough static-detectable: {static}/{len(entries)}")

# Write a summary to file
summary = {
    "total_entries": len(entries),
    "projects": len(projects),
    "advisories": len(advisories),
    "cves": len(cves),
    "languages": dict(langs),
    "entry_types": dict(etypes),
    "vuln_types": dict(vtypes.most_common()),
    "code_field_used": code_field,
    "code_length_stats": {
        "count": len(lengths) if code_field else 0,
        "min": min(lengths) if code_field else 0,
        "max": max(lengths) if code_field else 0,
        "mean": sum(lengths)/len(lengths) if code_field else 0,
        "median": sorted(lengths)[len(lengths)//2] if code_field else 0,
    },
    "has_context": has_context,
    "has_trace": has_trace,
    "static_detectable_estimate": static,
}

os.makedirs('artifacts', exist_ok=True)
with open('artifacts/vulngym_stats.json', 'w', encoding='utf-8') as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)
print(f"\nSummary saved to artifacts/vulngym_stats.json")
