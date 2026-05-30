"""Tool Orchestrator Module

Orchestrates multiple scanning tools (CodeVulnScanner, SemgrepScanner, SafetyScanner)
and merges/deduplicates their results.
"""

import os
import difflib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set

from src.utils.logger import get_logger

logger = get_logger(__name__)

JAVA_EXTENSIONS = {'.java', '.kt', '.kts', '.xml', '.gradle', '.gradle.kts'}
PYTHON_EXTENSIONS = {'.py', '.pyi', '.pyx', '.pyw'}
JS_EXTENSIONS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
DEPENDENCY_FILE_NAMES = {
    'requirements.txt', 'Pipfile', 'Pipfile.lock', 'setup.py', 'pyproject.toml',
    'pom.xml', 'build.gradle', 'build.gradle.kts',
    'package.json', 'package-lock.json', 'yarn.lock',
    'go.mod', 'go.sum',
    'Gemfile', 'Gemfile.lock',
    'Cargo.toml', 'Cargo.lock',
    'composer.json', 'composer.lock',
}


SOURCE_PREFERENCE = {
    'semgrep': 0,
    'rules': 1,
    'safety': 2,
}

SOURCE_CONFIDENCE = {
    'semgrep': 0.85,
    'rules': 0.7,
    'safety': 0.90,
}


class ToolOrchestrator:
    """Orchestrates multiple scanning tools and merges results"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logger

        self._semgrep_scanner = None
        self._safety_scanner = None
        self._semgrep_available = False
        self._safety_available = False

        self._init_scanners()

    def _detect_project_file_types(self, target_path: str) -> Set[str]:
        file_types: Set[str] = set()
        target_path_str = str(target_path)
        target = Path(target_path_str)
        for root_dir, _, files in os.walk(target_path_str):
            for filename in files:
                file_path = Path(root_dir) / filename
                suffix = file_path.suffix.lower()
                filename_lower = filename.lower()
                if suffix in JAVA_EXTENSIONS:
                    file_types.add('java')
                if suffix in PYTHON_EXTENSIONS:
                    file_types.add('python')
                if suffix in JS_EXTENSIONS:
                    file_types.add('javascript')
                if filename_lower in DEPENDENCY_FILE_NAMES:
                    if filename_lower in ('requirements.txt', 'Pipfile', 'Pipfile.lock', 'setup.py', 'pyproject.toml'):
                        file_types.add('python')
                    elif filename_lower in ('pom.xml', 'build.gradle', 'build.gradle.kts'):
                        file_types.add('java')
                    elif filename_lower in ('package.json', 'package-lock.json', 'yarn.lock'):
                        file_types.add('javascript')
        return file_types

    def _init_scanners(self) -> None:
        self._init_semgrep()
        self._init_safety()

    def _init_semgrep(self) -> None:
        try:
            from src.scanners.semgrep_scanner import SemgrepScanner
            scanner = SemgrepScanner()
            if scanner.is_available():
                self._semgrep_scanner = scanner
                self._semgrep_available = True
                self.logger.debug("SemgrepScanner initialized and available")
            else:
                self.logger.debug("SemgrepScanner initialized but not available (semgrep not installed)")
        except Exception as e:
            self.logger.debug(f"SemgrepScanner not available: {e}")
            self._semgrep_available = False

    def _init_safety(self) -> None:
        try:
            from src.scanners.safety_scanner import SafetyScanner
            scanner = SafetyScanner()
            if scanner.is_available():
                self._safety_scanner = scanner
                self._safety_available = True
                self.logger.debug("SafetyScanner initialized and available")
            else:
                self.logger.debug("SafetyScanner initialized but not available (safety not installed)")
        except Exception as e:
            self.logger.debug(f"SafetyScanner not available: {e}")
            self._safety_available = False

    def scan_project(self, target_path: str) -> Dict[str, Any]:
        target_path_str = str(target_path)
        target = Path(target_path_str)

        if not target.exists():
            self.logger.error(f"Target path does not exist: {target_path_str}")
            raise FileNotFoundError(f"Target path does not exist: {target_path_str}")

        file_types = self._detect_project_file_types(target_path_str)
        self.logger.info(f"Detected project file types: {file_types}")

        all_findings: List[Dict[str, Any]] = []
        sources_count: Dict[str, int] = {
            'rules': 0,
            'semgrep': 0,
            'safety': 0,
        }

        self.logger.info(f"Starting tool orchestration scan on: {target_path_str}")

        run_semgrep = self._semgrep_available and bool(file_types & {'java', 'javascript', 'python'})
        run_safety = self._safety_available and 'python' in file_types

        rules_findings = self._run_rules_scanner(target_path_str)
        sources_count['rules'] = len(rules_findings)
        all_findings.extend(rules_findings)
        self.logger.info(f"Rules scanner completed: {len(rules_findings)} findings")

        if run_semgrep:
            semgrep_findings = self._run_semgrep_scanner(target_path_str)
            sources_count['semgrep'] = len(semgrep_findings)
            all_findings.extend(semgrep_findings)
            self.logger.info(f"Semgrep scanner completed: {len(semgrep_findings)} findings")
        else:
            self.logger.info("Semgrep scanner skipped (not applicable for this project type)")

        if run_safety:
            safety_findings = self._run_safety_scanner(target_path_str)
            sources_count['safety'] = len(safety_findings)
            all_findings.extend(safety_findings)
            self.logger.info(f"Safety scanner completed: {len(safety_findings)} findings")
        else:
            self.logger.info("Safety scanner skipped (not applicable for this project type)")

        total_raw = sum(sources_count.values())
        deduplicated = self._deduplicate_findings(all_findings)
        dedup_count = total_raw - len(deduplicated)

        self.logger.info(
            f"Scan complete: {total_raw} raw findings, "
            f"{len(deduplicated)} after deduplication ({dedup_count} duplicates removed)"
        )

        return {
            'findings': deduplicated,
            'sources': sources_count,
            'deduplicated_count': dedup_count,
            'total_raw_count': total_raw,
            'semgrep_available': self._semgrep_available,
            'safety_available': self._safety_available,
        }

    def _run_rules_scanner(self, target_path: str) -> List[Dict[str, Any]]:
        try:
            from src.analyzers.code_vuln_scanner import CodeVulnScanner
            scanner = CodeVulnScanner(
                enable_verification=False,
                project_root=target_path,
            )
            return self._scan_directory_with_rules(scanner, target_path)
        except Exception as e:
            self.logger.error(f"Rules scanner failed: {e}")
            return []

    def _scan_directory_with_rules(
        self, scanner: Any, target_path: str
    ) -> List[Dict[str, Any]]:
        findings = []
        target = Path(target_path)
        code_extensions = scanner.CODE_EXTENSIONS if hasattr(scanner, 'CODE_EXTENSIONS') else {
            '.java', '.py', '.js', '.ts', '.jsx', '.tsx', '.xml', '.go', '.rs', '.rb', '.php', '.c', '.cpp', '.h'
        }

        try:
            for root_dir, _, files in os.walk(target_path):
                for filename in files:
                    file_path = Path(root_dir) / filename
                    file_path_str = str(file_path)
                    if file_path.suffix.lower() in code_extensions:
                        try:
                            file_findings = scanner.scan_file(file_path_str)
                            for f in file_findings:
                                findings.append(self._rules_finding_to_dict(f, file_path_str))
                        except Exception as e:
                            self.logger.debug(f"Failed to scan file {file_path_str}: {e}")
        except Exception as e:
            self.logger.error(f"Directory scan failed: {e}")

        return findings

    def _rules_finding_to_dict(self, finding: Any, file_path: str) -> Dict[str, Any]:
        vuln_type = finding.vuln_type if hasattr(finding, 'vuln_type') else 'unknown'
        level = finding.level.value if hasattr(finding, 'level') and hasattr(finding.level, 'value') else str(getattr(finding, 'level', 'medium'))
        description = finding.description if hasattr(finding, 'description') else ''
        code_snippet = finding.code_snippet if hasattr(finding, 'code_snippet') else ''
        remediation = finding.remediation if hasattr(finding, 'remediation') else ''
        line_number = finding.line_number if hasattr(finding, 'line_number') else 0

        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info',
        }

        return {
            'file': os.path.relpath(str(file_path)),
            'line': line_number,
            'column': 0,
            'vuln_type': vuln_type,
            'cwe': vuln_type,
            'severity': severity_map.get(level.lower(), 'medium'),
            'message': description,
            'code_snippet': code_snippet[:200],
            'confidence': SOURCE_CONFIDENCE['rules'],
            'fix_suggestion': remediation,
            'metadata': {
                'source': 'rules',
                'rule_id': vuln_type,
            }
        }

    def _run_semgrep_scanner(self, target_path: str) -> List[Dict[str, Any]]:
        if self._semgrep_scanner is None:
            return []
        try:
            raw_findings = self._semgrep_scanner.scan(target_path)
            for f in raw_findings:
                if 'file' in f:
                    f['file'] = os.path.relpath(str(f['file']))
                f.setdefault('source', 'semgrep')
                f.setdefault('metadata', {})['source'] = 'semgrep'
                f.setdefault('confidence', SOURCE_CONFIDENCE['semgrep'])
                f.setdefault('cwe', f.get('vuln_type', ''))
            return raw_findings
        except Exception as e:
            self.logger.error(f"Semgrep scanner failed: {e}")
            return []

    def _run_safety_scanner(self, target_path: str) -> List[Dict[str, Any]]:
        if self._safety_scanner is None:
            return []
        try:
            raw_findings = self._safety_scanner.scan(target_path)
            for f in raw_findings:
                if 'file' in f:
                    f['file'] = os.path.relpath(str(f['file']))
                f.setdefault('source', 'safety')
                f.setdefault('metadata', {})['source'] = 'safety'
                f.setdefault('confidence', SOURCE_CONFIDENCE['safety'])
                f.setdefault('cwe', f.get('vuln_type', ''))
            return raw_findings
        except Exception as e:
            self.logger.error(f"Safety scanner failed: {e}")
            return []

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        groups: Dict[str, List[Dict[str, Any]]] = {}

        for finding in findings:
            key = self._get_dedup_key(finding)
            if key not in groups:
                groups[key] = []
            groups[key].append(finding)

        deduplicated = []
        for key, group in groups.items():
            if len(group) == 1:
                kept = group[0]
                kept['sources'] = [kept.get('metadata', {}).get('source', 'unknown')]
                deduplicated.append(kept)
            else:
                best = self._select_best_finding(group)
                all_sources = [f.get('metadata', {}).get('source', 'unknown') for f in group]
                best['sources'] = list(dict.fromkeys(all_sources))
                best = self._apply_cross_verification(group, best)
                deduplicated.append(best)

        return self._semantic_dedup_pass(deduplicated)

    def _get_dedup_key(self, finding: Dict[str, Any]) -> str:
        file_path = str(finding.get('file', ''))
        normalized_path = os.path.normpath(file_path)
        line = finding.get('line', 0)
        vuln_type = finding.get('cwe', '') or finding.get('vuln_type', '')
        return f"{normalized_path}:{line}:{vuln_type}"

    def _select_best_finding(self, group: List[Dict[str, Any]]) -> Dict[str, Any]:
        def sort_key(f: Dict[str, Any]) -> Tuple[float, int]:
            source = f.get('metadata', {}).get('source', 'unknown')
            if 'source' not in f.get('metadata', {}):
                source = f.get('source', 'unknown')
            preference = SOURCE_PREFERENCE.get(source, 999)
            confidence = f.get('confidence', 0.0)
            return (-confidence, preference)

        sorted_group = sorted(group, key=sort_key)
        return sorted_group[0]

    def _compute_similarity(self, s1: str, s2: str) -> float:
        return difflib.SequenceMatcher(None, str(s1), str(s2)).ratio()

    def _normalize_file_path(self, file_path: str) -> str:
        return os.path.normpath(str(file_path))

    def _semantic_match(self, f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        vuln_type1 = f1.get('vuln_type', '') or f1.get('cwe', '')
        vuln_type2 = f2.get('vuln_type', '') or f2.get('cwe', '')
        if vuln_type1 != vuln_type2:
            return False

        file1 = self._normalize_file_path(f1.get('file', ''))
        file2 = self._normalize_file_path(f2.get('file', ''))
        if file1 != file2:
            return False

        line1 = int(f1.get('line', 0))
        line2 = int(f2.get('line', 0))
        if abs(line1 - line2) > 10:
            return False

        snippet1 = f1.get('code_snippet', '')
        snippet2 = f2.get('code_snippet', '')
        if not snippet1 or not snippet2:
            return False

        return self._compute_similarity(snippet1, snippet2) >= 0.8

    def _apply_cross_verification(self, group: List[Dict[str, Any]], best: Dict[str, Any]) -> Dict[str, Any]:
        unique_sources = list(dict.fromkeys([
            f.get('metadata', {}).get('source', 'unknown') for f in group
        ]))

        if len(unique_sources) >= 2:
            boost = min(0.05 * (len(unique_sources) - 1), 0.99 - best.get('confidence', 0.0))
            best['confidence'] = best.get('confidence', 0.0) + boost
            if 'metadata' not in best:
                best['metadata'] = {}
            best['metadata']['cross_verified'] = True
            best['metadata']['verifying_sources'] = unique_sources

        return best

    def _semantic_dedup_pass(self, deduplicated: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if len(deduplicated) <= 1:
            return deduplicated

        merged_indices = set()
        final_results = []

        for i, finding in enumerate(deduplicated):
            if i in merged_indices:
                continue

            similar_group = [finding]
            for j in range(i + 1, len(deduplicated)):
                if j in merged_indices:
                    continue
                if self._semantic_match(finding, deduplicated[j]):
                    similar_group.append(deduplicated[j])
                    merged_indices.add(j)

            if len(similar_group) > 1:
                best = self._select_best_finding(similar_group)
                all_sources = list(dict.fromkeys([
                    f.get('metadata', {}).get('source', 'unknown') for f in similar_group
                ]))
                if 'metadata' not in best:
                    best['metadata'] = {}
                best['metadata']['merged_from'] = [
                    {'file': f.get('file', ''), 'line': f.get('line', 0), 'source': f.get('metadata', {}).get('source', 'unknown')}
                    for f in similar_group if f is not best
                ]
                best['sources'] = all_sources
                final_results.append(best)
            else:
                final_results.append(finding)

        return final_results
