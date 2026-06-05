"""Safety SCA (Software Composition Analysis) Scanner

Integrates pyup.io/safety for Python dependency vulnerability scanning.
Supports CVE enrichment via NVDQueryAdapter for CWE details.

Cross-platform compliant: all path operations use str() conversion,
subprocess uses list format, and pathlib for path operations.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class SafetyScanner:
    """Safety SCA scanner for Python dependency vulnerabilities

    Runs safety check against requirements.txt, pyproject.toml, Pipfile,
    or installed packages and returns HOS-LS formatted findings.
    """

    PYTHON_DEP_FILES = [
        'requirements.txt',
        'requirements-dev.txt',
        'requirements_test.txt',
        'setup.py',
        'pyproject.toml',
        'Pipfile',
        'Pipfile.lock',
        'poetry.lock',
    ]

    def __init__(self, nvd_adapter=None):
        """Initialize SafetyScanner

        Args:
            nvd_adapter: Optional NVDQueryAdapter instance for CVE enrichment.
                        Accepts either src.nvd.nvd_query_adapter.NVDQueryAdapter
                        or src.vuln_data.nvd_adapter.NVDAdapter.
        """
        self.nvd_adapter = nvd_adapter
        self._available_cache = None

    @staticmethod
    def is_available() -> bool:
        """Check if safety CLI tool is installed and available

        Returns:
            True if safety is available, False otherwise
        """
        if shutil.which('safety') is not None:
            return True
        try:
            import safety
            return True
        except ImportError:
            return False

    def _detect_python_project(self, target_path: str) -> Optional[str]:
        """Detect if target is a Python project and find the best requirements file

        Args:
            target_path: Path to the project directory or file

        Returns:
            Path to the requirements file if found, None otherwise
        """
        target_path_str = str(target_path)
        target = Path(target_path_str)

        if target.is_file():
            if target.name in self.PYTHON_DEP_FILES:
                return str(target)
            target = target.parent

        if not target.is_dir():
            return None

        priority_files = [
            'requirements.txt',
            'requirements-dev.txt',
            'Pipfile',
            'Pipfile.lock',
            'poetry.lock',
            'pyproject.toml',
            'setup.py',
        ]

        for filename in priority_files:
            candidate = target / filename
            if candidate.is_file() and candidate.stat().st_size > 0:
                return str(candidate)

        for filename in self.PYTHON_DEP_FILES:
            for child in target.rglob(filename):
                if child.is_file() and child.stat().st_size > 0:
                    return str(child)

        return None

    def scan(self, target_path: str) -> List[Dict[str, Any]]:
        """Run safety scan on the target path

        Args:
            target_path: Path to the Python project directory, a
                         requirements file, or a single Python file

        Returns:
            List of finding dictionaries in HOS-LS format
        """
        if not self.is_available():
            logger.warning('Safety scanner not available (safety not installed)')
            return []

        target_path_str = str(target_path)
        dep_file = self._detect_python_project(target_path_str)

        findings = []

        if dep_file is not None:
            logger.info(f'Safety scanning dependency file: {dep_file}')
            findings = self._run_safety_with_file(dep_file)
        else:
            logger.info(f'No Python dependency files found in {target_path_str}, scanning installed packages')
            findings = self._run_safety_default()

        if self.nvd_adapter is not None and findings:
            findings = self._enrich_with_nvd(findings)

        logger.info(f'Safety scan completed: {len(findings)} vulnerabilities found')
        return findings

    def _run_safety_with_file(self, requirements_file: str) -> List[Dict[str, Any]]:
        """Run safety check with a specific requirements file

        Args:
            requirements_file: Absolute path to the requirements file

        Returns:
            List of findings
        """
        return self._run_safety_command(['--file', requirements_file], requirements_file)

    def _run_safety_default(self) -> List[Dict[str, Any]]:
        """Run safety check on installed packages (no specific file)

        Returns:
            List of findings
        """
        return self._run_safety_command([], None)

    def _run_safety_command(self, extra_args: List[str], requirements_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """Execute the safety command and parse results

        Args:
            extra_args: Additional arguments for safety (e.g., ['--file', 'requirements.txt'])
            requirements_file: Path to the requirements file for the finding metadata

        Returns:
            List of findings
        """
        cmd = [sys.executable, '-m', 'safety', 'check', '--json', '--full-report'] + extra_args

        logger.debug(f'Executing safety command: {" ".join(cmd)}')

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.error('Safety command timed out (120s)')
            return []
        except FileNotFoundError:
            logger.error('Safety module not found')
            return []
        except Exception as e:
            logger.error(f'Safety command execution failed: {e}')
            return []

        if result.returncode == 0 and not result.stdout.strip():
            logger.info('Safety found no vulnerabilities')
            return []

        stdout = result.stdout.strip()
        if not stdout:
            if result.stderr:
                logger.warning(f'Safety stderr: {result.stderr[:500]}')
            return []

        try:
            raw_data = json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.error(f'Failed to parse safety JSON output: {e}')
            logger.debug(f'Raw output (first 500 chars): {stdout[:500]}')
            return []

        return self._parse_safety_output(raw_data, requirements_file)

    def _parse_safety_output(self, raw_data: Any, requirements_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """Parse safety JSON output into HOS-LS finding format

        Safety can output either:
        - A list of vulnerability objects (newer versions)
        - A dict with 'vulnerabilities' key (some versions)

        Args:
            raw_data: Parsed JSON from safety output
            requirements_file: Path to the requirements file

        Returns:
            List of HOS-LS formatted findings
        """
        vulnerabilities = []

        if isinstance(raw_data, list):
            vulnerabilities = raw_data
        elif isinstance(raw_data, dict):
            vulnerabilities = raw_data.get('vulnerabilities', [])
            if not vulnerabilities:
                vulnerabilities = raw_data.get('results', [])
                if not vulnerabilities:
                    vulnerabilities = [raw_data] if 'package_name' in raw_data else []
        else:
            logger.warning(f'Unexpected safety output type: {type(raw_data)}')
            return []

        findings = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            finding = self._build_finding(vuln, requirements_file)
            if finding is not None:
                findings.append(finding)

        return findings

    def _build_finding(self, vuln: Dict[str, Any], requirements_file: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Build a single HOS-LS finding from a safety vulnerability entry

        Args:
            vuln: Single vulnerability dict from safety output
            requirements_file: Path to the requirements file

        Returns:
            HOS-LS finding dict or None if insufficient data
        """
        package = vuln.get('package_name', '') or vuln.get('package', '')
        version = vuln.get('installed_version', '') or vuln.get('version', '')
        description = vuln.get('description', '') or vuln.get('advisory', '')
        cve_id = vuln.get('cve', '') or vuln.get('cve_id', '')
        cvss_score = self._extract_cvss(vuln)
        fixed_version = vuln.get('fixed_version', '') or vuln.get('fix', '')
        vuln_type = vuln.get('vuln_type', 'dependency_vulnerability')

        if not package:
            return None

        severity = self._map_cvss(cvss_score)

        file_path = str(requirements_file) if requirements_file else 'installed_packages'

        return {
            'file': file_path,
            'line': 0,
            'vuln_type': vuln_type if vuln_type else 'dependency_vulnerability',
            'severity': severity,
            'message': f'Vulnerable package {package} version {version}: {description}',
            'code_snippet': f'{package}=={version}',
            'cwe_id': '',
            'confidence': 0.90,
            'metadata': {
                'source': 'safety',
                'package_name': package,
                'installed_version': version,
                'fixed_version': fixed_version,
                'cve_id': cve_id,
                'cvss_score': cvss_score,
            }
        }

    def _extract_cvss(self, vuln: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from vulnerability dict

        Safety output may have CVSS in different locations.

        Args:
            vuln: Vulnerability dict

        Returns:
            CVSS score as float, or None
        """
        cvss = vuln.get('cvss_score') or vuln.get('cvss') or vuln.get('cvssv3_score')
        if cvss is not None:
            try:
                return float(cvss)
            except (ValueError, TypeError):
                return None
        return None

    def _map_cvss(self, score: Optional[float]) -> str:
        """Map CVSS score to severity string

        Args:
            score: CVSS score (0.0 - 10.0)

        Returns:
            Severity string: 'critical', 'high', 'medium', or 'low'
        """
        if score is None:
            return 'medium'
        if score >= 9.0:
            return 'critical'
        if score >= 7.0:
            return 'high'
        if score >= 4.0:
            return 'medium'
        return 'low'

    def _enrich_with_nvd(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich findings with NVD CWE data

        Args:
            findings: List of findings to enrich

        Returns:
            Enriched findings list
        """
        if self.nvd_adapter is None:
            return findings

        for finding in findings:
            metadata = finding.get('metadata', {})
            cve_id = metadata.get('cve_id', '')
            package_name = metadata.get('package_name', '')

            cwe_id = ''

            if cve_id:
                cwe_id = self._query_nvd_for_cwe(cve_id, package_name)

            if cwe_id:
                finding['cwe_id'] = cwe_id

        return findings

    def _query_nvd_for_cwe(self, cve_id: str, package_name: str) -> str:
        """Query NVD adapter for CWE information

        Args:
            cve_id: CVE ID string
            package_name: Package name for fallback keyword search

        Returns:
            CWE ID string or empty string
        """
        try:
            nvd_type = type(self.nvd_adapter).__name__

            if nvd_type == 'NVDQueryAdapter':
                if hasattr(self.nvd_adapter, 'get_db_stats'):
                    cves = self.nvd_adapter.search_vulnerabilities(limit=200)
                    for cve in cves:
                        if cve.get('cve_id', '').upper() == cve_id.upper():
                            cwe_info = self.nvd_adapter.get_cwe_with_cves(
                                cve.get('cve_id', ''), limit=1
                            )
                            if cwe_info and cwe_info.get('cwe_id'):
                                return cwe_info['cwe_id']

                keywords = [package_name]
                cwe_matches = self.nvd_adapter.match_cwe(keywords, limit=1)
                if cwe_matches:
                    return cwe_matches[0].get('cwe_id', '')

            elif nvd_type == 'NVDAdapter':
                if hasattr(self.nvd_adapter, 'get_cve_details'):
                    details = self.nvd_adapter.get_cve_details(cve_id)
                    if details:
                        cwe_ids = details.get('cwe_ids', [])
                        if cwe_ids:
                            return cwe_ids[0]

                keywords = [package_name]
                cwe_matches = self.nvd_adapter.match_cwe(keywords, limit=1)
                if cwe_matches:
                    return cwe_matches[0].get('cwe_id', '')

        except Exception as e:
            logger.debug(f'NVD enrichment failed for {cve_id}/{package_name}: {e}')

        return ''
