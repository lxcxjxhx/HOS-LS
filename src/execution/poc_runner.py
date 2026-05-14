import os
import sys
import json
import time
import subprocess
import tempfile
import shutil
import logging
import hashlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

try:
    from .venv_manager import VenvManager, get_venv_manager
except ImportError:
    from src.execution.venv_manager import VenvManager, get_venv_manager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('POCRunner')


@dataclass
class POCResult:
    poc_id: str
    vulnerable: bool
    confidence: float
    evidence: List[Dict]
    error: Optional[str]
    execution_time: float
    target: str
    vuln_type: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'poc_id': self.poc_id,
            'vulnerable': self.vulnerable,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'error': self.error,
            'execution_time': self.execution_time,
            'target': self.target,
            'vuln_type': self.vuln_type
        }


class POCRunner:
    DEFAULT_TIMEOUT = 60

    def __init__(
        self,
        venv_manager: Optional[VenvManager] = None,
        timeout: int = DEFAULT_TIMEOUT,
        results_dir: Optional[str] = None
    ):
        self._venv_manager = venv_manager or get_venv_manager()
        self._timeout = timeout
        self._results_dir = results_dir or os.path.join(tempfile.gettempdir(), "poc_results")
        self._temp_files: List[str] = []
        self._poc_classes_cache: Dict[str, type] = {}
        self._base_poc_template_path = self._find_base_poc_template()

        os.makedirs(self._results_dir, exist_ok=True)
        logger.info(f"POCRunner initialized with timeout={self._timeout}, results_dir={self._results_dir}")

    def _find_base_poc_template(self) -> Optional[Path]:
        possible_paths = [
            Path(__file__).parent.parent.parent / 'dynamic_code' / 'pocs' / 'templates' / 'base_poc_template.py',
            Path.cwd() / 'dynamic_code' / 'pocs' / 'templates' / 'base_poc_template.py',
        ]

        for path in possible_paths:
            if path.exists():
                return path

        return None

    def _load_poc_classes(self) -> Dict[str, type]:
        if self._poc_classes_cache:
            return self._poc_classes_cache

        if not self._base_poc_template_path or not self._base_poc_template_path.exists():
            logger.warning("base_poc_template.py not found")
            return {}

        try:
            spec = importlib.util.spec_from_file_location(
                "base_poc_template",
                self._base_poc_template_path
            )

            if spec is None or spec.loader is None:
                return {}

            module = importlib.util.module_from_spec(spec)
            sys.modules['base_poc_template'] = module
            spec.loader.exec_module(module)

            self._poc_classes_cache = {
                'sql_injection': module.SQLInjectionPOC,
                'auth_bypass': module.AuthBypassPOC,
                'ssrf': module.SSrfPOC,
                'deserialization': module.DeserializationPOC,
            }

            logger.info("Loaded POC classes from base_poc_template.py")
            return self._poc_classes_cache

        except Exception as e:
            logger.error(f"Failed to load POC classes: {e}")
            return {}

    def run_poc(
        self,
        poc_script: str,
        target: str,
        vuln_type: str,
        dependencies: List[str] = None,
        poc_id: Optional[str] = None
    ) -> Dict[str, Any]:
        start_time = time.time()
        poc_id = poc_id or self._generate_poc_id(target, vuln_type)

        logger.info(f"Running POC {poc_id} against {target} (type: {vuln_type})")

        try:
            if not dependencies:
                result = self._run_poc_direct(poc_script, target, vuln_type, poc_id)
            else:
                result = self.run_poc_in_venv(
                    self._ensure_venv(poc_id, dependencies),
                    poc_script,
                    target
                )

            result['execution_time'] = time.time() - start_time
            return result

        except Exception as e:
            logger.error(f"POC execution failed for {poc_id}: {e}")
            return {
                'poc_id': poc_id,
                'vulnerable': False,
                'confidence': 0.0,
                'evidence': [],
                'error': str(e),
                'execution_time': time.time() - start_time,
                'target': target,
                'vuln_type': vuln_type
            }

    def run_poc_in_venv(
        self,
        venv_path: str,
        poc_script: str,
        target: str
    ) -> Dict[str, Any]:
        venv_python = self._venv_manager.get_venv_python(venv_path)
        if not venv_python:
            venv_python = os.path.join(venv_path, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_path, "bin", "python")

        if not os.path.exists(venv_python):
            venv_python = sys.executable

        temp_script = self._create_temp_script(poc_script)
        if not temp_script:
            return {
                'poc_id': '',
                'vulnerable': False,
                'confidence': 0.0,
                'evidence': [],
                'error': 'Failed to create temp script',
                'execution_time': 0.0,
                'target': target,
                'vuln_type': ''
            }

        try:
            process = subprocess.Popen(
                [venv_python, temp_script, '--target', target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            try:
                stdout, stderr = process.communicate(timeout=self._timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                return {
                    'poc_id': '',
                    'vulnerable': False,
                    'confidence': 0.0,
                    'evidence': [],
                    'error': f'Execution timeout after {self._timeout} seconds',
                    'execution_time': self._timeout,
                    'target': target,
                    'vuln_type': ''
                }

            if process.returncode == 0:
                return self.parse_poc_result(stdout, '')
            else:
                return self.parse_poc_result(stdout, stderr)

        except Exception as e:
            logger.error(f"Venv execution failed: {e}")
            return {
                'poc_id': '',
                'vulnerable': False,
                'confidence': 0.0,
                'evidence': [],
                'error': str(e),
                'execution_time': 0.0,
                'target': target,
                'vuln_type': ''
            }
        finally:
            self._cleanup_temp_script(temp_script)

    def _run_poc_direct(
        self,
        poc_script: str,
        target: str,
        vuln_type: str,
        poc_id: str
    ) -> Dict[str, Any]:
        poc_classes = self._load_poc_classes()
        poc_class = poc_classes.get(vuln_type)

        if not poc_class:
            return {
                'poc_id': poc_id,
                'vulnerable': False,
                'confidence': 0.0,
                'evidence': [],
                'error': f'Unknown vulnerability type: {vuln_type}',
                'execution_time': 0.0,
                'target': target,
                'vuln_type': vuln_type
            }

        try:
            from base_poc_template import POCContext as BasePOCContext

            context = BasePOCContext(
                target=target,
                vuln_type=vuln_type,
                file_path='',
                line_number=0,
                code_snippet='',
                additional_params={}
            )

            param = None
            poc = poc_class(context, param=param)
            result = poc.verify()

            return self.parse_poc_result(json.dumps(result), '', vuln_type)

        except Exception as e:
            logger.error(f"Direct POC execution failed: {e}")
            return {
                'poc_id': poc_id,
                'vulnerable': False,
                'confidence': 0.0,
                'evidence': [],
                'error': str(e),
                'execution_time': 0.0,
                'target': target,
                'vuln_type': vuln_type
            }

    def parse_poc_result(
        self,
        output: str,
        error: str,
        vuln_type: str = ''
    ) -> Dict[str, Any]:
        result = {
            'poc_id': '',
            'vulnerable': False,
            'confidence': 0.0,
            'evidence': [],
            'error': None,
            'execution_time': 0.0,
            'target': '',
            'vuln_type': vuln_type
        }

        if error and not output:
            result['error'] = error.strip()
            return result

        try:
            data = json.loads(output)

            is_exploitable = data.get('is_exploitable', False)
            evidence_list = data.get('evidence', [])

            if isinstance(evidence_list, list) and evidence_list:
                confidence = 0.8 if is_exploitable else 0.3
                for evidence in evidence_list:
                    if isinstance(evidence, dict):
                        if evidence.get('payloads'):
                            confidence = 0.9
                            break
            else:
                confidence = 0.5 if is_exploitable else 0.2

            result['vulnerable'] = is_exploitable
            result['confidence'] = confidence
            result['evidence'] = evidence_list if isinstance(evidence_list, list) else []
            result['target'] = data.get('target', '')
            result['vuln_type'] = data.get('vuln_type', vuln_type)
            result['poc_id'] = self._generate_poc_id(result['target'], result['vuln_type'])

        except json.JSONDecodeError:
            result['error'] = f'Failed to parse POC output: {output[:200]}'
            result['evidence'] = [{'raw_output': output[:500]}]

        return result

    def save_result(self, result: Dict[str, Any], poc_id: str) -> str:
        if not poc_id:
            poc_id = result.get('poc_id', 'unknown')

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{poc_id}_{timestamp}.json"
        filepath = os.path.join(self._results_dir, filename)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            logger.info(f"Saved POC result to {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Failed to save result: {e}")
            raise RuntimeError(f"Failed to save result: {e}") from e

    def cleanup(self) -> None:
        for temp_file in self._temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file {temp_file}: {e}")

        self._temp_files.clear()
        logger.info("POCRunner cleanup completed")

    def _ensure_venv(self, name: str, dependencies: List[str]) -> str:
        return self._venv_manager.get_or_create_venv(name, dependencies)

    def _generate_poc_id(self, target: str, vuln_type: str) -> str:
        hash_input = f"{target}:{vuln_type}:{time.time()}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:12]

    def _create_temp_script(self, script_content: str) -> Optional[str]:
        try:
            fd, path = tempfile.mkstemp(suffix='.py', prefix='poc_')
            os.write(fd, script_content.encode('utf-8'))
            os.close(fd)
            self._temp_files.append(path)
            return path
        except Exception as e:
            logger.error(f"Failed to create temp script: {e}")
            return None

    def _cleanup_temp_script(self, path: Optional[str]) -> None:
        if path and path in self._temp_files:
            try:
                if os.path.exists(path):
                    os.unlink(path)
                self._temp_files.remove(path)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp script {path}: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False
