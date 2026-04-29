"""Semgrep 快速规则扫描器

作为预扫描层，使用 Semgrep 内置规则快速检测高危漏洞
"""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional


class SemgrepRunner:
    """Semgrep 快速预扫描层"""

    CWE_RULES = {
        "CWE-89": "java.lang.security.audit.sqli.jdbc-sqli",
        "CWE-79": "java.lang.security.audit.xss.audit-xss-jsp-out",
        "CWE-22": "java.lang.security.audit.path-traversal-pathjoin",
        "CWE-259": "java.lang.security.audit.hardcoded-password-aes",
        "CWE-321": "java.lang.security.audit.hardcoded-crypto-key",
    }

    LANGUAGE_MAP = {
        ".java": "java",
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".c": "c",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
    }

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir or self._get_default_rules_dir()
        self._ensure_rules()
        self.semgrep_available = self._check_semgrep_installed()

    def _check_semgrep_installed(self) -> bool:
        """检查 Semgrep 是否已安装"""
        return shutil.which("semgrep") is not None

    def _get_default_rules_dir(self) -> str:
        """获取默认规则目录"""
        return str(Path(__file__).parent / "rules")

    def _ensure_rules(self):
        """确保规则目录存在"""
        Path(self.rules_dir).mkdir(parents=True, exist_ok=True)

    def scan_file(self, file_path: str, language: str = None) -> List[Dict[str, Any]]:
        """扫描单个文件

        Args:
            file_path: 文件路径
            language: 编程语言（自动检测如果为 None）

        Returns:
            漏洞发现列表
        """
        if not self.semgrep_available:
            return []

        if language is None:
            suffix = Path(file_path).suffix.lower()
            language = self.LANGUAGE_MAP.get(suffix, "auto")

        results = []
        try:
            cmd = [
                "semgrep",
                "--config", "auto",
                "--json",
                "--quiet",
                file_path
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                findings = data.get("results", [])
                for finding in findings:
                    cwe_id = self._match_cwe_id(finding)
                    results.append({
                        "file": file_path,
                        "line": finding.get("start", {}).get("line", 0),
                        "pattern": finding.get("pattern", ""),
                        "check_id": finding.get("check_id", ""),
                        "cwe_id": cwe_id,
                        "severity": self._map_severity(finding.get("severity", "")),
                        "message": finding.get("extra", {}).get("message", ""),
                        "confidence": 0.9,
                        "source": "semgrep"
                    })
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            print(f"[SEMGREP] 扫描失败 {file_path}: {e}")

        return results

    def scan_directory(self, dir_path: str, extensions: List[str] = None) -> List[Dict[str, Any]]:
        """扫描目录

        Args:
            dir_path: 目录路径
            extensions: 要扫描的文件扩展名列表

        Returns:
            所有漏洞发现
        """
        if extensions is None:
            extensions = list(self.LANGUAGE_MAP.keys())

        all_results = []
        path = Path(dir_path)

        for ext in extensions:
            for file_path in path.rglob(f"*{ext}"):
                if self._should_skip(file_path):
                    continue
                results = self.scan_file(str(file_path))
                all_results.extend(results)

        return all_results

    def scan_pattern(self, pattern: str, target: str) -> List[Dict[str, Any]]:
        """使用指定模式扫描

        Args:
            pattern: Semgrep 规则模式（如 "p/java-best-lists.eqeq-is-bad"）
            target: 目标文件或目录

        Returns:
            漏洞发现列表
        """
        results = []
        try:
            cmd = ["semgrep", "--config", pattern, "--json", "--quiet", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                findings = data.get("results", [])
                for finding in findings:
                    results.append({
                        "file": finding.get("path", ""),
                        "line": finding.get("start", {}).get("line", 0),
                        "pattern": finding.get("pattern", ""),
                        "check_id": finding.get("check_id", ""),
                        "cwe_id": self._match_cwe_id(finding),
                        "severity": self._map_severity(finding.get("severity", "")),
                        "message": finding.get("extra", {}).get("message", ""),
                        "confidence": 0.9,
                        "source": "semgrep"
                    })
        except Exception as e:
            print(f"[SEMGREP] 模式扫描失败 {pattern}: {e}")

        return results

    def _match_cwe_id(self, finding: Dict[str, Any]) -> Optional[str]:
        """匹配 CWE ID"""
        check_id = finding.get("check_id", "")
        message = finding.get("extra", {}).get("message", "").lower()

        for cwe_id, rule_id in self.CWE_RULES.items():
            if rule_id in check_id or cwe_id.lower() in message:
                return cwe_id

        if "sql" in message or "sqli" in check_id:
            return "CWE-89"
        if "xss" in message or "cross-site" in message:
            return "CWE-79"
        if "path" in message and "traversal" in message:
            return "CWE-22"

        return None

    def _map_severity(self, severity: str) -> str:
        """映射严重级别"""
        severity_map = {
            "ERROR": "CRITICAL",
            "WARNING": "HIGH",
            "INFO": "MEDIUM"
        }
        return severity_map.get(severity.upper(), "MEDIUM")

    def _should_skip(self, file_path: Path) -> bool:
        """判断是否跳过文件"""
        skip_dirs = {"node_modules", "target", "build", ".git", "__pycache__", "venv", ".venv"}
        skip_patterns = {"test", "Test", "spec", "Spec"}

        if any(part in skip_dirs for part in file_path.parts):
            return True
        if any(pattern in file_path.name for pattern in skip_patterns):
            return True
        return False


def run_semgrep_scan(target: str, scan_type: str = "file") -> List[Dict[str, Any]]:
    """便捷函数：运行 Semgrep 扫描

    Args:
        target: 目标路径
        scan_type: 扫描类型（"file" 或 "directory"）

    Returns:
        漏洞发现列表
    """
    runner = SemgrepRunner()

    if scan_type == "directory":
        return runner.scan_directory(target)
    else:
        return runner.scan_file(target)
