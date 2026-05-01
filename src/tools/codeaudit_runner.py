"""CodeAudit AST 语义分析器

作为语义验证层，使用 AST 分析验证 AI 发现的漏洞
"""
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional


class CodeAuditRunner:
    """CodeAudit AST 语义验证层"""

    SUPPORTED_LANGUAGES = {
        ".java": "java",
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".c": "c",
        ".cpp": "cpp",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
    }

    SECURITY_RULES = [
        "sql-injection",
        "xss",
        "command-injection",
        "path-traversal",
        "hardcoded-credentials",
        "insecure-random",
        "weak-crypto",
    ]

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir or self._get_default_rules_dir()
        self._ensure_rules()

    def _get_default_rules_dir(self) -> str:
        return str(Path(__file__).parent / "rules")

    def _ensure_rules(self):
        Path(self.rules_dir).mkdir(parents=True, exist_ok=True)

    def verify_vulnerability(self, file_path: str, vulnerability_type: str, code_snippet: str = None) -> Dict[str, Any]:
        """验证漏洞（AST 语义分析）

        Args:
            file_path: 文件路径
            vulnerability_type: 漏洞类型（如 "sql-injection"）
            code_snippet: 可选的代码片段

        Returns:
            验证结果
        """
        language = self._detect_language(file_path)

        try:
            cmd = [
                "codeaudit",
                "--lang", language,
                "--rule", vulnerability_type,
                "--json",
                file_path
            ]

            if code_snippet:
                with tempfile.NamedTemporaryFile(mode='w', suffix=Path(file_path).suffix, delete=False, encoding='utf-8') as f:
                    f.write(code_snippet)
                    temp_path = f.name
                cmd[-1] = temp_path

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if code_snippet:
                Path(temp_path).unlink(missing_ok=True)

            if result.returncode == 0 and result.stdout:
                return self._parse_result(result.stdout, vulnerability_type)
            else:
                return {
                    "verified": False,
                    "vulnerability_type": vulnerability_type,
                    "confidence": 0.0,
                    "reason": result.stderr or "Analysis completed with no findings"
                }

        except subprocess.TimeoutExpired:
            return {
                "verified": False,
                "vulnerability_type": vulnerability_type,
                "confidence": 0.0,
                "reason": "Analysis timeout"
            }
        except Exception as e:
            return {
                "verified": False,
                "vulnerability_type": vulnerability_type,
                "confidence": 0.0,
                "reason": str(e)
            }

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """分析文件检测所有漏洞

        Args:
            file_path: 文件路径

        Returns:
            漏洞列表
        """
        language = self._detect_language(file_path)
        findings = []

        try:
            cmd = ["codeaudit", "--lang", language, "--json", file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                findings = self._parse_findings(data)
        except Exception as e:
            print(f"[CODEAUDIT] 分析失败 {file_path}: {e}")

        return findings

    def analyze_directory(self, dir_path: str) -> List[Dict[str, Any]]:
        """分析目录

        Args:
            dir_path: 目录路径

        Returns:
            所有漏洞
        """
        all_findings = []
        path = Path(dir_path)

        for ext in self.SUPPORTED_LANGUAGES:
            for file_path in path.rglob(f"*{ext}"):
                if self._should_skip(file_path):
                    continue
                findings = self.analyze_file(str(file_path))
                all_findings.extend(findings)

        return all_findings

    def _detect_language(self, file_path: str) -> str:
        """检测编程语言"""
        suffix = Path(file_path).suffix.lower()
        return self.SUPPORTED_LANGUAGES.get(suffix, "unknown")

    def _parse_result(self, stdout: str, vulnerability_type: str) -> Dict[str, Any]:
        """解析分析结果"""
        try:
            data = json.loads(stdout)
            findings = self._parse_findings(data)

            if findings:
                return {
                    "verified": True,
                    "vulnerability_type": vulnerability_type,
                    "confidence": 0.85,
                    "findings": findings
                }
        except json.JSONDecodeError:
            pass

        return {
            "verified": False,
            "vulnerability_type": vulnerability_type,
            "confidence": 0.0,
            "reason": "No vulnerabilities found"
        }

    def _parse_findings(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """解析漏洞发现"""
        findings = []

        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("findings", [data])
        else:
            items = []

        for item in items:
            if isinstance(item, dict):
                findings.append({
                    "file": item.get("file", item.get("path", "")),
                    "line": item.get("line", item.get("start_line", 0)),
                    "vulnerability_type": item.get("type", item.get("vulnerability_type", "")),
                    "severity": self._map_severity(item.get("severity", "MEDIUM")),
                    "confidence": item.get("confidence", 0.7),
                    "message": item.get("message", item.get("description", "")),
                    "source": "codeaudit"
                })

        return findings

    def _map_severity(self, severity: str) -> str:
        """映射严重级别"""
        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "WARNING": "HIGH",
            "ERROR": "CRITICAL"
        }
        return severity_map.get(severity.upper(), "MEDIUM")

    def _should_skip(self, file_path: Path) -> bool:
        """判断是否跳过"""
        skip_dirs = {"node_modules", "target", "build", ".git", "__pycache__", "venv", ".venv", "test", "tests"}
        return any(part in skip_dirs for part in file_path.parts)


def verify_with_codeaudit(file_path: str, vulnerability_type: str, code_snippet: str = None) -> Dict[str, Any]:
    """便捷函数：验证漏洞"""
    runner = CodeAuditRunner()
    return runner.verify_vulnerability(file_path, vulnerability_type, code_snippet)
