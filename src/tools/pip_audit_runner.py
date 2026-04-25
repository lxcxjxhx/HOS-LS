"""pip-audit 依赖漏洞扫描器

作为依赖扫描层，检测第三方库的 CVE 漏洞
"""
import json
import subprocess
import os
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional


class PipAuditRunner:
    """pip-audit 依赖扫描层"""

    SEVERITY_MAP = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW"
    }

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        self._cached_deps = None

    def scan_dependencies(self, project_path: str = None, requirements_file: str = None) -> List[Dict[str, Any]]:
        """扫描项目依赖

        Args:
            project_path: 项目路径
            requirements_file: requirements.txt 路径

        Returns:
            依赖漏洞列表
        """
        results = []

        try:
            cmd = ["pip-audit", "--json", "--strict"]

            if project_path:
                cmd.extend(["--path", project_path])
            elif requirements_file:
                cmd.extend(["-r", requirements_file])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode in (0, 1):
                if result.stdout:
                    data = json.loads(result.stdout)
                    results = self._parse_results(data)

        except subprocess.TimeoutExpired:
            print("[PIP-AUDIT] 扫描超时")
        except json.JSONDecodeError:
            print("[PIP-AUDIT] JSON 解析失败")
        except Exception as e:
            print(f"[PIP-AUDIT] 扫描失败: {e}")

        return results

    def scan_pip_list(self) -> List[Dict[str, Any]]:
        """扫描当前环境的所有依赖

        Returns:
            依赖漏洞列表
        """
        results = []

        try:
            cmd = ["pip-audit", "--json", "--local"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode in (0, 1) and result.stdout:
                data = json.loads(result.stdout)
                results = self._parse_results(data)

        except Exception as e:
            print(f"[PIP-AUDIT] pip list 扫描失败: {e}")

        return results

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """扫描指定文件中的依赖

        Args:
            file_path: 文件路径（requirements.txt, setup.py, pyproject.toml 等）

        Returns:
            依赖漏洞列表
        """
        results = []

        try:
            suffix = Path(file_path).suffix.lower()

            if suffix == ".txt":
                cmd = ["pip-audit", "-r", file_path, "--json"]
            elif suffix in (".py", ".toml"):
                cmd = ["pip-audit", "--path", file_path, "--json"]
            else:
                cmd = ["pip-audit", "-r", file_path, "--json"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode in (0, 1) and result.stdout:
                data = json.loads(result.stdout)
                results = self._parse_results(data)

        except Exception as e:
            print(f"[PIP-AUDIT] 文件扫描失败 {file_path}: {e}")

        return results

    def get_package_info(self, package_name: str) -> Optional[Dict[str, Any]]:
        """获取包信息

        Args:
            package_name: 包名

        Returns:
            包信息
        """
        try:
            cmd = ["pip", "show", package_name]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                info = {}
                for line in result.stdout.split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        info[key.strip().lower().replace("-", "_")] = value.strip()
                return info

        except Exception as e:
            print(f"[PIP-AUDIT] 获取包信息失败 {package_name}: {e}")

        return None

    def _parse_results(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """解析扫描结果"""
        results = []

        if isinstance(data, dict):
            if "dependencies" in data:
                vulns = data["dependencies"]
            elif "vulnerabilities" in data:
                vulns = data["vulnerabilities"]
            else:
                vulns = [data] if data.get("name") else []
        elif isinstance(data, list):
            vulns = data
        else:
            vulns = []

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue

            name = vuln.get("name", "")
            version = vuln.get("version", "")
            vulns_list = vuln.get("vulns", vuln.get("vulnerabilities", []))

            for v in vulns_list:
                if isinstance(v, dict):
                    results.append({
                        "package": name,
                        "version": version,
                        "cve_id": v.get("id", v.get("cve_id", "")),
                        "cwe_id": self._extract_cwe(v.get("link", "")),
                        "severity": self._map_severity(v.get("severity", "MEDIUM")),
                        "description": v.get("id", v.get("description", "")),
                        "link": v.get("link", ""),
                        "fix_versions": v.get("fix_versions", []),
                        "source": "pip-audit"
                    })

        return results

    def _extract_cwe(self, link: str) -> Optional[str]:
        """从链接中提取 CWE ID"""
        if not link:
            return None

        import re
        cwe_match = re.search(r"CWE-(\d+)", link, re.IGNORECASE)
        if cwe_match:
            return f"CWE-{cwe_match.group(1)}"

        return None

    def _map_severity(self, severity: str) -> str:
        """映射严重级别"""
        if not severity:
            return "MEDIUM"

        severity_upper = severity.upper()
        if severity_upper in self.SEVERITY_MAP:
            return self.SEVERITY_MAP[severity_upper]

        if "CRITICAL" in severity_upper:
            return "CRITICAL"
        elif "HIGH" in severity_upper:
            return "HIGH"
        elif "MEDIUM" in severity_upper or "MODERATE" in severity_upper:
            return "MEDIUM"
        elif "LOW" in severity_upper:
            return "LOW"

        return "MEDIUM"

    def check_package_version(self, package_name: str, vulnerable_versions: List[str]) -> bool:
        """检查包版本是否在漏洞版本范围内

        Args:
            package_name: 包名
            vulnerable_versions: 漏洞版本列表

        Returns:
            是否存在漏洞
        """
        try:
            cmd = ["pip", "show", package_name]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return False

            for line in result.stdout.split("\n"):
                if line.startswith("Version:"):
                    current_version = line.split(":", 1)[1].strip()
                    return current_version in vulnerable_versions

        except Exception:
            pass

        return False


def run_pip_audit(project_path: str = None) -> List[Dict[str, Any]]:
    """便捷函数：运行 pip-audit 扫描

    Args:
        project_path: 项目路径（可选）

    Returns:
        依赖漏洞列表
    """
    runner = PipAuditRunner()
    if project_path:
        return runner.scan_dependencies(project_path=project_path)
    else:
        return runner.scan_pip_list()
