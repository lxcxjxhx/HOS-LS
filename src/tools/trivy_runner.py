"""Trivy 漏洞扫描器

作为综合漏洞扫描层，使用 Trivy 检测文件系统、容器镜像和 SBOM 中的漏洞
"""
import json
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional


class TrivyRunner:
    """Trivy 综合漏洞扫描层"""

    SEVERITY_MAP = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "UNKNOWN"
    }

    def __init__(self):
        self.trivy_available = self._check_trivy_installed()

    def _check_trivy_installed(self) -> bool:
        """检查 Trivy 是否已安装"""
        return shutil.which("trivy") is not None

    def scan_filesystem(self, target: str) -> List[Dict[str, Any]]:
        """扫描文件系统漏洞

        Args:
            target: 目标路径

        Returns:
            漏洞发现列表
        """
        if not self.trivy_available:
            print("[TRIVY] Trivy 未安装或不在 PATH 中")
            return []

        results = []
        try:
            cmd = [
                "trivy",
                "fs",
                "--format", "json",
                "--severity", "HIGH,CRITICAL",
                "--quiet",
                target
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.stdout:
                data = json.loads(result.stdout)
                results = self._parse_fs_results(data)

        except subprocess.TimeoutExpired:
            print("[TRIVY] 文件系统扫描超时")
        except json.JSONDecodeError:
            print("[TRIVY] JSON 解析失败")
        except Exception as e:
            print(f"[TRIVY] 文件系统扫描失败 {target}: {e}")

        return results

    def scan_image(self, image: str) -> List[Dict[str, Any]]:
        """扫描容器镜像漏洞

        Args:
            image: 镜像名称或标签

        Returns:
            漏洞发现列表
        """
        if not self.trivy_available:
            print("[TRIVY] Trivy 未安装或不在 PATH 中")
            return []

        results = []
        try:
            cmd = [
                "trivy",
                "image",
                "--format", "json",
                "--severity", "HIGH,CRITICAL",
                "--quiet",
                image
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.stdout:
                data = json.loads(result.stdout)
                results = self._parse_image_results(data, image)

        except subprocess.TimeoutExpired:
            print("[TRIVY] 镜像扫描超时")
        except json.JSONDecodeError:
            print("[TRIVY] JSON 解析失败")
        except Exception as e:
            print(f"[TRIVY] 镜像扫描失败 {image}: {e}")

        return results

    def scan_sbom(self, sbom_file: str) -> List[Dict[str, Any]]:
        """扫描 SBOM 文件漏洞

        Args:
            sbom_file: SBOM 文件路径

        Returns:
            漏洞发现列表
        """
        if not self.trivy_available:
            print("[TRIVY] Trivy 未安装或不在 PATH 中")
            return []

        results = []
        try:
            cmd = [
                "trivy",
                "sbom",
                "--format", "json",
                "--severity", "HIGH,CRITICAL",
                sbom_file
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.stdout:
                data = json.loads(result.stdout)
                results = self._parse_sbom_results(data, sbom_file)

        except subprocess.TimeoutExpired:
            print("[TRIVY] SBOM 扫描超时")
        except json.JSONDecodeError:
            print("[TRIVY] JSON 解析失败")
        except Exception as e:
            print(f"[TRIVY] SBOM 扫描失败 {sbom_file}: {e}")

        return results

    def _parse_fs_results(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """解析文件系统扫描结果"""
        results = []

        results_list = data.get("Results", [])
        for result in results_list:
            vulnerabilities = result.get("Vulnerabilities", []) or []
            for vuln in vulnerabilities:
                results.append(self._normalize_vulnerability(vuln, result.get("Target", "")))

        return results

    def _parse_image_results(self, data: Dict[str, Any], image: str) -> List[Dict[str, Any]]:
        """解析镜像扫描结果"""
        results = []

        results_list = data.get("Results", [])
        for result in results_list:
            vulnerabilities = result.get("Vulnerabilities", []) or []
            for vuln in vulnerabilities:
                vuln_data = self._normalize_vulnerability(vuln, result.get("Target", image))
                vuln_data["file"] = image
                results.append(vuln_data)

        return results

    def _parse_sbom_results(self, data: Dict[str, Any], sbom_file: str) -> List[Dict[str, Any]]:
        """解析 SBOM 扫描结果"""
        results = []

        results_list = data.get("Results", [])
        for result in results_list:
            vulnerabilities = result.get("Vulnerabilities", []) or []
            for vuln in vulnerabilities:
                vuln_data = self._normalize_vulnerability(vuln, sbom_file)
                vuln_data["file"] = sbom_file
                results.append(vuln_data)

        return results

    def _normalize_vulnerability(self, vuln: Dict[str, Any], target: str) -> Dict[str, Any]:
        """标准化漏洞格式"""
        return {
            "file": target,
            "line": 0,
            "cve_id": vuln.get("VulnerabilityID", ""),
            "cwe_id": vuln.get("CweID", ""),
            "severity": self._map_severity(vuln.get("Severity", "UNKNOWN")),
            "description": vuln.get("Description", ""),
            "package": vuln.get("PkgName", ""),
            "installed_version": vuln.get("InstalledVersion", ""),
            "fixed_version": self._get_fixed_version(vuln),
            "source": "trivy"
        }

    def _get_fixed_version(self, vuln: Dict[str, Any]) -> str:
        """获取修复版本"""
        fixed_versions = vuln.get("FixedVersion", "")
        if isinstance(fixed_versions, list):
            return ",".join(fixed_versions) if fixed_versions else ""
        return str(fixed_versions) if fixed_versions else ""

    def _map_severity(self, severity: str) -> str:
        """映射严重级别"""
        if not severity:
            return "UNKNOWN"

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

        return "UNKNOWN"


def run_trivy_scan(target: str, scan_type: str = "filesystem") -> List[Dict[str, Any]]:
    """便捷函数：运行 Trivy 扫描

    Args:
        target: 目标路径、镜像或 SBOM 文件
        scan_type: 扫描类型 ("filesystem", "image", "sbom")

    Returns:
        漏洞发现列表
    """
    runner = TrivyRunner()

    if scan_type == "image":
        return runner.scan_image(target)
    elif scan_type == "sbom":
        return runner.scan_sbom(target)
    else:
        return runner.scan_filesystem(target)
