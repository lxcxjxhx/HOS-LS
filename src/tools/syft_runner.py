"""Syft SBOM 生成器

使用 Syft 生成软件物料清单（SBOM）
"""
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional


class SyftRunner:
    """Syft SBOM 生成器"""

    SUPPORTED_FORMATS = {
        "json": "json",
        "spdx-json": "spdx-json",
        "cyclonedx-json": "cyclonedx-json"
    }

    SUPPORTED_PACKAGE_MANAGERS = {
        "auto": None,
        "pip": "pip",
        "npm": "npm",
        "maven": "maven",
        "gradle": "gradle",
        "go": "go",
        "cargo": "cargo"
    }

    def __init__(self):
        self._syft_available = self._check_syft_installation()

    def _check_syft_installation(self) -> bool:
        """检查 Syft 是否已安装"""
        try:
            result = subprocess.run(
                ["syft", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def generate_sbom(self, target: str, output_format: str = "json") -> Dict[str, Any]:
        """生成 SBOM

        Args:
            target: 目标路径（文件或目录）
            output_format: 输出格式（json, spdx-json, cyclonedx-json）

        Returns:
            SBOM 数据，包含 package_list
        """
        if not self._syft_available:
            print("[SYFT] Syft 未安装或不可用")
            return {"packages": [], "source": target, "format": output_format}

        format_type = self.SUPPORTED_FORMATS.get(output_format, "json")

        try:
            cmd = [
                "syft",
                "packages",
                target,
                "--format", format_type
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0 and result.stdout:
                sbom_data = json.loads(result.stdout)
                return self._normalize_sbom(sbom_data, output_format)
            else:
                error_msg = result.stderr.strip() if result.stderr else "未知错误"
                print(f"[SYFT] 生成 SBOM 失败: {error_msg}")

        except subprocess.TimeoutExpired:
            print("[SYFT] SBOM 生成超时")
        except json.JSONDecodeError as e:
            print(f"[SYFT] SBOM 解析失败: {e}")
        except Exception as e:
            print(f"[SYFT] 生成 SBOM 时发生错误: {e}")

        return {"packages": [], "source": target, "format": output_format}

    def scan_sbom(self, sbom_file: str) -> Dict[str, Any]:
        """扫描现有 SBOM 文件

        Args:
            sbom_file: SBOM 文件路径

        Returns:
            SBOM 数据，包含 package_list
        """
        if not self._syft_available:
            print("[SYFT] Syft 未安装或不可用")
            return {"packages": [], "source": sbom_file, "format": "unknown"}

        sbom_path = Path(sbom_file)
        if not sbom_path.exists():
            print(f"[SYFT] SBOM 文件不存在: {sbom_file}")
            return {"packages": [], "source": sbom_file, "format": "unknown"}

        try:
            cmd = ["syft", "scan", sbom_file]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0 and result.stdout:
                sbom_data = json.loads(result.stdout)
                return self._normalize_sbom(sbom_data, "scan")
            else:
                error_msg = result.stderr.strip() if result.stderr else "未知错误"
                print(f"[SYFT] 扫描 SBOM 失败: {error_msg}")

        except subprocess.TimeoutExpired:
            print("[SYFT] SBOM 扫描超时")
        except json.JSONDecodeError as e:
            print(f"[SYFT] SBOM 解析失败: {e}")
        except Exception as e:
            print(f"[SYFT] 扫描 SBOM 时发生错误: {e}")

        return {"packages": [], "source": sbom_file, "format": "unknown"}

    def generate_sbom_with_package_manager(
        self,
        target: str,
        package_manager: str = "auto",
        output_format: str = "json"
    ) -> Dict[str, Any]:
        """使用指定包管理器生成 SBOM

        Args:
            target: 目标路径
            package_manager: 包管理器（auto, pip, npm, maven, gradle, go, cargo）
            output_format: 输出格式

        Returns:
            SBOM 数据
        """
        if not self._syft_available:
            print("[SYFT] Syft 未安装或不可用")
            return {"packages": [], "source": target, "format": output_format}

        if package_manager not in self.SUPPORTED_PACKAGE_MANAGERS:
            print(f"[SYFT] 不支持的包管理器: {package_manager}")
            return {"packages": [], "source": target, "format": output_format}

        format_type = self.SUPPORTED_FORMATS.get(output_format, "json")
        pkg_manager = self.SUPPORTED_PACKAGE_MANAGERS[package_manager]

        try:
            cmd = [
                "syft",
                "packages",
                target,
                "--format", format_type
            ]

            if pkg_manager:
                cmd.extend(["--package", pkg_manager])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0 and result.stdout:
                sbom_data = json.loads(result.stdout)
                return self._normalize_sbom(sbom_data, output_format)
            else:
                error_msg = result.stderr.strip() if result.stderr else "未知错误"
                print(f"[SYFT] 生成 SBOM 失败: {error_msg}")

        except subprocess.TimeoutExpired:
            print("[SYFT] SBOM 生成超时")
        except json.JSONDecodeError as e:
            print(f"[SYFT] SBOM 解析失败: {e}")
        except Exception as e:
            print(f"[SYFT] 生成 SBOM 时发生错误: {e}")

        return {"packages": [], "source": target, "format": output_format}

    def _normalize_sbom(self, sbom_data: Dict[str, Any], original_format: str) -> Dict[str, Any]:
        """规范化 SBOM 数据为统一格式

        Args:
            sbom_data: 原始 SBOM 数据
            original_format: 原始格式类型

        Returns:
            规范化后的 SBOM 数据
        """
        packages = []

        artifacts = sbom_data.get("artifacts", [])
        if not artifacts:
            source_info = sbom_data.get("source", {})
            if isinstance(source_info, dict):
                artifacts = source_info.get("packages", [])
            elif "packages" in sbom_data:
                artifacts = sbom_data.get("packages", [])

        for artifact in artifacts:
            package_info = {
                "name": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "type": artifact.get("type", artifact.get("purl", "").split(":")[0] if artifact.get("purl") else "unknown"),
                "location": artifact.get("locations", [{}])[0].get("path", "") if artifact.get("locations") else ""
            }

            if artifact.get("purl"):
                package_info["purl"] = artifact.get("purl")

            if artifact.get("license"):
                package_info["license"] = artifact.get("license")

            packages.append(package_info)

        return {
            "source": sbom_data.get("source", {}).get("path", ""),
            "format": original_format,
            "packages": packages
        }


def run_syft_scan(target: str, output_format: str = "json") -> Dict[str, Any]:
    """便捷函数：生成 SBOM

    Args:
        target: 目标路径
        output_format: 输出格式

    Returns:
        SBOM 数据
    """
    runner = SyftRunner()
    return runner.generate_sbom(target, output_format)
