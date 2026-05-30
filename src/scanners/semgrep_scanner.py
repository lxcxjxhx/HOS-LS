"""Semgrep SAST 扫描器

集成 Semgrep 静态应用安全测试工具到 HOS-LS。
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class SemgrepScanner:
    """Semgrep 静态代码扫描器"""

    def __init__(self, timeout: int = 300):
        """初始化 Semgrep 扫描器

        Args:
            timeout: 扫描超时时间（秒），默认 300 秒
        """
        self.timeout = timeout
        self.logger = logger

    def is_available(self) -> bool:
        """检查 Semgrep 是否已安装

        Returns:
            bool: 如果 Semgrep 可用则返回 True
        """
        if shutil.which("semgrep") is not None:
            return True

        try:
            import semgrep  # noqa: F401
            return True
        except ImportError:
            return False

    def _map_severity(self, severity: str) -> str:
        """将 Semgrep 严重性映射到 HOS-LS 标准

        Args:
            severity: Semgrep 严重性级别

        Returns:
            str: HOS-LS 标准严重性
        """
        severity_upper = severity.upper()

        if severity_upper == "CRITICAL":
            return "critical"
        elif severity_upper in ("ERROR", "WARNING"):
            return "high"
        elif severity_upper == "INFO":
            return "medium"
        else:
            return "low"

    def scan(
        self,
        target_path: str,
        timeout: Optional[int] = None,
    ) -> List[Dict]:
        """执行 Semgrep 扫描

        Args:
            target_path: 扫描目标路径
            timeout: 超时时间（秒），默认使用实例设置的 timeout

        Returns:
            List[Dict]: 扫描发现列表，符合 HOS-LS Finding 格式

        Raises:
            FileNotFoundError: 目标路径不存在
            RuntimeError: 扫描执行失败
        """
        target_path_str = str(target_path)
        target = Path(target_path_str)

        if not target.exists():
            self.logger.error(f"目标路径不存在: {target_path_str}")
            raise FileNotFoundError(f"目标路径不存在: {target_path_str}")

        effective_timeout = timeout if timeout is not None else self.timeout

        command = [
            "semgrep",
            "scan",
            "--config=auto",
            "--json",
            "--max-chars-per-line",
            "500",
            "--no-git-ignore",
            "--quiet",
            target_path_str,
        ]

        self.logger.info(f"开始 Semgrep 扫描: {target_path_str}")
        self.logger.debug(f"执行命令: {' '.join(command)}")

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                encoding="utf-8",
            )

            self.logger.debug(f"Semgrep 返回码: {process.returncode}")

            if process.stdout:
                findings = self._parse_output(process.stdout)
                self.logger.info(f"扫描完成，发现 {len(findings)} 个问题")
                return findings
            elif process.stderr:
                self.logger.warning(f"Semgrep stderr 输出: {process.stderr[:500]}")
                return []
            else:
                self.logger.info("扫描完成，未发现任何问题")
                return []

        except subprocess.TimeoutExpired:
            self.logger.error(
                f"Semgrep 扫描超时（{effective_timeout} 秒）: {target_path_str}"
            )
            raise RuntimeError(
                f"Semgrep 扫描超时（{effective_timeout} 秒）"
            )
        except Exception as e:
            self.logger.error(f"Semgrep 扫描执行失败: {str(e)}")
            raise RuntimeError(f"Semgrep 扫描执行失败: {str(e)}")

    def _parse_output(self, json_output: str) -> List[Dict]:
        """解析 Semgrep JSON 输出

        Args:
            json_output: Semgrep 的 JSON 格式输出

        Returns:
            List[Dict]: 转换后的 HOS-LS Finding 列表
        """
        findings = []

        try:
            data = json.loads(json_output)
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON 解析失败: {str(e)}")
            return []

        results = data.get("results", [])

        for result in results:
            try:
                finding = {
                    "file": str(result.get("path", "")),
                    "line": result.get("start", {}).get("line", 0),
                    "column": result.get("start", {}).get("col", 0),
                    "vuln_type": (
                        result.get("extra", {})
                        .get("metadata", {})
                        .get("cwe", ["unknown"])[0]
                        if result.get("extra", {}).get("metadata", {}).get("cwe")
                        else "unknown"
                    ),
                    "severity": self._map_severity(
                        result.get("extra", {}).get("severity", "UNKNOWN")
                    ),
                    "message": result.get("extra", {}).get("message", ""),
                    "code_snippet": result.get("extra", {}).get("lines", ""),
                    "cwe_id": (
                        result.get("extra", {})
                        .get("metadata", {})
                        .get("cwe", [""])[0]
                        if result.get("extra", {}).get("metadata", {}).get("cwe")
                        else ""
                    ),
                    "confidence": 0.85,
                    "metadata": {
                        "source": "semgrep",
                        "rule_id": result.get("check_id", ""),
                        "semgrep_severity": result.get("extra", {}).get("severity", ""),
                    },
                }

                findings.append(finding)

            except Exception as e:
                self.logger.warning(f"解析扫描结果时出错: {str(e)}")
                continue

        return findings
