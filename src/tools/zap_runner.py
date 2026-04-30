"""OWASP ZAP 安全扫描工具

集成 OWASP ZAP (Zed Attack Proxy) 进行 Web 漏洞扫描。
支持 Python API (zapv2) 和 REST API 两种模式。

依赖:
    pip install python-owasp-zap-v2

官网: https://www.zaproxy.org/
"""

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ZAPScanConfig:
    """ZAP扫描配置"""

    api_key: str = ""
    proxy_host: str = "localhost"
    proxy_port: int = 8080
    proxy: Optional[str] = None
    timeout: int = 300
    scan_policy: str = "Default Policy"
    attack_mode: bool = True
    max_children: int = 10
    thread_count: int = 10


@dataclass
class ZAPFinding:
    """ZAP发现的漏洞"""

    name: str
    severity: str
    confidence: str
    url: str
    param: str
    attack: str
    evidence: str
    cwe_id: Optional[str] = None
    wasc_id: Optional[str] = None
    description: str = ""
    solution: str = ""
    other_info: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "param": self.param,
            "attack": self.attack,
            "evidence": self.evidence,
            "cwe_id": self.cwe_id,
            "wasc_id": self.wasc_id,
            "description": self.description,
            "solution": self.solution,
            "other_info": self.other_info,
        }


class ZAPAvailability:
    """ZAP可用性检查器"""

    ZAP_SEVERITY_MAP = {
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "informational": "INFO",
        "info": "INFO",
    }

    ZAP_CONFIDENCE_MAP = {
        "high": 0.9,
        "medium": 0.6,
        "low": 0.3,
        "firm": 0.7,
        "certain": 1.0,
    }

    CWE_MAPPING = {
        "Cross-Site Scripting (XSS)": "CWE-79",
        "SQL Injection": "CWE-89",
        "Path Traversal": "CWE-22",
        "Remote File Inclusion": "CWE-98",
        "XML External Entity": "CWE-611",
        "Cross-Site Request Forgery": "CWE-352",
        "LDAP Injection": "CWE-90",
        "Weak cryptographic hash": "CWE-327",
        "Insecure Cookie": "CWE-614",
        "Missing Authorization": "CWE-862",
        "Missing Authentication": "CWE-306",
        "Improper Input Validation": "CWE-20",
        "OS Command Injection": "CWE-78",
        "Information Exposure": "CWE-200",
    }

    @staticmethod
    def check_zap_installed() -> tuple[bool, str]:
        """检查 ZAP 是否已安装

        Returns:
            (是否安装, ZAP路径或安装命令)
        """
        if os.path.exists("C:\\Program Files\\OWASP\\ZAP\\ZAP.exe"):
            return True, "C:\\Program Files\\OWASP\\ZAP\\ZAP.exe"
        if os.path.exists("C:\\Program Files (x86)\\OWASP\\ZAP\\ZAP.exe"):
            return True, "C:\\Program Files (x86)\\OWASP\\ZAP\\ZAP.exe"

        for path_dir in os.environ.get("PATH", "").split(os.pathsep):
            zap_path = os.path.join(path_dir.strip(), "zap.sh")
            zap_exe = os.path.join(path_dir.strip(), "zap.bat")
            if os.path.exists(zap_path):
                return True, zap_path
            if os.path.exists(zap_exe):
                return True, zap_exe

        return False, "ZAP not found. Install from: https://www.zaproxy.org/download/"

    @staticmethod
    def check_python_api_available() -> bool:
        """检查 Python ZAP API 是否可用

        Returns:
            API是否可用
        """
        try:
            import zapv2
            return True
        except ImportError:
            return False

    @staticmethod
    def install_python_api() -> bool:
        """安装 Python ZAP API

        Returns:
            是否安装成功
        """
        try:
            subprocess.run(
                ["pip", "install", "python-owasp-zap-v2"],
                capture_output=True,
                timeout=60,
            )
            return True
        except Exception:
            return False


class ZAPRunner:
    """OWASP ZAP 扫描器

    支持两种模式:
    1. Python API 模式 (zapv2) - 需要 ZAP Desktop/Web GUI 运行
    2. REST API 模式 - 需要 ZAP Daemon 模式 (zap.sh/zap.bat -daemon)
    """

    def __init__(self, config: Optional[ZAPScanConfig] = None):
        self.config = config or ZAPScanConfig()
        self._zap = None
        self._connected = False
        self._api_mode = False

        self.zap_available, self.zap_path = ZAPAvailability.check_zap_installed()
        self.python_api_available = ZAPAvailability.check_python_api_available()

    def is_available(self) -> bool:
        """检查 ZAP 是否可用

        Returns:
            ZAP是否可用(任一模式)
        """
        if not self.zap_available and not self.python_api_available:
            logger.warning("ZAP not installed and python-owasp-zap-v2 not available")
            return False

        if self.python_api_available:
            return self._connect_via_api()

        return True

    def _connect_via_api(self) -> bool:
        """通过 Python API 连接 ZAP

        Returns:
            是否连接成功
        """
        if self._connected:
            return True

        try:
            import zapv2

            proxy = self.config.proxy or f"http://{self.config.proxy_host}:{self.config.proxy_port}"

            self._zap = zapv2.ZAPV2(
                proxies={
                    "http": proxy,
                    "https": proxy,
                },
                apikey=self.config.api_key,
            )

            self._connected = True
            self._api_mode = True
            logger.info(f"Connected to ZAP via API: {proxy}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to ZAP API: {e}")
            self._connected = False
            return False

    def scan_url(self, target_url: str) -> List[ZAPFinding]:
        """扫描单个URL

        Args:
            target_url: 目标URL

        Returns:
            发现的漏洞列表
        """
        if not self.is_available():
            logger.warning("ZAP not available, skipping scan")
            return []

        if not target_url.startswith(("http://", "https://")):
            target_url = f"http://{target_url}"

        try:
            if self._api_mode and self._zap:
                return self._scan_via_api(target_url)
            else:
                logger.warning("ZAP API not connected, use start_daemon() first")
                return []

        except Exception as e:
            logger.error(f"ZAP scan error: {e}")
            return []

    def _scan_via_api(self, target_url: str) -> List[ZAPFinding]:
        """通过 API 执行扫描

        Args:
            target_url: 目标URL

        Returns:
            发现的漏洞列表
        """
        findings = []

        try:
            logger.info(f"Starting ZAP scan: {target_url}")

            self._zap.urlopen(target_url)
            time.sleep(2)

            logger.info("Spidering target...")
            spider_id = self._zap.spider.scan(target_url)
            while int(self._zap.spider.status(spider_id)) < 100:
                time.sleep(1)

            logger.info("Active scanning...")
            scan_id = self._zap.ascan.scan(target_url, recurse=True)

            while int(self._zap.ascan.status(scan_id)) < 100:
                time.sleep(1)
                logger.info(f"Scan progress: {self._zap.ascan.status(scan_id)}%")

            alerts = self._zap.core.alerts()

            for alert_data in alerts:
                finding = self._parse_alert(alert_data)
                findings.append(finding)

            logger.info(f"ZAP scan completed, found {len(findings)} issues")

        except Exception as e:
            logger.error(f"ZAP API scan error: {e}")

        return findings

    def _parse_alert(self, alert_data: Dict[str, Any]) -> ZAPFinding:
        """解析ZAP告警数据

        Args:
            alert_data: ZAP告警数据

        Returns:
            ZAPFinding对象
        """
        name = alert_data.get("name", "Unknown")
        cwe_id = ZAPAvailability.CWE_MAPPING.get(name)

        return ZAPFinding(
            name=name,
            severity=ZAPAvailability.ZAP_SEVERITY_MAP.get(
                alert_data.get("risk", "").lower(), "INFO"
            ),
            confidence=str(alert_data.get("confidence", "Medium")),
            url=alert_data.get("url", ""),
            param=alert_data.get("param", ""),
            attack=alert_data.get("attack", ""),
            evidence=alert_data.get("evidence", ""),
            cwe_id=cwe_id,
            wasc_id=alert_data.get("wascId"),
            description=alert_data.get("desc", ""),
            solution=alert_data.get("solution", ""),
            other_info=alert_data.get("otherInfo", ""),
        )

    def spider_url(self, target_url: str) -> List[str]:
        """爬取URL获取所有链接

        Args:
            target_url: 目标URL

        Returns:
            发现的所有URL
        """
        if not self._api_mode or not self._zap:
            logger.warning("ZAP API not connected")
            return []

        try:
            self._zap.urlopen(target_url)
            self._zap.spider.scan(target_url)

            time.sleep(5)

            return self._zap.spider.all_urls

        except Exception as e:
            logger.error(f"ZAP spider error: {e}")
            return []

    def start_daemon(self, extra_args: Optional[List[str]] = None) -> subprocess.Popen:
        """启动 ZAP 守护进程

        Args:
            extra_args: 额外启动参数

        Returns:
            ZAP进程
        """
        if not self.zap_available:
            raise RuntimeError("ZAP not installed")

        cmd = [self.zap_path, "-daemon"]

        if self.config.api_key:
            cmd.extend(["-config", f"api.key={self.config.api_key}"])

        cmd.extend([
            "-config", f"proxy.port={self.config.proxy_port}",
            "-config", f"proxy.host={self.config.proxy_host}",
        ])

        if extra_args:
            cmd.extend(extra_args)

        logger.info(f"Starting ZAP daemon: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(5)

        return process

    def stop_daemon(self) -> None:
        """停止 ZAP 守护进程"""
        if self._zap and self._api_mode:
            try:
                self._zap.core.shutdown()
                logger.info("ZAP daemon stopped")
            except Exception as e:
                logger.error(f"Error stopping ZAP daemon: {e}")

    def get_scan_progress(self) -> int:
        """获取扫描进度

        Returns:
            扫描进度百分比
        """
        if not self._api_mode or not self._zap:
            return 0

        try:
            scans = self._zap.ascan.scans
            if scans:
                return int(float(scans[0].get("status", 0)))
        except Exception:
            pass

        return 0

    def generate_report(self, output_path: str, format: str = "json") -> bool:
        """生成扫描报告

        Args:
            output_path: 输出文件路径
            format: 报告格式 (json, html, xml)

        Returns:
            是否成功
        """
        if not self._api_mode or not self._zap:
            logger.warning("ZAP API not connected")
            return False

        try:
            if format == "json":
                report = self._zap.core.jsonreport()
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(report)
            elif format == "html":
                report = self._zap.core.htmlreport()
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(report)
            elif format == "xml":
                report = self._zap.core.xmlreport()
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(report)
            else:
                logger.error(f"Unsupported format: {format}")
                return False

            logger.info(f"Report saved to: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return False


def run_zap_scan(
    target: str,
    config: Optional[ZAPScanConfig] = None,
    timeout: int = 300,
) -> List[Dict[str, Any]]:
    """运行 ZAP 扫描的便捷函数

    Args:
        target: 目标URL或域名
        config: ZAP扫描配置
        timeout: 超时时间

    Returns:
        漏洞发现列表
    """
    runner = ZAPRunner(config)

    if not runner.is_available():
        logger.warning("ZAP not available, attempting auto-install...")

        if ZAPAvailability.install_python_api():
            logger.info("python-owasp-zap-v2 installed successfully")
            runner = ZAPRunner(config)
        else:
            logger.error("Failed to install python-owasp-zap-v2")
            return []

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    findings = runner.scan_url(target)

    return [f.to_dict() for f in findings]


def check_zap_status() -> Dict[str, Any]:
    """检查 ZAP 状态

    Returns:
        状态信息字典
    """
    zap_available, zap_path = ZAPAvailability.check_zap_installed()
    python_api_available = ZAPAvailability.check_python_api_available()

    status = {
        "zap_installed": zap_available,
        "zap_path": zap_path,
        "python_api_available": python_api_available,
        "can_scan": zap_available or python_api_available,
        "install_instructions": "Install ZAP from: https://www.zaproxy.org/download/",
    }

    if not python_api_available:
        status["pip_install_command"] = "pip install python-owasp-zap-v2"

    return status
