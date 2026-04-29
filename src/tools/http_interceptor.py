"""HTTP 拦截测试工具

提供 HTTP/HTTPS 流量拦截、修改和重放功能。
支持 mitmproxy 作为 Python 原生的替代方案。

依赖:
    pip install mitmproxy httpx

用途:
    - Web 漏洞检测的流量分析
    - 请求/响应修改测试
    - Session 令牌提取
    - CSRF Token 抓取
"""

import json
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class HTTPRequest:
    """HTTP请求"""

    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    params: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "params": self.params,
            "timestamp": self.timestamp,
        }


@dataclass
class HTTPResponse:
    """HTTP响应"""

    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "elapsed": self.elapsed,
            "timestamp": self.timestamp,
        }


@dataclass
class HTTPTransaction:
    """HTTP事务 (请求-响应对)"""

    request: HTTPRequest
    response: HTTPResponse
    finding_type: Optional[str] = None
    finding_evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
            "finding_type": self.finding_type,
            "finding_evidence": self.finding_evidence,
        }


@dataclass
class SecurityTestResult:
    """安全测试结果"""

    test_name: str
    passed: bool
    evidence: str
    severity: str = "INFO"
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_name": self.test_name,
            "passed": self.passed,
            "evidence": self.evidence,
            "severity": self.severity,
            "recommendations": self.recommendations,
        }


class MitmproxyAvailability:
    """mitmproxy 可用性检查器"""

    @staticmethod
    def check_installed() -> tuple[bool, str]:
        """检查 mitmproxy 是否已安装

        Returns:
            (是否安装, mitmproxy路径)
        """
        for path_dir in os.environ.get("PATH", "").split(os.pathsep):
            for name in ["mitmdump", "mitmproxy", "mitmweb"]:
                full_path = os.path.join(path_dir.strip(), name)
                if os.path.exists(full_path):
                    return True, full_path
                if os.path.exists(full_path + ".exe"):
                    return True, full_path + ".exe"

        return False, "mitmproxy not found. Install from: https://mitmproxy.org/"

    @staticmethod
    def check_python_available() -> bool:
        """检查 mitmproxy Python包是否可用

        Returns:
            是否可用
        """
        try:
            import mitmproxy
            return True
        except ImportError:
            return False

    @staticmethod
    def install_python_package() -> bool:
        """安装 mitmproxy Python包

        Returns:
            是否安装成功
        """
        try:
            subprocess.run(
                ["pip", "install", "mitmproxy"],
                capture_output=True,
                timeout=120,
            )
            return True
        except Exception:
            return False


class HTTPInterceptor:
    """HTTP 拦截器

    提供 HTTP 流量拦截和分析功能。
    支持两种模式:
    1. mitmproxy 模式 - 需要安装 mitmproxy
    2. httpx 模式 - 纯 Python HTTP 客户端，用于主动测试
    """

    def __init__(self, proxy_url: Optional[str] = None):
        self.proxy_url = proxy_url or "http://localhost:8080"
        self.mitm_available, self.mitm_path = MitmproxyAvailability.check_installed()
        self.transactions: List[HTTPTransaction] = []
        self._httpx_client: Optional[httpx.Client] = None

    def is_available(self) -> bool:
        """检查拦截器是否可用"""
        return self.mitm_available or HTTPX_AVAILABLE

    def start_proxy_capture(
        self,
        output_file: Optional[str] = None,
        callback: Optional[Callable[[HTTPTransaction], None]] = None,
    ) -> subprocess.Popen:
        """启动 mitmproxy 进行流量捕获

        Args:
            output_file: 输出文件路径
            callback: 处理每个事务的回调函数

        Returns:
            mitmproxy进程
        """
        if not self.mitm_available:
            raise RuntimeError("mitmproxy not installed")

        output_file = output_file or tempfile.mktemp(suffix=".mitm")

        cmd = [
            self.mitm_path,
            "-w", output_file,
            "--anticache",
        ]

        if self.proxy_url:
            parsed = urlparse(self.proxy_url)
            cmd.extend(["--listen-host", parsed.hostname or "localhost"])
            cmd.extend(["--listen-port", str(parsed.port or 8080)])

        logger.info(f"Starting mitmproxy: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        return process

    def stop_proxy_capture(self, process: subprocess.Popen) -> None:
        """停止流量捕获

        Args:
            process: mitmproxy进程
        """
        if process:
            process.terminate()
            process.wait(timeout=5)

    def load_transactions(self, mitm_dump_file: str) -> List[HTTPTransaction]:
        """加载 mitmdump 导出的流量

        Args:
            mitm_dump_file: mitmdump 导出的文件

        Returns:
            HTTP事务列表
        """
        transactions = []

        try:
            import mitmproxy.io
            from mitmproxy import contentviews

            with open(mitm_dump_file, "rb") as f:
                reader = mitmproxy.io.FlowReader(f)

                for flow in reader.stream():
                    if hasattr(flow, "request") and hasattr(flow, "response"):
                        request = HTTPRequest(
                            method=flow.request.method,
                            url=str(flow.request.url),
                            headers=dict(flow.request.headers),
                            body=flow.request.content.decode("utf-8", errors="replace")
                                if flow.request.content else None,
                        )

                        response = HTTPResponse(
                            status_code=flow.response.status_code,
                            headers=dict(flow.response.headers),
                            body=flow.response.content.decode("utf-8", errors="replace")
                                if flow.response.content else "",
                            elapsed=flow.response.timestamp - flow.request.timestamp
                                if hasattr(flow.response, "timestamp") else 0,
                        )

                        transactions.append(HTTPTransaction(request, response))

        except Exception as e:
            logger.error(f"Failed to load mitm dump: {e}")

        self.transactions.extend(transactions)
        return transactions

    def create_httpx_client(self, follow_redirects: bool = True) -> httpx.Client:
        """创建 httpx 客户端用于主动测试

        Args:
            follow_redirects: 是否跟随重定向

        Returns:
            httpx.Client实例
        """
        if not HTTPX_AVAILABLE:
            raise RuntimeError("httpx not available, install with: pip install httpx")

        self._httpx_client = httpx.Client(
            proxy=self.proxy_url if self.proxy_url else None,
            follow_redirects=follow_redirects,
            timeout=30.0,
        )

        return self._httpx_client

    def test_endpoint(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> HTTPTransaction:
        """测试端点

        Args:
            method: HTTP方法
            url: 目标URL
            headers: 请求头
            data: POST数据
            params: URL参数

        Returns:
            HTTP事务
        """
        if not self._httpx_client:
            self.create_httpx_client()

        headers = headers or {}
        headers.setdefault("User-Agent", "HOS-LS Security Scanner/1.0")

        start_time = time.time()

        try:
            response = self._httpx_client.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                params=params,
            )

            elapsed = time.time() - start_time

            request = HTTPRequest(
                method=method,
                url=url,
                headers=headers,
                body=json.dumps(data) if data else None,
                params=params or {},
            )

            resp = HTTPResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                elapsed=elapsed,
            )

            transaction = HTTPTransaction(request, resp)
            self.transactions.append(transaction)

            return transaction

        except Exception as e:
            logger.error(f"HTTP test error: {e}")
            raise

    def analyze_security_headers(self, url: str) -> List[SecurityTestResult]:
        """分析 URL 的安全头部

        Args:
            url: 目标URL

        Returns:
            安全测试结果列表
        """
        results = []

        if not self._httpx_client:
            self.create_httpx_client()

        try:
            response = self._httpx_client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            security_headers = {
                "strict-transport-security": "HSTS",
                "content-security-policy": "CSP",
                "x-content-type-options": "X-Content-Type-Options",
                "x-frame-options": "X-Frame-Options",
                "x-xss-protection": "X-XSS-Protection",
                "referrer-policy": "Referrer-Policy",
                "permissions-policy": "Permissions-Policy",
            }

            for header, name in security_headers.items():
                if header in headers:
                    results.append(SecurityTestResult(
                        test_name=f"{name} Header Present",
                        passed=True,
                        evidence=f"{header}: {headers[header]}",
                        severity="INFO",
                    ))
                else:
                    results.append(SecurityTestResult(
                        test_name=f"{name} Header Missing",
                        passed=False,
                        evidence=f"Header {header} not found",
                        severity="MEDIUM",
                        recommendations=[f"Add {header} header to improve security"],
                    ))

            if "x-powered-by" in headers or "server" in headers:
                server_info = headers.get("x-powered-by", "") + " " + headers.get("server", "")
                results.append(SecurityTestResult(
                    test_name="Server Information Disclosure",
                    passed=False,
                    evidence=server_info.strip(),
                    severity="LOW",
                    recommendations=["Hide server version information"],
                ))

        except Exception as e:
            logger.error(f"Security header analysis error: {e}")

        return results

    def test_sqli(self, url: str, param: str, value: str) -> SecurityTestResult:
        """测试 SQL 注入

        Args:
            url: 目标URL
            param: 参数名
            value: 参数值

        Returns:
            测试结果
        """
        if not self._httpx_client:
            self.create_httpx_client()

        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users;--",
            "1' AND '1'='1",
        ]

        for payload in payloads:
            try:
                response = self._httpx_client.get(
                    url,
                    params={param: payload},
                )

                text = response.text.lower()

                sql_errors = [
                    "sql syntax",
                    "mysql",
                    "postgresql",
                    "oracle",
                    "sqlite",
                    "sql error",
                    "syntax error",
                ]

                for error in sql_errors:
                    if error in text:
                        return SecurityTestResult(
                            test_name="SQL Injection Vulnerability",
                            passed=True,
                            evidence=f"Payload: {payload} triggered SQL error: {error}",
                            severity="HIGH",
                            recommendations=[
                                "Use parameterized queries",
                                "Implement input validation",
                                "Use ORM frameworks",
                            ],
                        )

                if response.status_code == 500:
                    return SecurityTestResult(
                        test_name="Potential SQL Injection",
                        passed=True,
                        evidence=f"Payload: {payload} caused server error (500)",
                        severity="MEDIUM",
                        recommendations=["Investigate potential SQL injection"],
                    )

            except Exception:
                continue

        return SecurityTestResult(
            test_name="SQL Injection Test",
            passed=True,
            evidence="No SQL injection detected with test payloads",
            severity="INFO",
        )

    def test_xss(self, url: str, param: str, value: str) -> SecurityTestResult:
        """测试 XSS

        Args:
            url: 目标URL
            param: 参数名
            value: 参数值

        Returns:
            测试结果
        """
        if not self._httpx_client:
            self.create_httpx_client()

        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
        ]

        for payload in payloads:
            try:
                response = self._httpx_client.get(
                    url,
                    params={param: payload},
                )

                if payload in response.text:
                    return SecurityTestResult(
                        test_name="XSS Vulnerability",
                        passed=True,
                        evidence=f"Payload reflected in response: {payload[:50]}...",
                        severity="HIGH",
                        recommendations=[
                            "Implement output encoding",
                            "Use Content-Security-Policy",
                            "Sanitize user input",
                        ],
                    )

            except Exception:
                continue

        return SecurityTestResult(
            test_name="XSS Test",
            passed=True,
            evidence="No XSS detected with test payloads",
            severity="INFO",
        )

    def test_csrf(self, url: str) -> SecurityTestResult:
        """测试 CSRF 保护

        Args:
            url: 目标URL

        Returns:
            测试结果
        """
        if not self._httpx_client:
            self.create_httpx_client()

        try:
            response = self._httpx_client.get(url)
            headers = {k.lower(): k for k in response.headers}

            csrf_headers = ["x-csrf-token", "x-xsrf-token", "csrf-token"]

            has_csrf_header = any(h in headers for h in csrf_headers)
            has_csrf_cookie = any("csrf" in k.lower() for k in response.headers)

            if has_csrf_header or has_csrf_cookie:
                return SecurityTestResult(
                    test_name="CSRF Protection Present",
                    passed=True,
                    evidence="CSRF token header or cookie found",
                    severity="INFO",
                )
            else:
                return SecurityTestResult(
                    test_name="CSRF Protection Missing",
                    passed=False,
                    evidence="No CSRF token header or cookie detected",
                    severity="MEDIUM",
                    recommendations=[
                        "Implement CSRF tokens",
                        "Use SameSite cookie attribute",
                    ],
                )

        except Exception as e:
            logger.error(f"CSRF test error: {e}")
            return SecurityTestResult(
                test_name="CSRF Test",
                passed=False,
                evidence=f"Error: {e}",
                severity="INFO",
            )

    def close(self) -> None:
        """关闭客户端连接"""
        if self._httpx_client:
            self._httpx_client.close()
            self._httpx_client = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def run_http_security_scan(
    target_url: str,
    test_sqli: bool = True,
    test_xss: bool = True,
    test_headers: bool = True,
    test_csrf: bool = False,
) -> Dict[str, Any]:
    """运行 HTTP 安全扫描的便捷函数

    Args:
        target_url: 目标URL
        test_sqli: 是否测试SQL注入
        test_xss: 是否测试XSS
        test_headers: 是否检查安全头部
        test_csrf: 是否检查CSRF保护

    Returns:
        扫描结果
    """
    results = []

    try:
        with HTTPInterceptor() as interceptor:
            if not interceptor.is_available():
                return {
                    "success": False,
                    "error": "No HTTP interceptor available (install mitmproxy or httpx)",
                    "results": [],
                }

            if test_headers:
                results.extend(interceptor.analyze_security_headers(target_url))

            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            if test_csrf:
                results.append(interceptor.test_csrf(target_url))

            if test_sqli or test_xss:
                params = parse_qs(parsed.query) if parsed.query else {}

                if not params:
                    params = {"id": "1"}

                param_name = list(params.keys())[0]
                param_value = list(params.values())[0][0]

                if test_sqli:
                    sqli_result = interceptor.test_sqli(target_url, param_name, param_value)
                    results.append(sqli_result)

                if test_xss:
                    xss_result = interceptor.test_xss(target_url, param_name, param_value)
                    results.append(xss_result)

    except Exception as e:
        logger.error(f"HTTP security scan error: {e}")
        return {
            "success": False,
            "error": str(e),
            "results": [],
        }

    return {
        "success": True,
        "target": target_url,
        "results": [r.to_dict() for r in results],
    }


def check_interceptor_status() -> Dict[str, Any]:
    """检查 HTTP 拦截器状态

    Returns:
        状态信息
    """
    mitm_available, mitm_path = MitmproxyAvailability.check_installed()
    mitm_python = MitmproxyAvailability.check_python_available()

    status = {
        "mitmproxy_installed": mitm_available,
        "mitmproxy_path": mitm_path,
        "httpx_available": HTTPX_AVAILABLE,
        "can_intercept": mitm_available or HTTPX_AVAILABLE,
    }

    if not mitm_available:
        status["install_instructions"] = "Install mitmproxy from: https://mitmproxy.org/"

    if not HTTPX_AVAILABLE:
        status["pip_install"] = "pip install httpx mitmproxy"

    return status
