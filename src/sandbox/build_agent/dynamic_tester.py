"""
DynamicTester Agent - 动态测试器

执行动态漏洞测试。
"""

import requests
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum


class TestResult(Enum):
    """测试结果"""
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class VulnerabilityTest:
    """漏洞测试"""
    vuln_type: str
    endpoint: str
    method: str
    payload: str
    result: TestResult
    confidence: float
    evidence: Optional[str] = None
    cve_id: Optional[str] = None


@dataclass
class DynamicTestReport:
    """动态测试报告"""
    total_tests: int
    vulnerabilities_found: int
    tests: List[VulnerabilityTest]
    duration: float
    target_url: str


class DynamicTester:
    """动态测试器

    对运行中的服务执行动态漏洞测试。
    """

    PAYLOAD_TEMPLATES = {
        "SQL Injection": [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "admin'--",
            "' AND 1=1--",
        ],
        "XSS": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
        ],
        "Command Injection": [
            "; ls",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "; pwd",
        ],
        "SSRF": [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254",
            "file:///etc/passwd",
        ],
        "Path Traversal": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
    }

    def __init__(
        self,
        base_url: str,
        cve_db=None,
        timeout: int = 10,
    ):
        """初始化动态测试器

        Args:
            base_url: 服务基础URL
            cve_db: CVE数据库
            timeout: 请求超时（秒）
        """
        self.base_url = base_url.rstrip("/")
        self.cve_db = cve_db
        self.timeout = timeout
        self.session = requests.Session()
        self.test_results: List[VulnerabilityTest] = []

    def discover_endpoints(self) -> List[Dict[str, Any]]:
        """发现API端点

        Returns:
            端点列表
        """
        print("[DynamicTester] Discovering endpoints...")

        endpoints = []

        try:
            response = self.session.get(f"{self.base_url}/actuator/endpoints", timeout=self.timeout)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for endpoint in data.get("_links", {}).keys():
                        if endpoint != "self":
                            endpoints.append({
                                "path": f"/actuator/{endpoint}" if endpoint != "self" else "/",
                                "method": "GET",
                            })
                except ValueError:
                    pass
        except requests.exceptions.Timeout:
            print(f"[DynamicTester] Timeout discovering actuator endpoints")
        except requests.exceptions.RequestException as e:
            print(f"[DynamicTester] Error discovering actuator endpoints: {e}")
        except Exception as e:
            print(f"[DynamicTester] Unexpected error discovering endpoints: {e}")

        common_paths = [
            "/api", "/api/users", "/api/products", "/api/admin",
            "/login", "/logout", "/register", "/search",
            "/user", "/users", "/admin", "/dashboard",
            "/health", "/info", "/metrics",
        ]

        for path in common_paths:
            try:
                response = self.session.head(f"{self.base_url}{path}", timeout=2)
                if response.status_code < 500:
                    endpoints.append({
                        "path": path,
                        "method": "GET",
                        "status": response.status_code,
                    })
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass

        print(f"[DynamicTester] Found {len(endpoints)} endpoints")
        return endpoints

    def test_vulnerability(
        self,
        vuln_type: str,
        endpoint: str,
        method: str = "GET",
        param_name: str = "input",
        cve_id: Optional[str] = None,
    ) -> VulnerabilityTest:
        """测试漏洞

        Args:
            vuln_type: 漏洞类型
            endpoint: 端点
            method: HTTP方法
            param_name: 参数名
            cve_id: CVE编号

        Returns:
            VulnerabilityTest对象
        """
        payloads = self.PAYLOAD_TEMPLATES.get(vuln_type, [])

        for payload in payloads:
            test = self._send_test_request(
                vuln_type=vuln_type,
                endpoint=endpoint,
                method=method,
                param_name=param_name,
                payload=payload,
                cve_id=cve_id,
            )

            if test.result == TestResult.VULNERABLE:
                return test

        return VulnerabilityTest(
            vuln_type=vuln_type,
            endpoint=endpoint,
            method=method,
            payload="",
            result=TestResult.NOT_VULNERABLE,
            confidence=0.0,
            cve_id=cve_id,
        )

    def _send_test_request(
        self,
        vuln_type: str,
        endpoint: str,
        method: str,
        param_name: str,
        payload: str,
        cve_id: Optional[str],
    ) -> VulnerabilityTest:
        """发送测试请求"""
        url = f"{self.base_url}{endpoint}"

        try:
            if method == "GET":
                response = self.session.get(
                    url,
                    params={param_name: payload},
                    timeout=self.timeout,
                )
            else:
                response = self.session.post(
                    url,
                    data={param_name: payload},
                    timeout=self.timeout,
                )

            evidence = self._analyze_response(vuln_type, payload, response)

            if evidence:
                return VulnerabilityTest(
                    vuln_type=vuln_type,
                    endpoint=endpoint,
                    method=method,
                    payload=payload,
                    result=TestResult.VULNERABLE,
                    confidence=0.8,
                    evidence=evidence,
                    cve_id=cve_id,
                )

        except requests.exceptions.RequestException as e:
            return VulnerabilityTest(
                vuln_type=vuln_type,
                endpoint=endpoint,
                method=method,
                payload=payload,
                result=TestResult.ERROR,
                confidence=0.0,
                evidence=str(e),
                cve_id=cve_id,
            )

        return VulnerabilityTest(
            vuln_type=vuln_type,
            endpoint=endpoint,
            method=method,
            payload=payload,
            result=TestResult.NOT_VULNERABLE,
            confidence=0.0,
            cve_id=cve_id,
        )

    def _analyze_response(self, vuln_type: str, payload: str, response: requests.Response) -> Optional[str]:
        """分析响应判断是否存在漏洞"""
        response_text = response.text.lower()

        if vuln_type == "SQL Injection":
            sql_errors = ["sql", "syntax error", "mysql", "postgresql", "oracle", "sqlite", "odbc"]
            for error in sql_errors:
                if error in response_text:
                    return f"SQL error detected: {error}"

        elif vuln_type == "XSS":
            if payload in response_text:
                return "XSS payload reflected"

        elif vuln_type == "Command Injection":
            cmd_indicators = ["root:", "bin:", "daemon:", "usr", "home", "nobody"]
            for indicator in cmd_indicators:
                if indicator in response_text:
                    return f"Command injection detected: {indicator}"

        elif vuln_type == "SSRF":
            ssrf_indicators = ["localhost", "127.0.0.1", "169.254", "ec2"]
            for indicator in ssrf_indicators:
                if indicator in response_text:
                    return f"SSRF detected: {indicator}"

        elif vuln_type == "Path Traversal":
            path_indicators = ["root:", "[boot loader]", "daemon:", "bin:", "etc"]
            for indicator in path_indicators:
                if indicator in response_text:
                    return f"Path traversal detected: {indicator}"

        return None

    def run_full_test(self, endpoints: List[Dict[str, Any]]) -> DynamicTestReport:
        """运行完整测试

        Args:
            endpoints: 端点列表

        Returns:
            DynamicTestReport对象
        """
        print(f"[DynamicTester] Running full dynamic test...")
        start_time = time.time()

        all_tests = []

        for endpoint_info in endpoints:
            path = endpoint_info.get("path", "/")
            method = endpoint_info.get("method", "GET")

            for vuln_type in self.PAYLOAD_TEMPLATES.keys():
                cve_id = None
                if self.cve_db:
                    cves = self.cve_db.search_by_keyword(vuln_type)
                    if cves:
                        cve_id = cves[0].get("cve_id")

                test = self.test_vulnerability(
                    vuln_type=vuln_type,
                    endpoint=path,
                    method=method,
                    cve_id=cve_id,
                )
                all_tests.append(test)

                if test.result == TestResult.VULNERABLE:
                    print(f"[DynamicTester] [!] {vuln_type} at {path}")

        vulnerabilities = [t for t in all_tests if t.result == TestResult.VULNERABLE]
        duration = time.time() - start_time

        report = DynamicTestReport(
            total_tests=len(all_tests),
            vulnerabilities_found=len(vulnerabilities),
            tests=all_tests,
            duration=duration,
            target_url=self.base_url,
        )

        print(f"[DynamicTester] Test completed: {len(vulnerabilities)}/{len(all_tests)} vulnerabilities found")
        print(f"[DynamicTester] Duration: {duration:.2f}s")

        self.test_results = all_tests
        return report

    def get_vulnerabilities(self) -> List[VulnerabilityTest]:
        """获取发现的漏洞"""
        return [t for t in self.test_results if t.result == TestResult.VULNERABLE]

    def close(self):
        """关闭会话"""
        self.session.close()
