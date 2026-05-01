"""API 安全测试器

支持 REST API、GraphQL 等 API 协议的专门安全测试。
支持 OpenAPI/Swagger 规范解析和自动测试。

依赖:
    pip install httpx requests jsonschema

用途:
    - REST API 安全测试
    - GraphQL 安全测试
    - OpenAPI 规范解析
    - API 端点枚举
"""

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class APIEndpoint:
    """API端点"""

    path: str
    method: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Optional[Dict] = None
    responses: Dict[str, Any] = field(default_factory=dict)
    security: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "parameters": self.parameters,
            "request_body": self.request_body,
            "responses": self.responses,
            "security": self.security,
            "tags": self.tags,
        }


@dataclass
class SecurityFinding:
    """安全问题发现"""

    endpoint: str
    method: str
    severity: str
    title: str
    description: str
    evidence: str
    cwe_id: Optional[str] = None
    remediation: str = ""
    payload: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "cwe_id": self.cwe_id,
            "remediation": self.remediation,
            "payload": self.payload,
        }


class OpenAPIParser:
    """OpenAPI 规范解析器"""

    def __init__(self, spec: Optional[Dict[str, Any]] = None):
        self.spec = spec
        self.endpoints: List[APIEndpoint] = []

        if spec:
            self.parse(spec)

    def parse(self, spec: Dict[str, Any]) -> None:
        """解析 OpenAPI 规范

        Args:
            spec: OpenAPI 规范字典
        """
        self.spec = spec
        self.endpoints = []

        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            for method in ["get", "post", "put", "patch", "delete", "options", "head"]:
                if method not in path_item:
                    continue

                operation = path_item[method]

                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=operation.get("parameters", []),
                    request_body=operation.get("requestBody"),
                    responses=operation.get("responses", {}),
                    security=operation.get("security", []),
                    tags=operation.get("tags", []),
                )

                self.endpoints.append(endpoint)

    @classmethod
    def from_file(cls, file_path: str) -> "OpenAPIParser":
        """从文件加载规范

        Args:
            file_path: OpenAPI 规范文件路径

        Returns:
            OpenAPIParser 实例
        """
        with open(file_path, "r", encoding="utf-8") as f:
            spec = json.load(f)
        return cls(spec)

    @classmethod
    def from_url(cls, url: str) -> Optional["OpenAPIParser"]:
        """从 URL 加载规范

        Args:
            url: OpenAPI 规范 URL

        Returns:
            OpenAPIParser 实例或 None
        """
        if not HTTPX_AVAILABLE:
            logger.warning("httpx not available, cannot load OpenAPI from URL")
            return None

        try:
            response = httpx.get(url, timeout=30)
            if response.status_code == 200:
                spec = response.json()
                return cls(spec)
        except Exception as e:
            logger.error(f"Failed to load OpenAPI from URL: {e}")

        return None


class RESTAPITester:
    """REST API 测试器"""

    GRAPHQL_VULNS = {
        "introspection": {
            "title": "GraphQL Introspection Enabled",
            "severity": "INFO",
            "cwe_id": "CWE-200",
            "description": "GraphQL introspection query is enabled, exposing schema details",
            "remediation": "Disable introspection in production",
        },
        "alias_based": {
            "title": "Alias-Based DoS Vulnerability",
            "severity": "HIGH",
            "cwe_id": "CWE-400",
            "description": "GraphQL is vulnerable to alias-based DoS attacks",
            "remediation": "Implement query complexity analysis and depth limiting",
        },
        "batch_query": {
            "title": "Batch Query Attack Possible",
            "severity": "MEDIUM",
            "cwe_id": "CWE-287",
            "description": "GraphQL batch queries are enabled",
            "remediation": "Disable batch queries or implement rate limiting",
        },
        "depth_limit": {
            "title": "Depth Limit Bypass",
            "severity": "MEDIUM",
            "cwe_id": "CWE-400",
            "description": "Query depth limit can be bypassed",
            "remediation": "Implement proper depth limiting",
        },
    }

    def __init__(self, base_url: str = "", headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.headers = headers or {}
        self.default_headers = {
            "User-Agent": "HOS-LS Security Scanner/1.0",
            "Accept": "application/json",
        }
        self.default_headers.update(self.headers)

        self.findings: List[SecurityFinding] = []

    def test_endpoint(
        self,
        endpoint: APIEndpoint,
        test_auth: bool = True,
        test_params: bool = True,
    ) -> List[SecurityFinding]:
        """测试 API 端点

        Args:
            endpoint: API端点
            test_auth: 是否测试认证
            test_params: 是否测试参数

        Returns:
            安全问题列表
        """
        findings = []
        url = urljoin(self.base_url + "/", endpoint.path.lstrip("/"))

        if test_params:
            findings.extend(self._test_parameters(endpoint, url))

        if test_auth:
            findings.extend(self._test_authentication(endpoint, url))

        findings.extend(self._test_common_vulnerabilities(endpoint, url))

        return findings

    def _test_parameters(
        self,
        endpoint: APIEndpoint,
        url: str,
    ) -> List[SecurityFinding]:
        """测试端点参数

        Args:
            endpoint: API端点
            url: 完整URL

        Returns:
            发现的问题
        """
        findings = []

        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "1' AND '1'='1",
            "'; DROP TABLE users;--",
        ]

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'-alert('XSS')-'",
        ]

        for param in endpoint.parameters:
            param_name = param.get("name", "")
            param_in = param.get("in", "query")
            param_type = param.get("type", "string")

            if param_type == "string":
                for payload in sqli_payloads:
                    findings.extend(self._test_sqli(url, param_name, payload, endpoint, param_in))
                for payload in xss_payloads:
                    findings.extend(self._test_xss(url, param_name, payload, endpoint, param_in))

        return findings

    def _test_sqli(
        self,
        url: str,
        param: str,
        payload: str,
        endpoint: APIEndpoint,
        param_in: str,
    ) -> List[SecurityFinding]:
        """测试 SQL 注入

        Args:
            url: URL
            param: 参数名
            payload: 测试payload
            endpoint: API端点
            param_in: 参数位置

        Returns:
            发现的问题
        """
        findings = []

        try:
            params = {param: payload}
            headers = self.default_headers.copy()

            if param_in == "header":
                headers[param] = payload
                params = {}

            method = endpoint.method.lower()
            if method == "get":
                response = httpx.get(url, params=params, headers=headers, timeout=10)
            elif method == "post":
                response = httpx.post(url, json=params, headers=headers, timeout=10)
            else:
                return findings

            text = response.text.lower()

            sql_errors = [
                "sql syntax",
                "mysql",
                "postgresql",
                "oracle",
                "sqlite",
                "sql error",
                "syntax error",
                "warning: mysql",
            ]

            for error in sql_errors:
                if error in text:
                    findings.append(SecurityFinding(
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        severity="HIGH",
                        title="Potential SQL Injection",
                        description=f"SQL injection vulnerability potentially exists in parameter '{param}'",
                        evidence=f"Payload: {payload} triggered SQL error: {error}",
                        cwe_id="CWE-89",
                        remediation="Use parameterized queries and input validation",
                        payload=payload,
                    ))
                    break

        except Exception as e:
            logger.debug(f"SQLi test error for {param}: {e}")

        return findings

    def _test_xss(
        self,
        url: str,
        param: str,
        payload: str,
        endpoint: APIEndpoint,
        param_in: str,
    ) -> List[SecurityFinding]:
        """测试 XSS

        Args:
            url: URL
            param: 参数名
            payload: 测试payload
            endpoint: API端点
            param_in: 参数位置

        Returns:
            发现的问题
        """
        findings = []

        try:
            params = {param: payload}
            headers = self.default_headers.copy()

            if param_in == "header":
                headers[param] = payload
                params = {}

            method = endpoint.method.lower()
            if method == "get":
                response = httpx.get(url, params=params, headers=headers, timeout=10)
            elif method == "post":
                response = httpx.post(url, json=params, headers=headers, timeout=10)
            else:
                return findings

            if payload in response.text:
                findings.append(SecurityFinding(
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    severity="MEDIUM",
                    title="Potential XSS Vulnerability",
                    description=f"XSS vulnerability potentially exists in parameter '{param}'",
                    evidence=f"Payload reflected in response: {payload[:50]}...",
                    cwe_id="CWE-79",
                    remediation="Implement output encoding and input validation",
                    payload=payload,
                ))

        except Exception as e:
            logger.debug(f"XSS test error for {param}: {e}")

        return findings

    def _test_authentication(
        self,
        endpoint: APIEndpoint,
        url: str,
    ) -> List[SecurityFinding]:
        """测试认证

        Args:
            endpoint: API端点
            url: URL

        Returns:
            发现的问题
        """
        findings = []

        if not endpoint.security:
            findings.append(SecurityFinding(
                endpoint=endpoint.path,
                method=endpoint.method,
                severity="MEDIUM",
                title="No Authentication Required",
                description=f"Endpoint does not require authentication",
                evidence=f"Method: {endpoint.method}, Path: {endpoint.path}",
                cwe_id="CWE-306",
                remediation="Implement proper authentication for this endpoint",
            ))

        try:
            response = httpx.get(url, headers=self.default_headers, timeout=10)

            if response.status_code == 200:
                findings.append(SecurityFinding(
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    severity="LOW",
                    title="No Authorization Check",
                    description="Endpoint accessible without authorization",
                    evidence=f"Status code: {response.status_code}",
                    cwe_id="CWE-862",
                    remediation="Implement proper authorization checks",
                ))

        except Exception:
            pass

        return findings

    def _test_common_vulnerabilities(
        self,
        endpoint: APIEndpoint,
        url: str,
    ) -> List[SecurityFinding]:
        """测试常见漏洞

        Args:
            endpoint: API端点
            url: URL

        Returns:
            发现的问题
        """
        findings = []

        if endpoint.method.upper() in ["PUT", "DELETE", "PATCH"]:
            findings.append(SecurityFinding(
                endpoint=endpoint.path,
                method=endpoint.method,
                severity="INFO",
                title="Sensitive HTTP Method",
                description="Endpoint uses a sensitive HTTP method",
                evidence=f"Method: {endpoint.method}",
                cwe_id="CWE-200",
                remediation="Ensure proper authorization for destructive operations",
            ))

        sensitive_params = ["token", "key", "secret", "password", "auth"]
        for param in endpoint.parameters:
            param_name = param.get("name", "").lower()
            if any(s in param_name for s in sensitive_params):
                findings.append(SecurityFinding(
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    severity="INFO",
                    title="Sensitive Parameter",
                    description=f"Endpoint uses sensitive parameter: {param.get('name')}",
                    evidence=f"Parameter: {param.get('name')}, Type: {param.get('type')}",
                    cwe_id="CWE-200",
                    remediation="Ensure sensitive parameters are properly protected",
                ))

        return findings


class GraphQLTester:
    """GraphQL 安全测试器"""

    def __init__(self, endpoint: str, headers: Optional[Dict[str, str]] = None):
        self.endpoint = endpoint
        self.headers = headers or {}
        self.introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...TypeRef
                }
                directives {
                    name
                    description
                    args {
                        ...InputValueRef
                    }
                }
            }
        }

        fragment TypeRef on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValueRef
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValueRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
        }

        fragment InputValueRef on __InputValue {
            name
            description
            type {
                ...TypeRef
            }
            defaultValue
        }
        """

    def is_available(self) -> bool:
        """检查 GraphQL 是否可用

        Returns:
            是否可用
        """
        if not HTTPX_AVAILABLE:
            return False

        try:
            response = httpx.post(
                self.endpoint,
                json={"query": "{ __typename }"},
                headers=self.headers,
                timeout=10,
            )
            return response.status_code == 200
        except Exception:
            return False

    def test_introspection(self) -> List[SecurityFinding]:
        """测试 GraphQL Introspection

        Returns:
            发现的问题
        """
        findings = []

        try:
            response = httpx.post(
                self.endpoint,
                json={"query": self.introspection_query},
                headers=self.headers,
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()

                if "errors" not in data:
                    findings.append(SecurityFinding(
                        endpoint=self.endpoint,
                        method="POST",
                        severity="INFO",
                        title="GraphQL Introspection Enabled",
                        description="GraphQL introspection is enabled, exposing full schema",
                        evidence="Introspection query returned schema data",
                        cwe_id="CWE-200",
                        remediation="Disable introspection in production environments",
                    ))

                    try:
                        schema = data.get("data", {}).get("__schema", {})
                        query_type = schema.get("queryType", {})
                        mutation_type = schema.get("mutationType", {})

                        if query_type:
                            findings.append(SecurityFinding(
                                endpoint=self.endpoint,
                                method="POST",
                                severity="INFO",
                                title=f"Query Type: {query_type.get('name', 'Unknown')}",
                                description="Query type information exposed",
                                evidence=f"Query type: {query_type}",
                                cwe_id=None,
                                remediation="Consider restricting schema exposure",
                            ))

                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"GraphQL introspection test error: {e}")

        return findings

    def test_batch_query(self) -> List[SecurityFinding]:
        """测试批量查询

        Returns:
            发现的问题
        """
        findings = []

        batch_query = """
        query q1 { __typename }
        query q2 { __typename }
        query q3 { __typename }
        """

        try:
            response = httpx.post(
                self.endpoint,
                json=[{"query": "query q1 { __typename }"}, {"query": "query q2 { __typename }"}],
                headers=self.headers,
                timeout=10,
            )

            if response.status_code == 200:
                findings.append(SecurityFinding(
                    endpoint=self.endpoint,
                    method="POST",
                    severity="MEDIUM",
                    title="Batch Queries Enabled",
                    description="GraphQL supports batch queries, which can be exploited",
                    evidence="Batch query returned valid responses",
                    cwe_id="CWE-400",
                    remediation="Disable batch queries or implement rate limiting",
                ))

        except Exception:
            pass

        return findings

    def test_alias_dos(self) -> List[SecurityFinding]:
        """测试别名 DoS

        Returns:
            发现的问题
        """
        findings = []

        alias_query = """
        query {
            a1: __typename
            a2: __typename
            a3: __typename
            a4: __typename
            a5: __typename
            a6: __typename
            a7: __typename
            a8: __typename
            a9: __typename
            a10: __typename
        }
        """

        try:
            start = time.time()
            response = httpx.post(
                self.endpoint,
                json={"query": alias_query},
                headers=self.headers,
                timeout=30,
            )
            elapsed = time.time() - start

            if response.status_code == 200 and elapsed > 5:
                findings.append(SecurityFinding(
                    endpoint=self.endpoint,
                    method="POST",
                    severity="HIGH",
                    title="Alias-Based DoS Vulnerability",
                    description="GraphQL is vulnerable to alias-based DoS attacks",
                    evidence=f"Query with 10 aliases took {elapsed:.2f}s to execute",
                    cwe_id="CWE-400",
                    remediation="Implement query complexity analysis and depth limiting",
                ))

        except Exception:
            pass

        return findings

    def test_field_depth(self) -> List[SecurityFinding]:
        """测试字段深度

        Returns:
            发现的问题
        """
        findings = []

        depth_query = """
        query {
            __schema {
                types {
                    fields {
                        type {
                            fields {
                                type {
                                    fields {
                                        type { name }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """

        try:
            response = httpx.post(
                self.endpoint,
                json={"query": depth_query},
                headers=self.headers,
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                if "errors" not in data:
                    findings.append(SecurityFinding(
                        endpoint=self.endpoint,
                        method="POST",
                        severity="MEDIUM",
                        title="No Depth Limit Enforced",
                        description="Query depth is not limited, potential for DoS",
                        evidence="Deep nested query executed successfully",
                        cwe_id="CWE-400",
                        remediation="Implement maximum query depth limiting",
                    ))

        except Exception:
            pass

        return findings

    def scan(self) -> List[SecurityFinding]:
        """执行 GraphQL 安全扫描

        Returns:
            发现的问题列表
        """
        findings = []

        if not self.is_available():
            logger.warning(f"GraphQL endpoint not available: {self.endpoint}")
            return findings

        findings.extend(self.test_introspection())
        findings.extend(self.test_batch_query())
        findings.extend(self.test_alias_dos())
        findings.extend(self.test_field_depth())

        return findings


class APISecurityTester:
    """API 安全测试器

    整合 REST API 和 GraphQL 测试功能。
    """

    def __init__(self, base_url: str = "", headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url
        self.headers = headers or {}
        self.rest_tester = RESTAPITester(base_url, headers)
        self.graphql_tester = None

        parsed = urlparse(base_url)
        if "graphql" in parsed.path.lower() if parsed.path else False:
            self.graphql_tester = GraphQLTester(base_url, headers)

        self.findings: List[SecurityFinding] = []

    def is_available(self) -> bool:
        """检查测试器是否可用

        Returns:
            是否可用
        """
        return HTTPX_AVAILABLE

    def check_and_install(self) -> tuple[bool, str]:
        """检查并返回安装说明

        Returns:
            (是否可用, 安装说明)
        """
        if HTTPX_AVAILABLE:
            return True, "httpx is available"

        return False, "pip install httpx"

    def test_openapi(self, spec: Dict[str, Any]) -> List[SecurityFinding]:
        """测试 OpenAPI 规范的 API

        Args:
            spec: OpenAPI 规范

        Returns:
            发现的问题
        """
        findings = []
        parser = OpenAPIParser(spec)

        for endpoint in parser.endpoints:
            endpoint_findings = self.rest_tester.test_endpoint(endpoint)
            findings.extend(endpoint_findings)

        self.findings.extend(findings)
        return findings

    def test_graphql(self, endpoint: Optional[str] = None) -> List[SecurityFinding]:
        """测试 GraphQL

        Args:
            endpoint: GraphQL端点，如果为None则使用base_url

        Returns:
            发现的问题
        """
        target = endpoint or self.base_url

        if not self.graphql_tester and target:
            self.graphql_tester = GraphQLTester(target, self.headers)

        if self.graphql_tester:
            findings = self.graphql_tester.scan()
            self.findings.extend(findings)
            return findings

        return []

    def test_url(self, url: str) -> List[SecurityFinding]:
        """测试指定 URL

        Args:
            url: 目标 URL

        Returns:
            发现的问题
        """
        findings = []

        try:
            response = httpx.get(url, headers=self.headers, timeout=10, follow_redirects=True)

            content_type = response.headers.get("content-type", "")

            if "openapi" in content_type.lower() or url.endswith((".yaml", ".yml", ".json")):
                if url.endswith((".yaml", ".yml")):
                    pass
                else:
                    try:
                        spec = response.json()
                        findings.extend(self.test_openapi(spec))
                    except Exception:
                        pass

            if "application/json" in content_type:
                try:
                    data = response.json()
                    if isinstance(data, dict) and "data" in data and "__schema" in data.get("data", {}):
                        findings.extend(self.test_graphql(url))
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"URL test error: {e}")

        return findings

    def scan(self, target: str) -> List[SecurityFinding]:
        """扫描目标

        Args:
            target: 目标 URL 或 OpenAPI 规范

        Returns:
            发现的问题
        """
        if target.endswith((".yaml", ".yml")):
            parser = OpenAPIParser.from_file(target)
            return self.test_openapi(parser.spec)
        elif target.endswith(".json"):
            with open(target, "r") as f:
                spec = json.load(f)
            return self.test_openapi(spec)
        else:
            return self.test_url(target)

    def get_tool_info(self) -> Dict[str, Any]:
        """获取工具信息

        Returns:
            工具信息字典
        """
        return {
            "name": "API Security Tester",
            "version": "1.0",
            "capabilities": [
                "REST API testing",
                "OpenAPI specification testing",
                "GraphQL security testing",
                "SQL injection testing",
                "XSS testing",
                "Authentication testing",
            ],
            "available": self.is_available(),
            "http_required": ["httpx"],
            "optional": ["requests"],
        }


def run_api_security_scan(
    target: str,
    test_graphql: bool = True,
    test_openapi: bool = True,
) -> Dict[str, Any]:
    """运行 API 安全扫描的便捷函数

    Args:
        target: 目标 URL 或 OpenAPI 规范文件
        test_graphql: 是否测试 GraphQL
        test_openapi: 是否测试 OpenAPI

    Returns:
        扫描结果
    """
    tester = APISecurityTester()

    if not tester.is_available():
        return {
            "success": False,
            "error": "httpx not available, install with: pip install httpx",
            "findings": [],
        }

    try:
        findings = tester.scan(target)

        return {
            "success": True,
            "target": target,
            "findings": [f.to_dict() for f in findings],
            "summary": {
                "total": len(findings),
                "critical": len([f for f in findings if f.severity == "CRITICAL"]),
                "high": len([f for f in findings if f.severity == "HIGH"]),
                "medium": len([f for f in findings if f.severity == "MEDIUM"]),
                "low": len([f for f in findings if f.severity == "LOW"]),
                "info": len([f for f in findings if f.severity == "INFO"]),
            },
        }

    except Exception as e:
        logger.error(f"API security scan error: {e}")
        return {
            "success": False,
            "error": str(e),
            "findings": [],
        }


def check_api_security_tools() -> Dict[str, Any]:
    """检查 API 安全测试工具状态

    Returns:
        工具状态信息
    """
    return {
        "httpx_available": HTTPX_AVAILABLE,
        "graphql_tester_available": HTTPX_AVAILABLE,
        "rest_api_tester_available": HTTPX_AVAILABLE,
        "install_instructions": "pip install httpx requests jsonschema",
    }
