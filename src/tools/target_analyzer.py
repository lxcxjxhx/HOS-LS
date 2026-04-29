"""目标分析器

识别目标类型、指纹和可测试性评估。
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TargetProfile:
    """目标画像"""

    type: str
    url: str
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    testability: Dict[str, Any] = field(default_factory=dict)
    recommended_tools: List[str] = field(default_factory=list)
    recommended_params: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "url": self.url,
            "fingerprint": self.fingerprint,
            "testability": self.testability,
            "recommended_tools": self.recommended_tools,
            "recommended_params": self.recommended_params,
            "confidence": self.confidence,
        }


class TargetAnalyzer:
    """目标分析器

    识别目标类型、指纹和可测试性评估。
    """

    FRAMEWORK_SIGNATURES = {
        "react": ["react", "react-dom", "create-react-app"],
        "vue": ["vue", "vuejs", "vue-router"],
        "angular": ["angular", "@angular/core"],
        "next.js": ["next", "nextjs", "_next"],
        "django": ["csrftoken", "csrfmiddlewaretoken", "django"],
        "flask": ["flask", "jinja"],
        "fastapi": ["fastapi", "uvicorn"],
        "express": ["express", "node_modules"],
        "spring": ["spring", "java", "jsessionid"],
        "laravel": ["laravel", "csrf-token"],
        "rails": ["ruby-on-rails", "actionpack"],
        "asp.net": ["__viewstate", "asp.net", "__eventvalidation"],
        "wordpress": ["wp-content", "wp-includes", "wordpress"],
        "drupal": ["drupal", "drupal_settings"],
        "joomla": ["joomla", "jm-config"],
    }

    MIDDLEWARE_SIGNATURES = {
        "nginx": ["nginx"],
        "apache": ["apache", "mod_"],
        "iis": ["microsoft-iis", "iis"],
        "cloudflare": ["cf-ray", "cloudflare"],
        "akamai": ["akamai"],
        "aws": ["aws", "amazon", "awsv"],
        "azure": ["azure"],
        "gcp": ["gcp", "google"],
    }

    LANGUAGE_SIGNATURES = {
        "php": [".php", "php"],
        "python": [".py", "python", "pip"],
        "javascript": [".js", "javascript", "node_modules"],
        "typescript": [".ts", "typescript"],
        "java": [".java", "java", "jar", "tomcat"],
        "ruby": [".rb", "ruby", "gem"],
        "go": [".go", "golang"],
        "rust": [".rs", "rust"],
        "c#": [".cs", "csharp", ".net"],
    }

    API_INDICATORS = [
        "/api/v",
        "/api/",
        "/graphql",
        "/rest/",
        "/swagger",
        "/openapi",
        "/api-docs",
        "application/json",
        "application/xml",
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._client: Optional[httpx.Client] = None

    def _get_client(self) -> httpx.Client:
        """获取 HTTP 客户端"""
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def analyze(self, target: str) -> TargetProfile:
        """分析目标

        Args:
            target: 目标 URL

        Returns:
            目标画像
        """
        target = target.rstrip("/")
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        fingerprint = self._gather_fingerprint(target)
        target_type = self._determine_type(target, fingerprint)
        testability = self._assess_testability(target, fingerprint)
        recommended_tools = self._recommend_tools(target_type, fingerprint)
        recommended_params = self._generate_params(target_type)

        return TargetProfile(
            type=target_type,
            url=target,
            fingerprint=fingerprint,
            testability=testability,
            recommended_tools=recommended_tools,
            recommended_params=recommended_params,
            confidence=0.8,
        )

    def _gather_fingerprint(self, target: str) -> Dict[str, Any]:
        """收集目标指纹信息"""
        fingerprint = {
            "framework": [],
            "cms": [],
            "middleware": [],
            "languages": [],
            "is_api": False,
            "headers": {},
            "technologies": [],
        }

        if not HTTPX_AVAILABLE:
            return fingerprint

        try:
            client = self._get_client()
            response = client.get(target, follow_redirects=True)

            fingerprint["headers"] = dict(response.headers)
            fingerprint["status_code"] = response.status_code

            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                fingerprint["is_api"] = True

            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
            headers_str = json.dumps(headers_lower)

            server = headers_lower.get("server", "")
            for middleware, signatures in self.MIDDLEWARE_SIGNATURES.items():
                if any(sig in server.lower() for sig in signatures):
                    fingerprint["middleware"].append(middleware)
                    fingerprint["technologies"].append(middleware)

            for framework, signatures in self.FRAMEWORK_SIGNATURES.items():
                if any(sig in headers_str for sig in signatures):
                    fingerprint["framework"].append(framework)
                    fingerprint["technologies"].append(framework)

            text_lower = response.text.lower()

            for cms, signatures in self.FRAMEWORK_SIGNATURES.items():
                if cms in ["wordpress", "drupal", "joomla"]:
                    if any(sig in text_lower for sig in signatures):
                        fingerprint["cms"].append(cms)
                        fingerprint["technologies"].append(cms)

            for lang, signatures in self.LANGUAGE_SIGNATURES.items():
                if any(sig in text_lower[:5000] for sig in signatures):
                    if lang not in fingerprint["languages"]:
                        fingerprint["languages"].append(lang)

            url_path = urlparse(target).path
            if any(indicator in url_path.lower() for indicator in self.API_INDICATORS):
                fingerprint["is_api"] = True

            if "/api/" in text_lower[:1000] or "swagger" in text_lower[:1000]:
                fingerprint["is_api"] = True

        except Exception as e:
            logger.debug(f"Fingerprint gathering error: {e}")

        return fingerprint

    def _determine_type(
        self,
        target: str,
        fingerprint: Dict[str, Any],
    ) -> str:
        """确定目标类型"""
        if fingerprint.get("is_api"):
            return "api"

        if fingerprint.get("framework"):
            return "web"

        if fingerprint.get("cms"):
            return "web"

        url_lower = target.lower()
        if any(ind in url_lower for ind in ["graphql", "api", "rest", "swagger"]):
            return "api"

        if not HTTPX_AVAILABLE:
            return "unknown"

        try:
            client = self._get_client()
            response = client.get(target, timeout=10, follow_redirects=True)
            content_type = response.headers.get("content-type", "")

            if "text/html" in content_type:
                return "web"
            elif "application/json" in content_type:
                return "api"
            else:
                return "service"

        except Exception:
            return "unknown"

    def _assess_testability(
        self,
        target: str,
        fingerprint: Dict[str, Any],
    ) -> Dict[str, Any]:
        """评估可测试性"""
        factors = []
        score = 0.5

        if fingerprint.get("is_api"):
            score += 0.2
            factors.append("API端点，可进行专门测试")
        else:
            score += 0.1
            factors.append("Web应用，可进行传统扫描")

        if fingerprint.get("framework"):
            score += 0.1
            factors.append(f"检测到框架: {', '.join(fingerprint['framework'][:2])}")

        if fingerprint.get("middleware"):
            score += 0.05
            factors.append(f"检测到中间件: {', '.join(fingerprint['middleware'][:2])}")

        status_code = fingerprint.get("status_code")
        if status_code and status_code == 200:
            score += 0.1
            factors.append("目标可访问")

        headers = fingerprint.get("headers", {})
        if headers.get("server"):
            score += 0.05
            factors.append(f"Server: {headers.get('server')}")

        score = min(score, 1.0)

        return {
            "score": score,
            "factors": factors,
        }

    def _recommend_tools(
        self,
        target_type: str,
        fingerprint: Dict[str, Any],
    ) -> List[str]:
        """推荐扫描工具"""
        tools = []

        if target_type == "api":
            tools.extend(["api_security", "sqlmap", "nuclei"])

            if fingerprint.get("graphql"):
                tools.append("graphql_test")
        elif target_type == "web":
            tools.extend(["zap", "nuclei", "fuzzing", "api_security"])

            if fingerprint.get("cms"):
                tools.extend(["nuclei", "cms_scanner"])
        else:
            tools.extend(["nuclei", "trivy"])

        tools.extend(["semgrep", "gitleaks"])

        unique_tools = list(dict.fromkeys(tools))

        return unique_tools[:6]

    def _generate_params(self, target_type: str) -> Dict[str, Any]:
        """生成推荐扫描参数"""
        params = {}

        if target_type == "api":
            params["api_security"] = {
                "test_graphql": True,
                "test_openapi": True,
            }
            params["sqlmap"] = {
                "risk": 1,
                "level": 2,
                "batch": True,
            }
        else:
            params["zap"] = {
                "risk": 1,
                "level": 2,
            }
            params["nuclei"] = {
                "severity": "medium,high,critical",
                "rate_limit": 150,
            }

        params["fuzzing"] = {
            "mode": "discover",
            "wordlist": "common",
        }

        return params

    def detect_endpoints(self, target: str) -> List[str]:
        """检测 API 端点

        Args:
            target: 目标 URL

        Returns:
            发现的端点列表
        """
        endpoints = []

        common_paths = [
            "/api/v1/users", "/api/v1/products", "/api/v1/auth",
            "/api/v2/", "/api/admin", "/api/debug",
            "/graphql", "/swagger", "/swagger-ui", "/api-docs",
            "/rest/", "/api/", "/wp-json/",
        ]

        if not HTTPX_AVAILABLE:
            return endpoints

        try:
            client = self._get_client()

            for path in common_paths:
                url = target.rstrip("/") + path
                try:
                    response = client.get(url, timeout=5, allow_redirects=False)
                    if response.status_code in [200, 301, 302, 401, 403]:
                        endpoints.append(path)
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Endpoint detection error: {e}")

        return endpoints

    def close(self) -> None:
        """关闭客户端"""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def analyze_target(target: str) -> TargetProfile:
    """分析目标的便捷函数

    Args:
        target: 目标 URL

    Returns:
        目标画像
    """
    with TargetAnalyzer() as analyzer:
        return analyzer.analyze(target)
