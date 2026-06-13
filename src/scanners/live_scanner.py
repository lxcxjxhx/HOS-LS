"""LiveScanner - 在线 Web 应用实时扫描模块

对运行中的 Web 应用进行安全扫描，检测常见漏洞和配置问题。
"""

import re
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from src.utils.logger import get_logger

logger = get_logger(__name__)


class Severity(Enum):
    """漏洞严重级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class LiveFinding:
    """扫描发现"""
    severity: Severity
    message: str
    url: str
    finding_type: str
    details: Optional[str] = None
    recommendation: Optional[str] = None

    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)


@dataclass
class LiveScanResult:
    """扫描结果"""
    target_url: str
    findings: List[LiveFinding] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    pages_scanned: int = 0


class LiveScanner:
    """在线 Web 应用扫描器

    对运行中的 Web 应用进行实时安全扫描。
    """

    MAX_PAGES = 10
    TIMEOUT = 15
    MAX_LINKS_PER_PAGE = 20

    SECURITY_HEADERS = {
        "X-Frame-Options": (
            Severity.MEDIUM,
            "网站缺少 X-Frame-Options 响应头，可能受到点击劫持攻击",
            "添加 X-Frame-Options: DENY 或 SAMEORIGIN 响应头"
        ),
        "Content-Security-Policy": (
            Severity.MEDIUM,
            "网站缺少 Content-Security-Policy 响应头，可能受到 XSS 攻击",
            "配置合理的 CSP 策略以限制资源加载来源"
        ),
        "X-Content-Type-Options": (
            Severity.LOW,
            "网站缺少 X-Content-Type-Options 响应头，浏览器可能进行 MIME 嗅探",
            "添加 X-Content-Type-Options: nosniff 响应头"
        ),
        "Strict-Transport-Security": (
            Severity.MEDIUM,
            "网站缺少 Strict-Transport-Security 响应头，可能受到降级攻击",
            "添加 Strict-Transport-Security: max-age=31536000; includeSubDomains 响应头"
        ),
        "Referrer-Policy": (
            Severity.LOW,
            "网站缺少 Referrer-Policy 响应头，可能泄露敏感 URL 信息",
            "添加 Referrer-Policy: strict-origin-when-cross-origin 响应头"
        ),
        "Permissions-Policy": (
            Severity.LOW,
            "网站缺少 Permissions-Policy 响应头，浏览器功能权限未限制",
            "添加 Permissions-Policy 响应头限制不必要的浏览器功能"
        ),
        "X-XSS-Protection": (
            Severity.INFO,
            "网站缺少 X-XSS-Protection 响应头（现代浏览器已废弃，但仍建议配置）",
            "添加 X-XSS-Protection: 1; mode=block 响应头（作为辅助防护）"
        ),
    }

    def __init__(self, config: Any = None) -> None:
        self.config = config

    def scan(
        self,
        url: str,
        cookies: Optional[str] = None,
        scope: Optional[Dict[str, Any]] = None,
        deep_analysis: bool = False,
    ) -> LiveScanResult:
        """执行实时扫描

        Args:
            url: 目标 URL
            cookies: Cookie 字符串（用于认证）
            scope: 范围配置字典
            deep_analysis: 是否启用 AI 深度分析

        Returns:
            LiveScanResult 扫描结果
        """
        result = LiveScanResult(target_url=url)

        if not self._validate_url(url):
            result.findings.append(LiveFinding(
                severity=Severity.INFO,
                message="目标 URL 格式无效",
                url=url,
                finding_type="invalid_url",
                recommendation="请提供有效的 HTTP 或 HTTPS URL",
            ))
            return result

        reachable, base_response = self._check_reachability(url, cookies)
        if not reachable or base_response is None:
            result.findings.append(LiveFinding(
                severity=Severity.INFO,
                message="目标 URL 无法访问",
                url=url,
                finding_type="unreachable",
                recommendation="确认目标服务是否正常运行，网络连接是否正常",
            ))
            return result

        pages_to_scan: List[str] = [url]
        visited: set = set()

        self._scan_page(url, base_response, result, cookies)
        visited.add(url)
        result.pages_scanned += 1

        links = self._extract_links(base_response, url)
        pages_to_scan.extend(links)

        while pages_to_scan and result.pages_scanned < self.MAX_PAGES:
            page_url = pages_to_scan.pop(0)
            if page_url in visited:
                continue
            if scope and not self._in_scope(page_url, scope):
                continue

            try:
                response = self._http_get(page_url, cookies)
                if response:
                    self._scan_page(page_url, response, result, cookies)
                    page_links = self._extract_links(response, page_url)
                    for link in page_links:
                        if link not in visited and link not in pages_to_scan:
                            pages_to_scan.append(link)
                    visited.add(page_url)
                    result.pages_scanned += 1
            except Exception as e:
                logger.debug(f"扫描页面失败 {page_url}: {e}")

        if deep_analysis:
            self._run_deep_analysis(base_response, url, result, cookies)

        return result

    def _validate_url(self, url: str) -> bool:
        """验证 URL 格式"""
        try:
            parsed = urlparse(url)
            return parsed.scheme in ("http", "https") and bool(parsed.netloc)
        except Exception:
            return False

    def _check_reachability(
        self, url: str, cookies: Optional[str]
    ) -> tuple:
        """检查目标可达性

        Returns:
            (bool, response): 是否可达和响应对象
        """
        try:
            response = self._http_get(url, cookies, follow_redirects=True, timeout=10)
            if response is not None:
                return True, response
            return False, None
        except Exception as e:
            logger.debug(f"可达性检查失败: {e}")
            return False, None

    def _http_get(
        self,
        url: str,
        cookies: Optional[str] = None,
        follow_redirects: bool = False,
        timeout: int = None,
    ) -> Optional[httpx.Response]:
        """执行 HTTP GET 请求"""
        try:
            headers = {
                "User-Agent": "HOS-LS-LiveScanner/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            }
            request_cookies = self._parse_cookies(cookies) if cookies else None
            verify = self._get_ssl_context()

            with httpx.Client(
                follow_redirects=follow_redirects,
                timeout=timeout or self.TIMEOUT,
                verify=verify,
            ) as client:
                response = client.get(url, headers=headers, cookies=request_cookies)
                return response
        except httpx.TLSConfigError as e:
            logger.debug(f"SSL 配置错误 {url}: {e}")
            return None
        except httpx.RequestError as e:
            logger.debug(f"请求失败 {url}: {e}")
            return None
        except Exception as e:
            logger.debug(f"HTTP 请求异常 {url}: {e}")
            return None

    def _parse_cookies(self, cookie_string: str) -> Dict[str, str]:
        """解析 Cookie 字符串为字典"""
        cookies = {}
        if not cookie_string:
            return cookies
        for part in cookie_string.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key:
                    cookies[key] = value
        return cookies

    def _get_ssl_context(self) -> bool:
        """获取 SSL 验证配置"""
        if self.config and hasattr(self.config, "live_scan"):
            live_scan_config = self.config.live_scan
            if hasattr(live_scan_config, "verify_ssl"):
                return live_scan_config.verify_ssl
        return True

    def _in_scope(self, url: str, scope: Dict[str, Any]) -> bool:
        """检查 URL 是否在扫描范围内"""
        parsed = urlparse(url)
        allowed_domains = scope.get("allowed_domains")
        allowed_paths = scope.get("allowed_paths")
        excluded_paths = scope.get("excluded_paths", [])

        if allowed_domains and parsed.hostname not in allowed_domains:
            return False

        if allowed_paths:
            path_match = any(parsed.path.startswith(p) for p in allowed_paths)
            if not path_match:
                return False

        if excluded_paths:
            if any(parsed.path.startswith(p) for p in excluded_paths):
                return False

        return True

    def _scan_page(
        self,
        url: str,
        response: httpx.Response,
        result: LiveScanResult,
        cookies: Optional[str] = None,
    ) -> None:
        """扫描单个页面"""
        self._check_security_headers(url, response, result)
        self._check_information_disclosure(url, response, result)
        self._check_cookie_security(url, response, result)
        self._check_mixed_content(url, response, result)
        self._check_cors(url, response, result)
        self._check_directory_listing(url, response, result)
        self._check_sensitive_data(url, response, result)

    def _check_security_headers(
        self, url: str, response: httpx.Response, result: LiveScanResult
    ) -> None:
        """检查安全响应头"""
        response_headers_lower = {
            k.lower(): v for k, v in response.headers.items()
        }

        for header_name, (severity, message, recommendation) in self.SECURITY_HEADERS.items():
            if header_name.lower() not in response_headers_lower:
                result.findings.append(LiveFinding(
                    severity=severity,
                    message=message,
                    url=url,
                    finding_type="missing_header",
                    details=f"缺少响应头: {header_name}",
                    recommendation=recommendation,
                ))

    def _check_information_disclosure(
        self, url: str, response: httpx.Response, result: LiveScanResult
    ) -> None:
        """检查信息泄露"""
        server_header = response.headers.get("Server")
        if server_header:
            result.findings.append(LiveFinding(
                severity=Severity.LOW,
                message="服务器通过 Server 响应头暴露了技术栈信息",
                url=url,
                finding_type="information_disclosure",
                details=f"Server: {server_header}",
                recommendation="在 Web 服务器配置中移除或修改 Server 响应头",
            ))

        x_powered_by = response.headers.get("X-Powered-By")
        if x_powered_by:
            result.findings.append(LiveFinding(
                severity=Severity.LOW,
                message="X-Powered-By 响应头暴露了框架/技术信息",
                url=url,
                finding_type="information_disclosure",
                details=f"X-Powered-By: {x_powered_by}",
                recommendation="在应用配置中禁用 X-Powered-By 响应头",
            ))

    def _check_cookie_security(
        self, url: str, response: httpx.Response, result: LiveScanResult
    ) -> None:
        """检查 Cookie 安全标志"""
        set_cookie_headers = response.headers.get_list("set-cookie")
        if not set_cookie_headers:
            return

        for cookie_header in set_cookie_headers:
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=", 1)[0].strip() if "=" in cookie_header else cookie_header

            if "httponly" not in cookie_lower:
                result.findings.append(LiveFinding(
                    severity=Severity.MEDIUM,
                    message=f"Cookie '{cookie_name}' 缺少 HttpOnly 标志，可能被 JavaScript 读取",
                    url=url,
                    finding_type="cookie_issue",
                    recommendation="为敏感 Cookie 设置 HttpOnly 标志",
                ))

            if "secure" not in cookie_lower:
                result.findings.append(LiveFinding(
                    severity=Severity.MEDIUM,
                    message=f"Cookie '{cookie_name}' 缺少 Secure 标志，可能通过非 HTTPS 传输",
                    url=url,
                    finding_type="cookie_issue",
                    recommendation="为敏感 Cookie 设置 Secure 标志",
                ))

            if "samesite" not in cookie_lower:
                result.findings.append(LiveFinding(
                    severity=Severity.LOW,
                    message=f"Cookie '{cookie_name}' 缺少 SameSite 标志，可能受到 CSRF 攻击",
                    url=url,
                    finding_type="cookie_issue",
                    recommendation="为 Cookie 设置 SameSite=Strict 或 SameSite=Lax",
                ))

    def _check_mixed_content(
        self, url: str, response: httpx.Response, result: LiveScanResult
    ) -> None:
        """检查混合内容"""
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return

        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            return

        mixed_tags = soup.find_all(["script", "iframe", "object", "embed", "link"], src=True)
        mixed_sources = []
        for tag in mixed_tags:
            src = tag.get("src", "")
            if src and src.startswith("http://"):
                mixed_sources.append(src)

        if mixed_sources:
            result.findings.append(LiveFinding(
                severity=Severity.MEDIUM,
                message="HTTPS 页面加载了 HTTP 资源（混合内容），可能受到中间人攻击",
                url=url,
                finding_type="mixed_content",
                details=f"不安全资源: {', '.join(mixed_sources[:5])}",
                recommendation="将所有资源引用改为 HTTPS 或使用协议相对 URL",
            ))

    def _check_cors(
        self, url: str, response: httpx.Response, result: LiveScanResult
    ) -> None:
        """检查 CORS 配置"""
        acao = response.headers.get("Access-Control-Allow-Origin")
        if not acao:
            return

        if acao == "*":
            severity = Severity.HIGH
            message = "CORS 配置允许任意域名访问（Access-Control-Allow-Origin: *）"
            recommendation = "限制 Access-Control-Allow-Origin 为可信域名列表"
        else:
            acac = response.headers.get("Access-Control-Allow-Credentials")
            if acac and acac.lower() == "true":
                severity = Severity.HIGH
                message = "CORS 配置允许携带凭证访问非白名单域名"
                recommendation = "不要将 Access-Control-Allow-Credentials 与通配符或非可信域名一起使用"
            else:
                severity = Severity.LOW
                message = f"CORS 配置允许跨域访问: {acao}"
                recommendation = "确认 CORS 配置仅允许可信域名"

        result.findings.append(LiveFinding(
            severity=severity,
            message=message,
            url=url,
            finding_type="cors_misconfig",
            recommendation=recommendation,
        ))

    def _check_directory_listing(
        self, url: str, response: httpx.Response, result: LiveScanResult
    ) -> None:
        """检查目录列表"""
        if response.status_code not in (200, 403):
            return

        body_lower = response.text.lower()
        indicators = [
            "index of",
            "directory listing",
            "last modified</a>",
            "parent directory",
            "<pre>",
        ]
        is_directory_listing = any(ind in body_lower for ind in indicators)

        if is_directory_listing:
            parsed = urlparse(url)
            if parsed.path and not parsed.path.endswith((".html", ".htm", ".php", ".jsp", ".asp", ".aspx")):
                result.findings.append(LiveFinding(
                    severity=Severity.MEDIUM,
                    message="服务器启用了目录列表，可能暴露敏感文件",
                    url=url,
                    finding_type="directory_listing",
                    recommendation="禁用 Web 服务器的目录列表功能",
                ))

    def _check_sensitive_data(
        self, url: str, response: httpx.Response, result: LiveScanResult
    ) -> None:
        """检查敏感信息泄露"""
        body = response.text
        patterns = {
            r"(?i)stack\s*trace": "页面包含堆栈跟踪信息",
            r"(?i)at\s+\w+[\w.$]+\.\w+\([^)]+\)": "页面包含方法调用栈信息",
            r"(?i)fatal\s*error|warning\s*:": "页面包含错误信息",
            r"(?i)password\s*=\s*[\"'][^\"']+[\"']": "页面可能暴露了密码",
            r"(?i)api[_-]?key\s*=\s*[\"'][^\"']+[\"']": "页面可能暴露了 API 密钥",
            r"(?i)secret\s*=\s*[\"'][^\"']+[\"']": "页面可能暴露了密钥信息",
        }

        for pattern, message in patterns.items():
            if re.search(pattern, body):
                result.findings.append(LiveFinding(
                    severity=Severity.HIGH,
                    message=message,
                    url=url,
                    finding_type="information_disclosure",
                    recommendation="确保生产环境不暴露调试信息和敏感数据",
                ))
                break

    def _extract_links(
        self, response: httpx.Response, base_url: str
    ) -> List[str]:
        """从页面提取链接"""
        links = []
        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            return links

        base_parsed = urlparse(base_url)
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
                continue

            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)

            if parsed.scheme not in ("http", "https"):
                continue
            if parsed.netloc != base_parsed.netloc:
                continue

            clean_url = full_url.split("#")[0]
            if clean_url not in links:
                links.append(clean_url)

        return links[:self.MAX_LINKS_PER_PAGE]

    def _run_deep_analysis(
        self,
        response: httpx.Response,
        url: str,
        result: LiveScanResult,
        cookies: Optional[str] = None,
    ) -> None:
        """运行 AI 深度分析"""
        try:
            from src.ai.models import AIRequest
        except ImportError:
            logger.debug("AI 模型模块不可用，跳过深度分析")
            return

        max_content_length = 8000
        page_content = response.text[:max_content_length]

        prompt = f"""请对以下 Web 页面内容进行安全分析，识别潜在的安全漏洞和风险。

目标 URL: {url}

页面内容:
{page_content}

请分析以下方面:
1. 是否存在 XSS 攻击风险（反射型、存储型、DOM 型）
2. 是否存在 SQL 注入风险迹象
3. 是否存在不安全的配置或实现
4. 是否存在认证或授权问题
5. 是否暴露了敏感数据

请以 JSON 数组格式返回发现的问题，每个问题包含:
- severity: 严重级别 (critical/high/medium/low/info)
- message: 问题描述
- details: 详细信息
- recommendation: 修复建议

只返回 JSON 数组，不要其他内容。"""

        try:
            request = AIRequest(
                prompt=prompt,
                system_prompt="你是一个专业的 Web 安全研究员。请分析页面内容并识别安全风险。",
            )

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                ai_response = loop.run_until_complete(
                    self._call_ai_model(request)
                )
            finally:
                loop.close()

            if ai_response:
                self._parse_ai_findings(ai_response, url, result)

        except Exception as e:
            logger.debug(f"AI 深度分析失败: {e}")
            result.findings.append(LiveFinding(
                severity=Severity.INFO,
                message="AI 深度分析不可用或未配置",
                url=url,
                finding_type="ai_unavailable",
                details=str(e),
                recommendation="配置 AI 提供商 API 密钥以启用深度分析",
            ))

    async def _call_ai_model(self, request: "AIRequest") -> Optional[str]:
        """调用 AI 模型进行分析"""
        try:
            from src.ai.client import AIModelManager
            from src.ai.models import AIProvider

            manager = AIModelManager()
            default_client = manager.get_default_client()
            if default_client and default_client.is_available():
                response = await default_client.generate_with_retry(request)
                return response.content if hasattr(response, "content") else None

            for provider in [AIProvider.OPENAI, AIProvider.ANTHROPIC, AIProvider.DEEPSEEK, AIProvider.ALIYUN]:
                client = manager.get_client(provider)
                if client and client.is_available():
                    try:
                        response = await client.generate_with_retry(request)
                        return response.content if hasattr(response, "content") else None
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"AI 调用失败: {e}")
        return None

    def _parse_ai_findings(
        self, ai_content: str, url: str, result: LiveScanResult
    ) -> None:
        """解析 AI 返回的发现"""
        try:
            import json

            json_match = re.search(r'\[.*\]', ai_content, re.DOTALL)
            if not json_match:
                return

            findings_data = json.loads(json_match.group())
            if not isinstance(findings_data, list):
                return

            for item in findings_data:
                if not isinstance(item, dict):
                    continue

                severity_str = item.get("severity", "info").lower()
                message = item.get("message", "")
                details = item.get("details")
                recommendation = item.get("recommendation")

                if not message:
                    continue

                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.INFO

                existing_messages = {f.message for f in result.findings}
                if message not in existing_messages:
                    result.findings.append(LiveFinding(
                        severity=severity,
                        message=message,
                        url=url,
                        finding_type="ai_analysis",
                        details=details,
                        recommendation=recommendation,
                    ))
        except (json.JSONDecodeError, Exception) as e:
            logger.debug(f"解析 AI 发现失败: {e}")
