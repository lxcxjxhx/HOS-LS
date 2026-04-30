"""模糊测试引擎

提供 Web 参数、HTTP 头部等的模糊测试功能。
支持内容发现。

依赖:
    pip install httpx

用途:
    - Web 参数模糊测试
    - HTTP 头部模糊测试
    - 内容/目录发现
    - API 端点枚举
"""

import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FuzzResult:
    """模糊测试结果"""

    url: str
    method: str
    status_code: int
    length: int
    words: int
    time: float
    payload: str
   发现了: bool = False
    content_type: str = ""
    location: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    matched_pattern: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "length": self.length,
            "words": self.words,
            "time": self.time,
            "payload": self.payload,
            "发现了": self.发现了,
            "content_type": self.content_type,
            "location": self.location,
            "headers": self.headers,
            "matched_pattern": self.matched_pattern,
        }


@dataclass
class DiscoveredItem:
    """发现的资源"""

    url: str
    status_code: int
    content_type: str
    size: int
   发现方法: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "size": self.size,
            "发现方法": self.发现方法,
        }


class WordlistLoader:
    """Wordlist 加载器"""

    DEFAULT_DIRS = [
        "admin", "api", "backup", "bin", "cgi-bin", "config", "css",
        "dashboard", "data", "db", "debug", "demo", "dev", "docs",
        "ftp", "images", "include", "index", "js", "lib", "login",
        "logout", "logs", "manage", "manager", "media", "old", "proxy",
        "scripts", "server", "sql", "static", "status", "test", "tmp",
        "tools", "uploads", "upload", "users", "var", "web", "www",
    ]

    DEFAULT_FILES = [
        ".htaccess", ".htpasswd", ".git/config", ".git/HEAD",
        ".env", ".env.bak", ".env.local", ".env.production",
        "README.md", "README.txt", "CHANGELOG.md",
        "config.php", "config.py", "config.yaml", "config.yml",
        "database.php", "database.yml",
        "wp-config.php", "web.config", "settings.py",
        "backup.sql", "dump.sql", "database.sql",
        "error.log", "access.log", "debug.log",
        "phpinfo.php", "info.php", "test.php",
        "admin.php", "login.php", "dashboard.php",
    ]

    COMMON_PATHS = [
        "/admin", "/admin/", "/administrator", "/login", "/login.php",
        "/api", "/api/v1", "/api/v2", "/api-docs", "/swagger",
        "/graphql", "/graphiql",
        "/backup", "/backups", "/db", "/database",
        "/test", "/tests", "/testing", "/debug", "/debugger",
        "/config", "/configuration", "/settings",
        "/upload", "/uploads", "/files", "/documents",
        "/images", "/img", "/assets", "/static",
        "/wp-admin", "/wp-content", "/wp-includes",
        "/console", "/terminal", "/shell",
        "/info", "/phpinfo", "/server-status", "/server-info",
        "/health", "/metrics", "/monitor", "/status",
    ]

    @classmethod
    def get_default_dirs(cls) -> List[str]:
        """获取默认目录列表"""
        return cls.DEFAULT_DIRS.copy()

    @classmethod
    def get_default_files(cls) -> List[str]:
        """获取默认文件列表"""
        return cls.DEFAULT_FILES.copy()

    @classmethod
    def get_common_paths(cls) -> List[str]:
        """获取常见路径列表"""
        return cls.COMMON_PATHS.copy()

    @classmethod
    def load_from_file(cls, file_path: str) -> List[str]:
        """从文件加载 wordlist

        Args:
            file_path: 文件路径

        Returns:
            词条列表
        """
        items = []

        if not os.path.exists(file_path):
            logger.warning(f"Wordlist file not found: {file_path}")
            return items

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        items.append(line)
        except Exception as e:
            logger.error(f"Failed to load wordlist: {e}")

        return items


class FuzzingEngine:
    """模糊测试引擎

    支持对 Web 参数、HTTP 头部进行模糊测试。
    支持内容发现。
    """

    STATUS_CODES = {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }

    INTERESTING_CODES = {200, 201, 204, 301, 302, 401, 403, 500, 502, 503}

    def __init__(
        self,
        wordlist_dir: Optional[List[str]] = None,
        wordlist_file: Optional[List[str]] = None,
        max_workers: int = 10,
        timeout: int = 10,
    ):
        """初始化模糊测试引擎

        Args:
            wordlist_dir: 目录发现 wordlist
            wordlist_file: 文件 wordlist
            max_workers: 最大并发数
            timeout: 请求超时
        """
        self.wordlist_dir = wordlist_dir or WordlistLoader.get_common_paths()
        self.wordlist_file = wordlist_file or WordlistLoader.get_default_files()
        self.max_workers = max_workers
        self.timeout = timeout

        self.session = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "HOS-LS Security Scanner/1.0",
            },
        )

        self.results: List[FuzzResult] = []
        self.discovered: List[DiscoveredItem] = []
        self._barray_detected: Set[int] = set()

    def is_available(self) -> bool:
        """检查引擎是否可用

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

    def fuzz_params(
        self,
        url: str,
        params: List[str],
        payloads: Optional[List[str]] = None,
        method: str = "GET",
    ) -> List[FuzzResult]:
        """模糊测试 URL 参数

        Args:
            url: 目标 URL
            params: 参数名列表
            payloads: 自定义 payloads，如果为 None 则使用默认 payloads
            method: HTTP 方法

        Returns:
            测试结果
        """
        results = []

        default_payloads = [
            "", " ", "<script>alert('XSS')</script>", "' OR '1'='1",
            "'; DROP TABLE users;--", "$(whoami)", "| cat /etc/passwd",
            "../", "..\\", "%00", "\x00", "<>",
            "a" * 1000, "a" * 10000,
        ]

        payloads = payloads or default_payloads

        for param in params:
            for payload in payloads:
                result = self._test_param(url, param, payload, method)
                if result:
                    results.append(result)

                    if result.status_code in self.INTERESTING_CODES:
                        self.results.append(result)

        return results

    def _test_param(
        self,
        url: str,
        param: str,
        payload: str,
        method: str,
    ) -> Optional[FuzzResult]:
        """测试单个参数

        Args:
            url: URL
            param: 参数名
            payload: payload
            method: HTTP 方法

        Returns:
            测试结果
        """
        try:
            start_time = time.time()

            if method.upper() == "GET":
                response = self.session.get(url, params={param: payload})
            else:
                response = self.session.request(method, url, data={param: payload})

            elapsed = time.time() - start_time

            result = FuzzResult(
                url=url,
                method=method,
                status_code=response.status_code,
                length=len(response.content),
                words=len(response.text.split()),
                time=elapsed,
                payload=payload,
                content_type=response.headers.get("content-type", ""),
                location=response.headers.get("location", ""),
                headers=dict(response.headers),
            )

            if response.status_code in self.INTERESTING_CODES:
                result.发现了 = True

            return result

        except Exception as e:
            logger.debug(f"Param fuzz error: {e}")
            return None

    def fuzz_headers(
        self,
        url: str,
        headers: Optional[List[str]] = None,
    ) -> List[FuzzResult]:
        """模糊测试 HTTP 头部

        Args:
            url: 目标 URL
            headers: 头部名称列表

        Returns:
            测试结果
        """
        results = []

        default_headers = [
            "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
            "X-Api-Version", "X-Auth-Token", "Authorization",
            "X-Custom-Header", "X-Requested-With",
            "Referer", "Origin", "Host",
        ]

        fuzz_headers_list = headers or default_headers

        payload = "<script>alert('XSS')</script>"

        for header in fuzz_headers_list:
            result = self._test_header(url, header, payload)
            if result:
                results.append(result)

        return results

    def _test_header(
        self,
        url: str,
        header: str,
        payload: str,
    ) -> Optional[FuzzResult]:
        """测试单个头部

        Args:
            url: URL
            header: 头部名称
            payload: payload

        Returns:
            测试结果
        """
        try:
            start_time = time.time()

            response = self.session.get(
                url,
                headers={header: payload},
                timeout=self.timeout,
            )

            elapsed = time.time() - start_time

            result = FuzzResult(
                url=url,
                method="GET",
                status_code=response.status_code,
                length=len(response.content),
                words=len(response.text.split()),
                time=elapsed,
                payload=f"{header}: {payload}",
                content_type=response.headers.get("content-type", ""),
                headers=dict(response.headers),
            )

            if payload in response.text:
                result.发现了 = True
                result.matched_pattern = "payload_reflected"

            if response.status_code in self.INTERESTING_CODES:
                result.发现了 = True

            return result

        except Exception:
            return None

    def discover_content(
        self,
        base_url: str,
        wordlist: Optional[List[str]] = None,
        recursive: bool = False,
        max_depth: int = 2,
    ) -> List[DiscoveredItem]:
        """发现内容/目录

        Args:
            base_url: 基础 URL
            wordlist: 路径 wordlist
            recursive: 是否递归扫描
            max_depth: 最大递归深度

        Returns:
            发现的项目
        """
        discovered = []
        base_url = base_url.rstrip("/") + "/"
        paths = wordlist or self.wordlist_dir

        for path in paths:
            path = path.lstrip("/")

            if not path:
                continue

            full_url = urljoin(base_url, path)

            try:
                response = self.session.get(
                    full_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                item = DiscoveredItem(
                    url=full_url,
                    status_code=response.status_code,
                    content_type=response.headers.get("content-type", ""),
                    size=len(response.content),
                    发现方法="directory_bruteforce",
                )

                discovered.append(item)
                self.discovered.append(item)

                if response.status_code == 200:
                    logger.info(f"Discovered: {full_url}")

                if recursive and response.status_code in {200, 301, 302}:
                    if "/" in path and max_depth > 0:
                        pass

            except Exception as e:
                logger.debug(f"Discovery error for {path}: {e}")

        return discovered

    def discover_common_paths(
        self,
        base_url: str,
    ) -> List[DiscoveredItem]:
        """使用常见路径列表发现内容

        Args:
            base_url: 基础 URL

        Returns:
            发现的项目
        """
        paths = WordlistLoader.get_common_paths()
        return self.discover_content(base_url, paths)

    def test_auth_bypass(
        self,
        url: str,
        methods: Optional[List[str]] = None,
    ) -> List[FuzzResult]:
        """测试认证绕过

        Args:
            url: 目标 URL
            methods: 使用的 HTTP 方法列表

        Returns:
            测试结果
        """
        results = []

        default_methods = [
            ("GET", {}),
            ("GET", {"X-Forwarded-For": "127.0.0.1"}),
            ("GET", {"X-Real-IP": "127.0.0.1"}),
            ("GET", {"X-Originating-IP": "127.0.0.1"}),
            ("GET", {"Host": "localhost"}),
            ("GET", {"Host": "127.0.0.1"}),
            ("GET", {"Authorization": "Basic YWRtaW46YWRtaW4="}),
            ("GET", {"Cookie": "admin=true"}),
        ]

        test_methods = methods or default_methods

        for method, headers in test_methods:
            try:
                response = self.session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                )

                result = FuzzResult(
                    url=url,
                    method=method,
                    status_code=response.status_code,
                    length=len(response.content),
                    words=len(response.text.split()),
                    time=0,
                    payload=str(headers),
                    content_type=response.headers.get("content-type", ""),
                    headers=headers,
                )

                if response.status_code == 200:
                    result.发现了 = True

                results.append(result)

            except Exception as e:
                logger.debug(f"Auth bypass test error: {e}")

        return results

    def get_tool_info(self) -> Dict[str, Any]:
        """获取工具信息

        Returns:
            工具信息字典
        """
        return {
            "name": "Fuzzing Engine",
            "version": "1.0",
            "capabilities": [
                "Parameter fuzzing",
                "Header fuzzing",
                "Content discovery",
                "Directory enumeration",
                "Authentication bypass testing",
            ],
            "available": self.is_available(),
            "http_required": ["httpx"],
        }


def run_fuzzing_scan(
    target: str,
    mode: str = "discover",
    params: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """运行模糊测试的便捷函数

    Args:
        target: 目标 URL
        mode: 模式 (discover, params, headers, auth_bypass)
        params: 参数名列表
        payloads: 自定义 payloads
        params: List of parameter names to fuzz
        payloads: List of payloads to use

    Returns:
        测试结果
    """
    engine = FuzzingEngine()

    if not engine.is_available():
        return {
            "success": False,
            "error": "httpx not available, install with: pip install httpx",
            "results": [],
        }

    try:
        if mode == "discover":
            results = engine.discover_common_paths(target)
            return {
                "success": True,
                "target": target,
                "mode": mode,
                "discovered": [r.to_dict() for r in results],
                "summary": {
                    "total": len(results),
                    "found_200": len([r for r in results if r.status_code == 200]),
                    "found_301": len([r for r in results if r.status_code == 301]),
                    "found_302": len([r for r in results if r.status_code == 302]),
                    "found_403": len([r for r in results if r.status_code == 403]),
                },
            }

        elif mode == "params":
            if not params:
                params = ["id", "page", "search", "query", "user", "file"]
            results = engine.fuzz_params(target, params, payloads)
            return {
                "success": True,
                "target": target,
                "mode": mode,
                "results": [r.to_dict() for r in results],
                "summary": {
                    "total": len(results),
                    "found": len([r for r in results if r.发现了]),
                },
            }

        elif mode == "headers":
            results = engine.fuzz_headers(target)
            return {
                "success": True,
                "target": target,
                "mode": mode,
                "results": [r.to_dict() for r in results],
                "summary": {
                    "total": len(results),
                    "found": len([r for r in results if r.发现了]),
                },
            }

        elif mode == "auth_bypass":
            results = engine.test_auth_bypass(target)
            return {
                "success": True,
                "target": target,
                "mode": mode,
                "results": [r.to_dict() for r in results],
                "summary": {
                    "total": len(results),
                    "found": len([r for r in results if r.发现了]),
                },
            }

        else:
            return {
                "success": False,
                "error": f"Unknown mode: {mode}",
                "results": [],
            }

    except Exception as e:
        logger.error(f"Fuzzing scan error: {e}")
        return {
            "success": False,
            "error": str(e),
            "results": [],
        }


def check_fuzzing_tools() -> Dict[str, Any]:
    """检查模糊测试工具状态

    Returns:
        工具状态信息
    """
    return {
        "httpx_available": HTTPX_AVAILABLE,
        "fuzzing_engine_available": HTTPX_AVAILABLE,
        "install_instructions": "pip install httpx",
        "default_wordlists_loaded": True,
    }
