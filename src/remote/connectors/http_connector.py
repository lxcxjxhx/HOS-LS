"""
HTTP/HTTPS 连接器

基于 httpx 实现的高性能异步 HTTP 连接器。
支持网站爬取、API 调用、表单提交等功能。
"""

import asyncio
import re
from datetime import datetime
from typing import List, Optional, Dict, Any, Set
from urllib.parse import urljoin, urlparse

from .base_connector import (
    BaseConnector,
    ConnectionResult,
    ConnectionStatus,
    ConnectionConfig
)
from ..target import FileInfo

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    try:
        import aiohttp
        HTTPX_AVAILABLE = False
        AIOHTTP_AVAILABLE = True
    except ImportError:
        AIOHTTP_AVAILABLE = False

from rich.console import Console

console = Console()


class HTTPConnector(BaseConnector):
    """
    HTTP/HTTPS 网站连接器
    
    功能特性：
    - 异步高性能（基于 httpx 或 aiohttp）
    - 支持 REST API 调用
    - HTML/JS/CSS 资源抓取
    - Cookie/Session 管理
    - 自动重定向处理
    - 代理支持
    - SSL/TLS 验证
    - 请求频率限制
    """
    
    connector_type = "http"
    
    def __init__(
        self,
        url: str,
        method: str = "GET",
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
        auth: tuple = None,
        timeout: int = 30,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
        config: ConnectionConfig = None,
        **kwargs
    ):
        """
        初始化 HTTP 连接器
        
        Args:
            url: 目标URL
            method: 默认请求方法（GET/POST等）
            headers: 自定义请求头
            cookies: Cookie字典
            auth: 认证信息元组 (username, password)
            timeout: 请求超时时间（秒）
            follow_redirects: 是否跟随重定向
            verify_ssl: 是否验证SSL证书
            config: 连接配置
            **kwargs: 额外参数
        """
        super().__init__(config=config, **kwargs)
        
        self.url = url.rstrip('/')
        self.method = method.upper()
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.auth = auth
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        
        self._client: Optional[Any] = None
        self._session_cookies = {}
        self._visited_urls: Set[str] = set()
        self._request_count = 0
        self._last_request_time: Optional[datetime] = None
        
        if not HTTPX_AVAILABLE and not AIOHTTP_AVAILABLE:
            raise ImportError(
                "请安装 httpx 库: pip install httpx"
                "\n或安装 aiohttp: pip install aiohttp"
            )
    
    async def _do_connect(self) -> ConnectionResult:
        """测试HTTP连接"""
        try:
            if HTTPX_AVAILABLE:
                client_kwargs = {
                    'headers': {
                        'User-Agent': self.config.user_agent,
                        **self.headers
                    },
                    'timeout': httpx.Timeout(self.timeout),
                    'follow_redirects': self.follow_redirects,
                    'verify': self.verify_ssl
                }
                
                if self.config.proxy:
                    client_kwargs['proxy'] = self.config.proxy
                    
                if self.auth:
                    client_kwargs['auth'] = httpx.BasicAuth(*self.auth)
                    
                self._client = httpx.AsyncClient(**client_kwargs)
                
                response = await self._client.get(self.url)
                
                return ConnectionResult(
                    success=True,
                    status=ConnectionStatus.CONNECTED,
                    message=f"已连接到 {self.url} (状态码: {response.status_code})",
                    metadata={
                        'url': self.url,
                        'status_code': response.status_code,
                        'server': response.headers.get('Server', 'Unknown'),
                        'content_type': response.headers.get('Content-Type', '')
                    }
                )
                
            elif AIOHTTP_AVAILABLE:
                import aiohttp
                
                session_kwargs = {
                    'headers': {
                        'User-Agent': self.config.user_agent,
                        **self.headers
                    },
                    'timeout': aiohttp.ClientTimeout(total=self.timeout),
                    'cookie_jar': aiohttp.CookieJar()
                }
                
                if self.auth:
                    session_kwargs['auth'] = aiohttp.BasicAuth(*self.auth)
                    
                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
                self._client = aiohttp.ClientSession(connector=connector, **session_kwargs)
                
                async with self._client.get(self.url) as response:
                    return ConnectionResult(
                        success=True,
                        status=ConnectionStatus.CONNECTED,
                        message=f"已连接到 {self.url} (状态码: {response.status})",
                        metadata={
                            'url': self.url,
                            'status_code': response.status,
                            'server': response.headers.get('Server', 'Unknown'),
                            'content_type': response.headers.get('Content-Type', '')
                        }
                    )
                    
        except httpx.ConnectError as e:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message=f"连接失败: 无法访问 {self.url}",
                error=e
            )
        except httpx.TimeoutException as e:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message=f"连接超时 ({self.timeout}s)",
                error=e
            )
        except Exception as e:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message=str(e),
                error=e
            )
    
    async def _do_disconnect(self) -> None:
        """关闭HTTP客户端"""
        try:
            if self._client:
                await self._client.aclose()
                self._client = None
        except Exception as e:
            console.print(f"[yellow]关闭HTTP客户端时出错: {e}[/yellow]")
    
    async def _rate_limit(self):
        """请求频率限制"""
        if self._last_request_time:
            elapsed = (datetime.now() - self._last_request_time).total_seconds()
            min_interval = getattr(self.config, 'request_interval', 0.5)
            
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = datetime.now()
        self._request_count += 1
    
    async def fetch_page(
        self,
        path: str = "/",
        method: str = None,
        params: Dict[str, Any] = None,
        data: Any = None,
        json_data: Dict[str, Any] = None,
        headers: Dict[str, str] = None,
        **kwargs
    ) -> str:
        """
        获取网页内容
        
        Args:
            path: URL路径
            method: 请求方法
            params: 查询参数
            data: 表单数据
            json_data: JSON数据
            headers: 额外请求头
            
        Returns:
            页面HTML内容
        """
        if not self.is_connected:
            raise ConnectionError("未连接到网站")
            
        await self._rate_limit()
        
        full_url = urljoin(self.url + '/', path.lstrip('/'))
        method = method or self.method
        
        try:
            if HTTPX_AVAILABLE:
                request_kwargs = {
                    'method': method,
                    'params': params,
                    'data': data,
                    'json': json_data,
                    'headers': headers
                }
                
                response = await self._client.request(full_url, **request_kwargs)
                response.raise_for_status()
                
                return response.text
                
            elif AIOHTTP_AVAILABLE:
                async with self._client.request(
                    method=method,
                    url=full_url,
                    params=params,
                    data=data,
                    json=json_data,
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    return await response.text()
                    
        except httpx.HTTPStatusError as e:
            raise IOError(f"HTTP错误 {e.response.status_code}: {full_url}")
        except Exception as e:
            raise IOError(f"获取页面失败: {e}")
    
    async def crawl(
        self,
        path: str = "/",
        depth: int = 3,
        max_pages: int = 100,
        allowed_domains: List[str] = None,
        exclude_patterns: List[str] = None,
        include_patterns: List[str] = None,
        **kwargs
    ) -> List[FileInfo]:
        """
        爬取网站页面和资源
        
        Args:
            path: 起始路径
            depth: 爬取深度
            max_pages: 最大页面数
            allowed_domains: 允许的域名列表
            exclude_patterns: 排除URL模式
            include_patterns: 包含URL模式
            
        Returns:
            页面/资源信息列表
        """
        if not self.is_connected:
            raise ConnectionError("未连接到网站")
            
        files = []
        pages_to_visit = [(path, 0)]
        visited_urls = set()
        
        default_exclude = [
            r'\.(jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)$',
            r'\.css$',
            r'javascript:',
            r'mailto:',
            r'#',
            r'/api/',
            r'/admin/',
            r'/login',
            r'/logout'
        ]
        
        default_include = [
            r'\.(html?|php|jsp|aspx?)$',
            r'^/$'
        ]
        
        exclude_patterns = exclude_patterns or default_exclude
        include_patterns = include_patterns or default_include
        
        while pages_to_visit and len(files) < max_pages:
            current_path, current_depth = pages_to_visit.pop(0)
            
            if current_depth > depth:
                continue
                
            full_url = urljoin(self.url + '/', current_path.lstrip('/'))
            
            if full_url in visited_urls:
                continue
                
            visited_urls.add(full_url)
            
            try:
                content = await self.fetch_page(current_path)
                
                file_info = FileInfo(
                    path=full_url,
                    name=current_path.split('/')[-1] or 'index.html',
                    size=len(content.encode('utf-8')),
                    modified_time=datetime.now(),
                    is_file=True,
                    mime_type='text/html',
                    language='html'
                )
                files.append(file_info)
                
                if current_depth < depth:
                    links = self._extract_links(content, full_url)
                    
                    for link in links:
                        if link not in visited_urls and len(files) < max_pages:
                            should_include = any(
                                re.search(pattern, link, re.IGNORECASE)
                                for pattern in include_patterns
                            )
                            
                            should_exclude = any(
                                re.search(pattern, link, re.IGNORECASE)
                                for pattern in exclude_patterns
                            )
                            
                            if should_include and not should_exclude:
                                relative_path = link.replace(self.url + '/', '') if link.startswith(self.url) else link
                                pages_to_visit.append((relative_path, current_depth + 1))
                                
            except Exception as e:
                console.print(f"[yellow]警告: 无法爬取 {full_url}: {e}[/yellow]")
                
        return files
    
    def _extract_links(self, html_content: str, base_url: str) -> List[str]:
        """从HTML中提取链接"""
        links = []
        
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        matches = href_pattern.findall(html_content)
        
        for match in matches:
            if match.startswith(('http://', 'https://')):
                if match.startswith(self.url):
                    links.append(match)
            elif match.startswith('/') or not match.startswith(('javascript:', 'mailto:', '#')):
                absolute_url = urljoin(base_url, match)
                if absolute_url.startswith(self.url):
                    links.append(absolute_url)
                    
        return list(set(links))
    
    async def get_resource_info(self, path: str = "/", **kwargs) -> FileInfo:
        """
        获取网页/资源信息
        
        Args:
            path: URL路径
            
        Returns:
            资源信息对象
        """
        if not self.is_connected:
            raise ConnectionError("未连接到网站")
            
        await self._rate_limit()
        
        full_url = urljoin(self.url + '/', path.lstrip('/'))
        
        try:
            if HTTPX_AVAILABLE:
                response = await self._client.head(full_url)
                content_length = int(response.headers.get('Content-Length', 0))
                content_type = response.headers.get('Content-Type', '').split(';')[0]
                
                file_name = path.split('/')[-1] or 'index.html'
                
                file_info = FileInfo(
                    path=full_url,
                    name=file_name,
                    size=content_length,
                    modified_time=datetime.now(),
                    is_file=True,
                    mime_type=content_type
                )
                
                if 'html' in content_type.lower():
                    file_info.language = 'html'
                elif 'javascript' in content_type.lower():
                    file_info.language = 'javascript'
                elif 'css' in content_type.lower():
                    file_info.language = 'css'
                    
                return file_info
                
        except Exception as e:
            console.print(f"[yellow]警告: 获取资源信息失败 {full_url}: {e}[/yellow]")
            
        return FileInfo(
            path=full_url,
            name=path.split('/')[-1] or 'unknown',
            is_file=True
        )
    
    async def send_request(
        self,
        endpoint: str,
        method: str = "GET",
        data: Dict[str, Any] = None,
        json_data: Dict[str, Any] = None,
        headers: Dict[str, str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        发送API请求
        
        Args:
            endpoint: API端点路径
            method: 请求方法
            data: 表单数据
            json_data: JSON数据
            headers: 额外请求头
            
        Returns:
            响应结果字典
        """
        if not self.is_connected:
            raise ConnectionError("未连接到网站")
            
        await self._rate_limit()
        
        full_url = urljoin(self.url + '/', endpoint.lstrip('/'))
        
        try:
            if HTTPX_AVAILABLE:
                request_kwargs = {
                    'method': method,
                    'url': full_url,
                    'data': data,
                    'json': json_data,
                    'headers': headers
                }
                
                response = await self._client.request(**request_kwargs)
                
                result = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'success': response.status_code < 400
                }
                
                try:
                    result['json'] = response.json()
                except:
                    result['text'] = response.text
                    
                return result
                
        except Exception as e:
            return {
                'status_code': 0,
                'error': str(e),
                'success': False
            }
    
    async def list_files(self, path: str = "/", **kwargs) -> List[FileInfo]:
        """列出网站页面/资源（使用crawl方法）"""
        return await self.crawl(path, **kwargs)
    
    async def read_file(self, path: str, **kwargs) -> str:
        """获取网页/资源内容"""
        return await self.fetch_page(path, **kwargs)
    
    async def execute_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """发送API请求（模拟命令执行）"""
        return await self.send_request(command, **kwargs)
    
    async def get_api_endpoints(self, base_path: str = "/api") -> List[str]:
        """
        尝试发现API端点
        
        Args:
            base_path: API基础路径
            
        Returns:
            发现的API端点列表
        """
        common_endpoints = [
            '/users', '/auth', '/login', '/register',
            '/products', '/orders', '/config',
            '/health', '/version', '/status',
            '/admin', '/dashboard', '/settings',
            '/v1/', '/v2/', '/api/v1/'
        ]
        
        discovered = []
        
        for endpoint in common_endpoints:
            full_path = f"{base_path}{endpoint}"
            
            try:
                info = await self.get_resource_info(full_path)
                
                if info.size > 0:
                    discovered.append(urljoin(self.url + '/', full_path.lstrip('/')))
                    
            except Exception:
                pass
                
        return discovered
    
    async def check_security_headers(self) -> Dict[str, Any]:
        """
        检查安全响应头
        
        Returns:
            安全头检查结果
        """
        if not self.is_connected:
            raise ConnectionError("未连接到网站")
            
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Frame-Options': '点击劫持防护',
            'X-Content-Type-Options': 'MIME嗅探防护',
            'X-XSS-Protection': 'XSS防护',
            'Content-Security-Policy': 'CSP策略',
            'Referrer-Policy': 'Referer策略',
            'Permissions-Policy': '权限策略',
            'Cache-Control': '缓存控制'
        }
        
        results = {}
        
        try:
            response = await self._client.head(self.url)
            
            for header, description in security_headers.items():
                value = response.headers.get(header)
                results[header] = {
                    'present': bool(value),
                    'value': value or '',
                    'description': description,
                    'severity': 'medium' if header in ['X-Frame-Options', 'X-XSS-Protection'] else 'low'
                }
                
        except Exception as e:
            console.print(f"[yellow]检查安全头失败: {e}[/yellow]")
            
        return results
    
    async def close(self) -> None:
        """关闭连接（别名）"""
        await self.disconnect()
    
    def get_stats(self) -> Dict[str, Any]:
        """获取连接统计"""
        stats = super().get_stats()
        stats.update({
            'total_requests': self._request_count,
            'visited_urls': len(self._visited_urls),
            'target_url': self.url
        })
        return stats


def create_http_connector_from_config(config_dict: Dict[str, Any]) -> HTTPConnector:
    """
    从配置字典创建HTTP连接器
    
    Args:
        config_dict: 配置字典
        
    Returns:
        HTTP连接器实例
    """
    options = config_dict.get('options', {})
    credentials = config_dict.get('credentials', {})
    
    auth_config = options.get('auth', {})
    auth_type = auth_config.get('type')
    auth_tuple = None
    
    if auth_type == 'basic':
        username = credentials.get('username', auth_config.get('username'))
        password = credentials.get('password', auth_config.get('token'))
        if username and password:
            auth_tuple = (username, password)
    elif auth_type == 'bearer':
        token = credentials.get('token', auth_config.get('token'))
        if token:
            return HTTPConnector(
                url=config_dict.get('uri', ''),
                headers={'Authorization': f'Bearer {token}'}
            )
    
    return HTTPConnector(
        url=config_dict.get('uri', ''),
        auth=auth_tuple,
        **options
    )
