"""HTTP Protocol

HTTP/HTTPS协议实现，支持Web服务探测和目录枚举。
"""

import logging
from typing import Optional, Dict, Any, List
import requests
from requests.auth import HTTPBasicAuth

from ..exceptions import ConnectionError, AuthenticationError, TimeoutError, ProtocolError
from .base_protocol import BaseProtocol

logger = logging.getLogger(__name__)


class HTTPProtocol(BaseProtocol):
    """HTTP协议类"""

    COMMON_PATHS = [
        '/', '/admin', '/login', '/api', '/backup', '/config',
        '/dashboard', '/uploads', '/images', '/css', '/js',
        '/robots.txt', '/sitemap.xml', '/.git/', '/env',
        '/wp-admin', '/phpmyadmin', '/admin.php', '/login.php',
    ]

    def __init__(
        self,
        host: str,
        port: int = 80,
        use_ssl: bool = False,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 30,
    ):
        super().__init__()
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.username = username
        self.password = password
        self.timeout = timeout
        self._session: Optional[requests.Session] = None
        self._base_url: Optional[str] = None

    @property
    def base_url(self) -> str:
        """获取基础URL"""
        if self._base_url is None:
            protocol = 'https' if self.use_ssl else 'http'
            self._base_url = f"{protocol}://{self.host}:{self.port}"
        return self._base_url

    def connect(self) -> bool:
        """建立HTTP会话"""
        try:
            self._session = requests.Session()

            if self.username and self.password:
                self._session.auth = HTTPBasicAuth(self.username, self.password)

            response = self._session.get(
                self.base_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            response.raise_for_status()
            self._connected = True
            logger.info(f"HTTP connection established to {self.base_url}")
            return True

        except requests.exceptions.Timeout:
            logger.error(f"Connection timeout to {self.host}:{self.port}")
            raise TimeoutError(f"Connection timeout to {self.host}:{self.port}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error to {self.host}:{self.port}: {e}")
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                logger.error(f"Authentication failed for {self.host}:{self.port}")
                raise AuthenticationError(f"Authentication failed: {e}")
            logger.error(f"HTTP error: {e}")
            raise ProtocolError(f"HTTP error: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            raise ProtocolError(f"Request error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during connection: {e}")
            raise ConnectionError(f"Unexpected error: {e}")

    def disconnect(self) -> None:
        """关闭HTTP会话"""
        if self._session:
            try:
                self._session.close()
                logger.debug(f"HTTP session closed for {self.base_url}")
            except Exception as e:
                logger.warning(f"Error closing HTTP session: {e}")
            finally:
                self._session = None
        self._connected = False

    def is_connected(self) -> bool:
        """检查会话状态"""
        return self._connected and self._session is not None

    def send(self, data: bytes) -> int:
        """发送数据（HTTP不支持此操作）"""
        raise NotImplementedError("HTTP does not support raw send")

    def recv(self, size: int) -> bytes:
        """接收数据（HTTP不支持此操作）"""
        raise NotImplementedError("HTTP does not support raw recv")

    def _get_session(self) -> requests.Session:
        """获取或创建会话"""
        if self._session is None:
            self._session = requests.Session()
            if self.username and self.password:
                self._session.auth = HTTPBasicAuth(self.username, self.password)
        return self._session

    def _make_request(self, method: str, path: str, data: Optional[bytes] = None, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """发送HTTP请求的通用方法"""
        url = f"{self.base_url}{path}"

        try:
            session = self._get_session()

            request_kwargs: Dict[str, Any] = {
                'timeout': self.timeout,
                'verify': False,
                'allow_redirects': True,
            }

            if headers:
                request_kwargs['headers'] = headers

            if method.upper() == 'GET':
                response = session.get(url, **request_kwargs)
            elif method.upper() == 'POST':
                request_kwargs['data'] = data
                response = session.post(url, **request_kwargs)
            elif method.upper() == 'HEAD':
                response = session.head(url, **request_kwargs)
            else:
                raise ProtocolError(f"Unsupported HTTP method: {method}")

            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.content,
                'text': response.text,
            }

        except requests.exceptions.Timeout:
            logger.error(f"Request timeout for {url}")
            raise TimeoutError(f"Request timeout for {path}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {url}: {e}")
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                raise AuthenticationError(f"Authentication failed: {e}")
            if e.response is not None and e.response.status_code == 404:
                raise ProtocolError(f"Resource not found: {path}")
            raise ProtocolError(f"HTTP error: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            raise ProtocolError(f"Request error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during request: {e}")
            raise ProtocolError(f"Unexpected error: {e}")

    def get(self, path: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """发送GET请求"""
        logger.debug(f"GET request to {path}")
        return self._make_request('GET', path, headers=headers)

    def post(self, path: str, data: bytes, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """发送POST请求"""
        logger.debug(f"POST request to {path}")
        return self._make_request('POST', path, data=data, headers=headers)

    def head(self, path: str) -> Dict[str, Any]:
        """发送HEAD请求"""
        logger.debug(f"HEAD request to {path}")
        return self._make_request('HEAD', path)

    def enumerate_directories(self, paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """枚举常见目录"""
        if paths is None:
            paths = self.COMMON_PATHS

        results: List[Dict[str, Any]] = []

        for path in paths:
            try:
                response = self._make_request('GET', path)
                status_code = response['status_code']

                if status_code in (200, 201, 204) or (300 <= status_code < 400):
                    results.append({
                        'path': path,
                        'status_code': status_code,
                        'found': True,
                    })
                    logger.info(f"Found accessible path: {path} (status: {status_code})")

            except TimeoutError:
                logger.warning(f"Timeout while checking {path}")
                results.append({
                    'path': path,
                    'status_code': None,
                    'found': False,
                    'error': 'timeout',
                })
            except ConnectionError:
                logger.warning(f"Connection error while checking {path}")
                results.append({
                    'path': path,
                    'status_code': None,
                    'found': False,
                    'error': 'connection_error',
                })
            except Exception as e:
                logger.debug(f"Error checking {path}: {e}")

        return results

    def detect_web_service(self) -> Dict[str, Any]:
        """检测Web服务信息"""
        result = {
            'server_type': 'Unknown',
            'version': None,
            'powered_by': None,
            'detected': False,
        }

        try:
            response = self._make_request('GET', '/')
            headers = response['headers']

            server_header = headers.get('Server', '')
            if server_header:
                result['server_type'] = server_header
                result['detected'] = True
                logger.info(f"Detected server: {server_header}")

                server_lower = server_header.lower()
                if 'apache' in server_lower:
                    result['server_type'] = 'Apache'
                elif 'nginx' in server_lower:
                    result['server_type'] = 'nginx'
                elif 'microsoft' in server_lower or 'iis' in server_lower:
                    result['server_type'] = 'IIS'
                elif 'cloudflare' in server_lower:
                    result['server_type'] = 'Cloudflare'
                elif 'nginx' in server_lower:
                    result['server_type'] = 'nginx'

                import re
                version_match = re.search(r'(\d+\.[.\d]+)', server_header)
                if version_match:
                    result['version'] = version_match.group(1)

            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                result['powered_by'] = powered_by
                logger.info(f"X-Powered-By: {powered_by}")

            www_authenticate = headers.get('WWW-Authenticate', '')
            if www_authenticate:
                result['auth_required'] = www_authenticate.strip()

            content_type = headers.get('Content-Type', '')
            if content_type:
                result['content_type'] = content_type

        except TimeoutError:
            logger.warning(f"Timeout while detecting web service")
            result['error'] = 'timeout'
        except ConnectionError as e:
            logger.warning(f"Connection error while detecting web service: {e}")
            result['error'] = 'connection_error'
        except Exception as e:
            logger.warning(f"Error detecting web service: {e}")
            result['error'] = str(e)

        return result

    def check_https_support(self) -> bool:
        """检查目标是否支持HTTPS"""
        if self.use_ssl:
            return True

        https_port = self.port if self.port != 80 else 443
        test_url = f"https://{self.host}:{https_port}/"

        try:
            response = requests.get(
                test_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            response.raise_for_status()
            logger.info(f"HTTPS is supported on {self.host}:{https_port}")
            return True
        except requests.exceptions.SSLError:
            logger.info(f"SSL error - HTTPS may not be supported on {self.host}:{https_port}")
            return False
        except requests.exceptions.ConnectionError:
            logger.info(f"Connection refused - HTTPS not supported on {self.host}:{https_port}")
            return False
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout while checking HTTPS support")
            return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error checking HTTPS support: {e}")
            return False
        except Exception as e:
            logger.warning(f"Unexpected error checking HTTPS: {e}")
            return False
