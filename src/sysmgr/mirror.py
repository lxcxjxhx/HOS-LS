"""代理/镜像自动检测与切换模块

提供网络可达性检测、最快镜像选择、HTTP/HTTPS 代理支持。
"""

import logging
import os
import socket
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# PyPI 镜像候选列表
PYPI_MIRRORS = [
    "https://mirrors.aliyun.com/pypi/simple/",
    "https://pypi.tuna.tsinghua.edu.cn/simple/",
    "https://pypi.mirrors.ustc.edu.cn/simple/",
    "https://repo.huaweicloud.com/repository/pypi/simple/",
    "https://pypi.org/simple/",
]

# Go 代理候选列表
GOPROXY_MIRRORS = [
    "https://goproxy.cn",
    "https://goproxy.io",
    "https://mirrors.aliyun.com/goproxy/",
    "https://proxy.golang.org",
]

# 通用网络连通性检测目标
CONNECTIVITY_CHECK_URLS = [
    "https://www.baidu.com",
    "https://www.aliyun.com",
    "https://www.google.com",
]

DEFAULT_TIMEOUT = 5.0


def get_proxy_env() -> Optional[str]:
    """获取环境变量中配置的代理

    Returns:
        代理 URL 或 None
    """
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        proxy = os.environ.get(var)
        if proxy:
            return proxy
    return None


def set_proxy_env(proxy_url: Optional[str]) -> None:
    """设置 HTTP/HTTPS 代理环境变量

    Args:
        proxy_url: 代理 URL，为 None 时清除代理环境变量
    """
    vars_to_set = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
    if proxy_url:
        for var in vars_to_set:
            os.environ[var] = proxy_url
        logger.info("[MIRROR] 代理已设置: %s", proxy_url)
    else:
        for var in vars_to_set:
            os.environ.pop(var, None)
        logger.debug("[MIRROR] 代理环境变量已清除")


def check_connectivity(url: str, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """检测 URL 是否可达

    Args:
        url: 目标 URL
        timeout: 超时时间（秒）

    Returns:
        是否可达
    """
    try:
        resp = httpx.head(url, timeout=timeout, follow_redirects=True)
        return resp.status_code < 400
    except Exception:
        return False


def measure_latency(url: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[float]:
    """测量 URL 响应延迟

    Args:
        url: 目标 URL
        timeout: 超时时间（秒）

    Returns:
        延迟（秒），超时或失败时返回 None
    """
    try:
        start = time.monotonic()
        resp = httpx.head(url, timeout=timeout, follow_redirects=True)
        if resp.status_code < 400:
            return time.monotonic() - start
    except Exception:
        pass
    return None


def find_fastest_mirror(
    mirrors: list[str], timeout: float = DEFAULT_TIMEOUT
) -> Optional[str]:
    """从候选列表中找到响应最快的镜像

    Args:
        mirrors: 镜像 URL 列表
        timeout: 单个镜像超时时间（秒）

    Returns:
        最快镜像 URL，全部不可达时返回 None
    """
    fastest_url = None
    fastest_latency = float("inf")

    for url in mirrors:
        latency = measure_latency(url, timeout=timeout)
        if latency is not None and latency < fastest_latency:
            fastest_url = url
            fastest_latency = latency
            logger.debug("[MIRROR] %s 可达 (延迟: %.2fs)", url, latency)

    if fastest_url:
        logger.info("[MIRROR] 最快镜像: %s (延迟: %.2fs)", fastest_url, fastest_latency)
    else:
        logger.warning("[MIRROR] 所有镜像均不可达")

    return fastest_url


def find_fastest_pypi_mirror(
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[str]:
    """查找最快的 PyPI 镜像

    Args:
        timeout: 超时时间（秒）

    Returns:
        最快镜像 URL 或 None
    """
    return find_fastest_mirror(PYPI_MIRRORS, timeout=timeout)


def find_fastest_goproxy_mirror(
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[str]:
    """查找最快的 Go 代理镜像

    Args:
        timeout: 超时时间（秒）

    Returns:
        最快镜像 URL 或 None
    """
    return find_fastest_mirror(GOPROXY_MIRRORS, timeout=timeout)


def detect_network_status(timeout: float = DEFAULT_TIMEOUT) -> dict:
    """检测当前网络状态

    Args:
        timeout: 超时时间（秒）

    Returns:
        包含网络状态信息的字典
    """
    proxy = get_proxy_env()
    direct_ok = any(check_connectivity(u, timeout) for u in CONNECTIVITY_CHECK_URLS[:2])

    return {
        "proxy": proxy,
        "direct_connection": direct_ok,
        "behind_firewall": not direct_ok,
        "fastest_pypi_mirror": find_fastest_pypi_mirror(timeout),
        "fastest_goproxy_mirror": find_fastest_goproxy_mirror(timeout),
    }


class MirrorManager:
    """镜像管理器 - 封装镜像检测与切换逻辑"""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self._pypi_mirror: Optional[str] = None
        self._goproxy_mirror: Optional[str] = None

    @property
    def pypi_mirror(self) -> Optional[str]:
        """获取已检测的 PyPI 镜像"""
        return self._pypi_mirror

    @property
    def goproxy_mirror(self) -> Optional[str]:
        """获取已检测的 Go 代理镜像"""
        return self._goproxy_mirror

    def detect_all(self) -> None:
        """检测所有镜像"""
        logger.info("[MIRROR] 开始检测可用镜像...")
        self._pypi_mirror = find_fastest_pypi_mirror(self.timeout)
        self._goproxy_mirror = find_fastest_goproxy_mirror(self.timeout)

        network = detect_network_status(self.timeout)
        if network["behind_firewall"]:
            logger.warning("[MIRROR] 检测到墙内网络，已自动选择镜像")
        else:
            logger.info("[MIRROR] 网络连接正常")

    def get_pip_index_url(self) -> Optional[str]:
        """获取 pip 使用的 index-url"""
        return self._pypi_mirror

    def get_go_proxy(self) -> str:
        """获取 GOPROXY 环境变量值"""
        return self._goproxy_mirror or "https://goproxy.cn"

    def apply_proxy(self, proxy_url: Optional[str] = None) -> None:
        """应用代理设置

        Args:
            proxy_url: 代理 URL，为 None 时自动从环境变量读取
        """
        if proxy_url is None:
            proxy_url = get_proxy_env()
        set_proxy_env(proxy_url)
