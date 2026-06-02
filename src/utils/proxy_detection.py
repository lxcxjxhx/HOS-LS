"""
Proxy auto-detection utility.
Auto-detect local proxy (Clash etc), default port 7897.
Includes fallback mechanism for when proxy is unavailable.
"""

import os
import socket
import logging
from typing import Optional, List, Tuple

logger = logging.getLogger(__name__)

DEFAULT_PROXY_PORTS = [7897, 7890, 7891, 1080, 10809, 20170]


def detect_proxy(host="127.0.0.1", ports=None):
    """Auto-detect local proxy with fallback mechanism.
    
    Returns:
        Tuple[Optional[str], bool]: (proxy_url or None, is_fallback)
    """
    if ports is None:
        ports = DEFAULT_PROXY_PORTS
    
    # 1. Check environment variables first
    env_proxy = (
        os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
        or os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
    )
    if env_proxy:
        # Validate that the env proxy is actually reachable
        if _test_proxy_connection(env_proxy):
            return env_proxy, False
        else:
            logger.warning(f"[PROXY] Environment proxy {env_proxy} is not reachable, attempting fallback")
    
    # 2. Try default proxy ports
    for port in ports:
        proxy_url = f"http://{host}:{port}"
        if _test_proxy_connection(proxy_url):
            return proxy_url, False
    
    # 3. Fallback: return None (no proxy) with warning
    logger.warning("[PROXY] No available proxy detected, requests will use direct connection")
    return None, True


def _test_proxy_connection(proxy_url: str, timeout: float = 1.0) -> bool:
    """Test if a proxy connection is actually working.
    
    Args:
        proxy_url: Full proxy URL (e.g., http://127.0.0.1:7897)
        timeout: Connection timeout in seconds
        
    Returns:
        bool: True if proxy is reachable
    """
    try:
        # Parse host and port from proxy URL
        url_part = proxy_url.replace("http://", "").replace("https://", "")
        if ":" in url_part:
            host, port_str = url_part.rsplit(":", 1)
            port = int(port_str)
        else:
            host = url_part
            port = 80
        
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError, ValueError):
        return False


def get_proxy_with_fallback(host="127.0.0.1", ports=None, force_no_proxy=False):
    """Get proxy with fallback mechanism and logging.
    
    Args:
        host: Proxy host to check
        ports: List of ports to check
        force_no_proxy: If True, skip proxy detection entirely
        
    Returns:
        Optional[str]: Proxy URL or None
    """
    if force_no_proxy:
        logger.info("[PROXY] Proxy disabled by configuration, using direct connection")
        return None
    
    proxy_url, is_fallback = detect_proxy(host, ports)
    
    if proxy_url:
        if is_fallback:
            logger.info(f"[PROXY] Using fallback proxy: {proxy_url} (env proxy was unavailable)")
        else:
            logger.info(f"[PROXY] Using proxy: {proxy_url}")
    else:
        logger.info("[PROXY] No proxy detected, using direct connection")
    
    return proxy_url
