"""
Proxy auto-detection utility.
Auto-detect local proxy (Clash etc), default port 7897.
"""

import os
import socket
from typing import Optional, List


DEFAULT_PROXY_PORTS = [7897, 7890, 7891, 1080, 10809, 20170]


def detect_proxy(host="127.0.0.1", ports=None):
    """Auto-detect local proxy."""
    if ports is None:
        ports = DEFAULT_PROXY_PORTS
    env_proxy = (
        os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
        or os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
    )
    if env_proxy:
        return env_proxy
    for port in ports:
        try:
            sock = socket.create_connection((host, port), timeout=0.5)
            sock.close()
            return f"http://{host}:{port}"
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return None
