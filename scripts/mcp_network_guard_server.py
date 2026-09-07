"""Reasonix 全局 MCP server：MCP/skill 网络连通性自愈。

由 scripts/install_mcp_network_guard.py 安装到
``%APPDATA%\\reasonix\\mcp-network-guard.py``，并在全局 config.toml 注册为
stdio 插件 ``network-guard``。任何项目/宿主的会话都可调用工具：

- ``network_guard(hosts, auto_export)`` — 探测目标 → 已有代理生效则复用 →
  否则扫描常见本地代理端口自动挂载 → 直连兜底 → 全败时返回诊断与 exit 1。
- ``mount_proxy(port)`` — 显式挂载指定代理端口到当前会话环境。
"""
from __future__ import annotations

import os
import urllib.request
from typing import Any, Dict, List

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("network-guard")

DEFAULT_HOSTS = ["https://github.com", "https://registry.npmjs.org"]
CANDIDATE_PORTS = [7897, 7890, 7891, 10808, 10809, 1080, 8118, 8888]
GUARD_TIMEOUT = 6


def _probe(url: str) -> bool:
    """单 URL 探测：状态码 2xx/3xx 即通（沿用当前进程代理变量）。"""
    try:
        req = urllib.request.Request(
            url, method="HEAD", headers={"User-Agent": "network-guard/1.0"}
        )
        with urllib.request.urlopen(req, timeout=GUARD_TIMEOUT) as resp:
            return 200 <= resp.status < 400
    except Exception:
        return False


def _all_ok(hosts: List[str]) -> bool:
    return all(_probe(h) for h in hosts)


def _mount(port: int) -> None:
    proxy = f"http://127.0.0.1:{port}"
    os.environ["HTTP_PROXY"] = proxy
    os.environ["HTTPS_PROXY"] = proxy
    os.environ["ALL_PROXY"] = proxy


@mcp.tool()
def network_guard(
    hosts: List[str] | None = None, auto_export: bool = True
) -> Dict[str, Any]:
    """检测 hosts 连通性；不通则自动挂载本地代理并复测。

    返回 {"ok": bool, "action": str, "proxy": str|None, "detail": [...]}。
    """
    targets = hosts or DEFAULT_HOSTS
    detail: List[str] = []
    # 1) 已有代理变量 → 先复测
    existing = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if existing:
        ok = _all_ok(targets)
        detail.append(f"existing proxy {existing}: {'OK' if ok else 'unreachable'}")
        if ok:
            return {"ok": True, "action": "reuse", "proxy": existing, "detail": detail}
    # 2) 扫描候选端口
    for port in CANDIDATE_PORTS:
        proxy = f"http://127.0.0.1:{port}"
        os.environ["HTTPS_PROXY"] = proxy
        os.environ["HTTP_PROXY"] = proxy
        if _all_ok(targets):
            _mount(port)
            detail.append(f"auto-mounted {proxy}")
            if auto_export:
                detail.append(
                    "export HTTPS_PROXY=%s HTTP_PROXY=%s ALL_PROXY=%s" % (proxy, proxy, proxy)
                )
            return {"ok": True, "action": "mount", "proxy": proxy, "detail": detail}
    os.environ.pop("HTTPS_PROXY", None)
    os.environ.pop("HTTP_PROXY", None)
    # 3) 直连兜底
    if _all_ok(targets):
        detail.append("direct connection OK (no proxy)")
        return {"ok": True, "action": "direct", "proxy": None, "detail": detail}
    detail.append("FAIL: all candidate proxies and direct connection failed")
    return {"ok": False, "action": "fail", "proxy": None, "detail": detail}


@mcp.tool()
def mount_proxy(port: int) -> Dict[str, Any]:
    """显式挂载本地代理端口到当前会话环境变量。"""
    proxy = f"http://127.0.0.1:{port}"
    _mount(port)
    return {"ok": True, "proxy": proxy, "env": {
        k: os.environ[k] for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
    }}


if __name__ == "__main__":
    mcp.run()
