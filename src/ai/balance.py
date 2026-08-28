"""API 余额自动获取模块（API Balance Fetch）

在扫描前自动查询各 AI provider 的账户余额，余额过低时给出告警，
避免扫描中途因 Insufficient Balance (HTTP 402) 中断。

支持的 provider：
    - deepseek : GET {base_url}/user/balance（官方接口，2026-08 实测可用）
    - anthropic: GET {base_url}/v1/organizations/{org}/credits（需 org id，尽力而为）
    - openai / aliyun / local : 无公开余额接口，返回 unavailable（不报错）

Author: HOS-LS Team
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from src.core.config import Config, get_config
from src.utils.logger import get_logger

logger = get_logger("balance")

# 余额告警阈值（默认 5 CNY 或 0.7 USD 以下告警，可用环境变量覆盖）
DEFAULT_MIN_BALANCE_CNY: float = 5.0
DEFAULT_MIN_BALANCE_USD: float = 0.7

_BALANCE_CACHE_TTL: float = 300.0  # 5 分钟内不重复请求
_balance_cache: Dict[str, Dict[str, Any]] = {}
_balance_cache_ts: Dict[str, float] = {}


@dataclass
class BalanceInfo:
    """账户余额信息。"""

    provider: str
    available: bool = False          # 查询成功且接口可用
    is_active: bool = False          # 账户可用（is_available）
    currency: str = ""
    total_balance: float = 0.0
    granted_balance: float = 0.0
    topped_up_balance: float = 0.0
    raw: Optional[Dict[str, Any]] = None
    message: str = ""

    @property
    def low_balance(self) -> bool:
        """余额是否低于告警阈值。"""
        if not self.available or not self.is_active:
            return False
        threshold = float(os.getenv("HOS_LS_MIN_BALANCE_CNY", str(DEFAULT_MIN_BALANCE_CNY)))
        return self.total_balance < threshold

    @property
    def display_text(self) -> str:
        if not self.available:
            return f"[dim]{self.provider}: {self.message or '余额接口不可用（跳过检查）'}[/dim]"
        currency = self.currency or "CNY"
        status = "可用" if self.is_active else "不可用"
        flag = "[bold red]⚠ 余额不足[/bold red]" if self.low_balance else "[green]✓[/green]"
        return (
            f"{flag} {self.provider} 余额: {self.total_balance:.2f} {currency} "
            f"(账户{status}, 到账 {self.topped_up_balance:.2f} / 赠送 {self.granted_balance:.2f})"
        )


def _api_key_for(config: Config) -> Optional[str]:
    """按顺序取 API key：配置 → HOS_LS_AI_API_KEY → DEEPSEEK_API_KEY。"""
    key = config.ai.api_key
    if not key:
        key = os.getenv("HOS_LS_AI_API_KEY") or os.getenv("DEEPSEEK_API_KEY")
    return key


def _base_url_for(config: Config, provider: str) -> str:
    if config.ai.base_url:
        return config.ai.base_url.rstrip("/")
    return {
        "deepseek": "https://api.deepseek.com",
        "anthropic": "https://api.anthropic.com",
        "openai": "https://api.openai.com",
    }.get(provider, "https://api.deepseek.com")


async def fetch_balance_async(
    provider: str,
    api_key: str,
    base_url: Optional[str] = None,
    org_id: Optional[str] = None,
) -> BalanceInfo:
    """异步查询 provider 账户余额。"""
    import aiohttp

    base = (base_url or "").rstrip("/")
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}

    try:
        if provider == "deepseek":
            url = f"{base or 'https://api.deepseek.com'}/user/balance"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status != 200:
                        return BalanceInfo(provider, available=False, message=f"HTTP {resp.status}")
                    data = await resp.json()
            infos = data.get("balance_infos") or []
            info = infos[0] if infos else {}
            return BalanceInfo(
                provider=provider,
                available=True,
                is_active=bool(data.get("is_available", True)),
                currency=info.get("currency", "CNY"),
                total_balance=float(info.get("total_balance") or 0.0),
                granted_balance=float(info.get("granted_balance") or 0.0),
                topped_up_balance=float(info.get("topped_up_balance") or 0.0),
                raw=data,
            )
        elif provider == "anthropic":
            # 需要组织 ID；未提供时返回不可用但不报错
            org = org_id or os.getenv("ANTHROPIC_ORG_ID")
            if not org:
                return BalanceInfo(provider, available=False, message="未配置 ANTHROPIC_ORG_ID")
            url = f"{base or 'https://api.anthropic.com'}/v1/organizations/{org}/credits"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status != 200:
                        return BalanceInfo(provider, available=False, message=f"HTTP {resp.status}")
                    data = await resp.json()
            return BalanceInfo(
                provider=provider,
                available=True,
                is_active=True,
                currency="USD",
                total_balance=float(data.get("total_credits") or data.get("available_credits") or 0.0),
                raw=data,
            )
        else:
            return BalanceInfo(provider, available=False, message="该 provider 无公开余额接口")
    except Exception as exc:  # pragma: no cover - 网络/解析异常
        logger.debug("余额查询失败(%s): %s", provider, exc)
        return BalanceInfo(provider, available=False, message=f"查询失败: {str(exc)[:60]}")


def _is_loop_running() -> bool:
    """当前是否已处于运行中的 asyncio 事件循环（scanner 异步上下文）。"""
    try:
        loop = asyncio.get_running_loop()
        return loop is not None and loop.is_running()
    except RuntimeError:
        return False


def fetch_balance_sync(config: Optional[Config] = None, provider: Optional[str] = None) -> BalanceInfo:
    """同步查询余额（CLI/扫描前置使用），带 5 分钟缓存。

    若当前已处于运行中的 asyncio 事件循环（如 scanner.scan 异步上下文），
    则在独立线程中运行事件循环执行查询，避免 asyncio.run() 嵌套报错。
    """
    cfg = config or get_config()
    provider = provider or cfg.ai.get_provider("pure_ai") or cfg.ai.provider or "deepseek"
    api_key = _api_key_for(cfg)
    if not api_key:
        return BalanceInfo(provider, available=False, message="未配置 API key")

    cache_key = f"{provider}:{api_key[:8]}"
    now = time.time()
    if cache_key in _balance_cache and now - _balance_cache_ts.get(cache_key, 0) < _BALANCE_CACHE_TTL:
        return _balance_cache[cache_key]

    def _query() -> BalanceInfo:
        return asyncio.run(fetch_balance_async(provider, api_key, _base_url_for(cfg, provider)))

    if _is_loop_running():
        import threading

        result: Dict[str, BalanceInfo] = {}
        worker = threading.Thread(target=lambda: result.setdefault("info", _query()), daemon=True)
        worker.start()
        worker.join(timeout=30)
        info = result.get("info") or BalanceInfo(provider, available=False, message="查询超时")
    else:
        info = _query()

    _balance_cache[cache_key] = info
    _balance_cache_ts[cache_key] = now
    return info


def check_balance(
    config: Optional[Config] = None,
    provider: Optional[str] = None,
    quiet: bool = False,
) -> BalanceInfo:
    """扫描前置余额检查：查询余额并返回结果，供 CLI 决定是否告警。

    Returns:
        BalanceInfo（查询失败/不可用时 available=False，不抛异常）
    """
    info = fetch_balance_sync(config, provider)
    if not quiet:
        from rich.console import Console

        Console(emoji=False).print(info.display_text)
    return info
