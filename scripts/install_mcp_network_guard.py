"""全局安装 network-guard MCP server 到用户级 reasonix 配置。

做两件事：
1. 拷贝 scripts/mcp_network_guard_server.py -> %APPDATA%/reasonix/mcp-network-guard.py
2. 在 %APPDATA%/reasonix/config.toml 追加 [[plugins]] network-guard
   （幂等：已注册则跳过）。

用法：
    python scripts/install_mcp_network_guard.py           # 安装
    python scripts/install_mcp_network_guard.py --check   # 仅检查是否已安装
"""
from __future__ import annotations

import argparse
import shutil
import sys
from os import environ
from pathlib import Path

appdata = environ.get("APPDATA", "")
if not appdata:
    print("ERROR: APPDATA environment variable not set", file=sys.stderr)
    sys.exit(1)
APPDATA = Path(appdata)

SRC = Path(__file__).resolve().parent / "mcp_network_guard_server.py"
DST = APPDATA / "reasonix" / "mcp-network-guard.py"
CONFIG = APPDATA / "reasonix" / "config.toml"
MARKER = "network-guard"

PLUGIN_BLOCK = """
[[plugins]]
name    = "network-guard"
command = "python"
args    = ["{dst}"]
"""


def installed() -> bool:
    return CONFIG.exists() and MARKER in CONFIG.read_text(encoding="utf-8")


def install() -> int:
    if not SRC.exists():
        print(f"ERROR: source server missing: {SRC}", file=sys.stderr)
        return 1
    DST.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SRC, DST)
    print(f"copied server -> {DST}")
    if installed():
        print("config.toml already registers network-guard; skip")
        return 0
    text = CONFIG.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        text += "\n"
    text += PLUGIN_BLOCK.format(dst=str(DST).replace("\\", "/"))
    CONFIG.write_text(text, encoding="utf-8")
    print(f"registered [[plugins]] {MARKER} -> {CONFIG}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="安装 network-guard 全局 MCP server")
    parser.add_argument("--check", action="store_true", help="仅检查是否已安装")
    args = parser.parse_args()
    if args.check:
        print("installed" if installed() else "not installed")
        return 0
    return install()


if __name__ == "__main__":
    sys.exit(main())
