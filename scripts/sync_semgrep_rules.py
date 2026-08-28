#!/usr/bin/env python3
"""Semgrep 官方规则同步脚本

从 Semgrep Registry 同步官方规则到本地缓存目录，
供 SemgrepAgent 的 SemgrepRuleManager 使用。

用法：
  python scripts/sync_semgrep_rules.py              # 同步全部规则包
  python scripts/sync_semgrep_rules.py --list       # 列出已缓存的规则
  python scripts/sync_semgrep_rules.py --pack xss   # 只同步指定包

缓存位置：~/.hos-ls/semgrep-rules/
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sync-semgrep")

RULE_STORE = os.path.expanduser("~/.hos-ls/semgrep-rules")

# Semgrep Registry 官方规则包
REGISTRY_PACKS = {
    "p/default": "Semgrep 默认规则集（安全 + 质量）",
    "p/security-audit": "安全审计规则集（高精度）",
    "p/command-injection": "命令注入专用规则",
    "p/sql-injection": "SQL 注入专用规则",
    "p/xss": "XSS 专用规则",
    "p/secrets": "密钥/凭证泄露检测规则",
    "p/java": "Java 安全规则集",
    "p/python": "Python 安全规则集",
    "p/javascript": "JavaScript/TypeScript 安全规则集",
}


def get_semgrep_path() -> str:
    """定位 semgrep 可执行文件"""
    cand = shutil.which("semgrep")
    if cand:
        return cand
    # 项目 envs 布局
    here = Path(__file__).resolve().parent.parent
    probes = [
        here / "envs" / "sast-venv" / "Scripts" / "semgrep.exe",
        here / "envs" / "sast-venv" / "bin" / "semgrep",
    ]
    for p in probes:
        if p.exists():
            return str(p)
    logger.error("未找到 semgrep CLI！请安装: pip install semgrep")
    sys.exit(1)


def list_cached():
    """列出已缓存的规则包"""
    store = Path(RULE_STORE)
    if not store.exists():
        logger.info("规则缓存目录不存在: %s", RULE_STORE)
        return
    packs = sorted(store.iterdir()) if store.is_dir() else []
    if not packs:
        logger.info("规则缓存为空")
        return
    logger.info("已缓存的规则包 (%d):", len(packs))
    for p in packs:
        yaml_count = len(list(p.rglob("*.yaml"))) + len(list(p.rglob("*.yml")))
        logger.info("  %-30s %d 条规则", p.name, yaml_count)


def sync_pack(pack_name: str, semgrep_bin: str):
    """同步单个规则包到本地缓存"""
    local_name = pack_name.replace("/", "_")
    local_path = Path(RULE_STORE) / local_name
    local_path.mkdir(parents=True, exist_ok=True)

    logger.info("同步规则包: %s → %s", pack_name, local_path)

    try:
        # 利用 semgrep --config <pack> 运行一次空扫描触发规则下载
        # 规则被缓存到 ~/.semgrep/ 目录
        cmd = [semgrep_bin, "scan", "--config", pack_name, "--json", "-q", "-"]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
            input="print('hello')\n", encoding="utf-8", errors="replace",
        )

        # semgrep 将规则缓存到 ~/.semgrep/
        semgrep_cache = Path.home() / ".semgrep" / local_name
        if semgrep_cache.exists():
            # 清空本地缓存并复制新规则
            for item in local_path.iterdir():
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
            for item in semgrep_cache.iterdir():
                if item.is_dir():
                    shutil.copytree(item, local_path / item.name, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, local_path / item.name)

            yaml_count = len(list(local_path.rglob("*.yaml"))) + len(list(local_path.rglob("*.yml")))
            logger.info("  ✅ 同步完成: %d 条规则", yaml_count)
        else:
            logger.warning("  ⚠️  semgrep 未生成缓存 (首次运行会自动下载)")

    except subprocess.TimeoutExpired:
        logger.error("  ❌ 超时 (120s)")
    except Exception as e:
        logger.error("  ❌ 异常: %s", e)


def main():
    parser = argparse.ArgumentParser(description="Semgrep 官方规则同步工具")
    parser.add_argument("--list", action="store_true", help="列出已缓存的规则")
    parser.add_argument("--pack", type=str, default=None, help="只同步指定规则包 (如 xss)")
    args = parser.parse_args()

    semgrep_bin = get_semgrep_path()

    if args.list:
        list_cached()
        return

    # 确定要同步的包
    if args.pack:
        target = f"p/{args.pack}"
        if target not in REGISTRY_PACKS:
            logger.error("未知规则包: %s，可选: %s", target, ", ".join(REGISTRY_PACKS.keys()))
            sys.exit(1)
        packs_to_sync = {target: REGISTRY_PACKS[target]}
    else:
        packs_to_sync = REGISTRY_PACKS

    logger.info("开始同步 Semgrep 规则包 (%d 个)...", len(packs_to_sync))
    start = time.time()

    for pack_name, desc in packs_to_sync.items():
        logger.info("[%s] %s", pack_name, desc)
        sync_pack(pack_name, semgrep_bin)

    elapsed = time.time() - start
    logger.info("同步完成! 耗时: %.1f 秒", elapsed)
    logger.info("规则缓存位置: %s", RULE_STORE)
    logger.info("使用: semgrep scan --config %s <目标>", RULE_STORE)


if __name__ == "__main__":
    main()
