"""CLI 命令行入口

提供安全工具管理的命令行接口：
    python -m src.sysmgr.cli [discover|install|catalog|update|status|analyze]
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from tqdm import tqdm

from .ai_tool_analyzer import AIToolAnalyzer
from .auto_updater import AutoUpdater
from .discovery import ToolRegistry, build_default_registry, check_tool_installed, discover_tools, print_tool_status
from .mirror import MirrorManager
from .vscode_marketplace import VSCodeMarketplace

logger = logging.getLogger(__name__)

CATALOG_PATH = Path(__file__).parent / "catalog.json"


def _setup_logging(verbose: bool = False) -> None:
    """配置日志"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%H:%M:%S",
    )


def _load_catalog() -> list[dict]:
    """加载工具目录"""
    if CATALOG_PATH.exists():
        with open(CATALOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("tools", [])
    return []


def cmd_discover(args: argparse.Namespace) -> None:
    """检测所有已注册工具状态"""
    logger.info("[CLI] 开始检测工具...")
    registry = build_default_registry()
    registry = discover_tools(registry)

    logger.info(print_tool_status(registry))

    logger.info(
        "[CLI] 检测结果: %d 已安装, %d 缺失",
        len(registry.installed),
        len(registry.missing),
    )


def cmd_install(args: argparse.Namespace) -> None:
    """安装指定工具或全部"""
    tools = _load_catalog()
    proxy_url = args.proxy if hasattr(args, "proxy") else None

    if args.tool_name:
        target_tools = [t for t in tools if t.get("name") == args.tool_name]
        if not target_tools:
            logger.error("[CLI] 未找到工具: %s", args.tool_name)
            sys.exit(1)
    else:
        target_tools = tools
        logger.info("[CLI] 将安装全部 %d 个工具", len(target_tools))

    success_count = 0
    fail_count = 0

    for tool in tqdm(target_tools, desc="安装工具", unit="tool"):
        tool_name = tool.get("name", "")
        install_cmd = tool.get("install_cmd", {})

        if isinstance(install_cmd, dict):
            cmd = install_cmd.get("pip", install_cmd.get("go", install_cmd.get("apt", "")))
        else:
            cmd = install_cmd

        if not cmd:
            logger.warning("[CLI] %s 无安装命令，跳过", tool_name)
            fail_count += 1
            continue

        logger.info("[CLI] 安装 %s: %s", tool_name, cmd)

        import subprocess

        try:
            env = None
            if proxy_url:
                env = __import__("os").environ.copy()
                env["HTTP_PROXY"] = proxy_url
                env["HTTPS_PROXY"] = proxy_url

            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,
                env=env,
            )

            if result.returncode == 0:
                logger.info("[CLI] ✓ %s 安装成功", tool_name)
                success_count += 1
            else:
                logger.error("[CLI] ✗ %s 安装失败: %s", tool_name, result.stderr)
                fail_count += 1

        except subprocess.TimeoutExpired:
            logger.error("[CLI] ✗ %s 安装超时", tool_name)
            fail_count += 1
        except Exception as e:
            logger.error("[CLI] ✗ %s 安装异常: %s", tool_name, e)
            fail_count += 1

    logger.info(
        "[CLI] 安装完成: %d 成功, %d 失败",
        success_count,
        fail_count,
    )


def cmd_catalog(args: argparse.Namespace) -> None:
    """显示工具目录"""
    tools = _load_catalog()

    if not tools:
        logger.warning("[CLI] 工具目录为空")
        return

    tags_filter = args.tags if hasattr(args, "tags") and args.tags else None

    if tags_filter:
        tools = [
            t for t in tools
            if any(tag in t.get("tags", []) for tag in tags_filter)
        ]

    logger.info("=" * 80)
    logger.info("安全工具目录 (%d 个工具)", len(tools))
    logger.info("=" * 80)

    categories = {}
    for tool in tools:
        cat = tool.get("category", "unknown")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(tool)

    for category, cat_tools in sorted(categories.items()):
        logger.info("")
        logger.info("--- %s (%d) ---", category.upper(), len(cat_tools))
        for tool in cat_tools:
            name = tool.get("name", "")
            desc = tool.get("description", "")
            tags = ", ".join(tool.get("tags", []))
            installed, version = check_tool_installed(name)
            status = "✓" if installed else "✗"
            version_str = f" ({version})" if installed and version else ""
            logger.info("  [%s] %-15s %s %s", status, name, desc, version_str)
            if tags:
                logger.info("         标签: %s", tags)

    logger.info("")
    logger.info("-" * 80)
    logger.info("总计: %d 个工具", len(tools))


def cmd_update(args: argparse.Namespace) -> None:
    """更新工具库"""
    proxy_url = args.proxy if hasattr(args, "proxy") else None
    github_token = args.github_token if hasattr(args, "github_token") else None

    logger.info("[CLI] 开始更新工具库...")

    updater = AutoUpdater(
        proxy_url=proxy_url,
        github_token=github_token,
    )

    results = updater.run_full_update()

    logger.info("=" * 60)
    logger.info("[CLI] 更新结果")
    logger.info("=" * 60)
    logger.info("[CLI] 工具更新: %d", len(results.get("updates", [])))
    logger.info("[CLI] 新工具添加: %d", len(results.get("new_tools", [])))

    if results.get("errors"):
        logger.warning("[CLI] 错误: %d", len(results["errors"]))
        for err in results["errors"]:
            logger.warning("  - %s", err)


def cmd_status(args: argparse.Namespace) -> None:
    """显示状态报告"""
    logger.info("[CLI] 生成状态报告...")

    registry = build_default_registry()
    registry = discover_tools(registry)

    logger.info(print_tool_status(registry))

    tools = _load_catalog()
    if tools:
        installed_count = 0
        for tool in tools:
            installed, _ = check_tool_installed(tool.get("name", ""))
            if installed:
                installed_count += 1

        logger.info("")
        logger.info("--- 工具目录状态 ---")
        logger.info("目录工具总数: %d", len(tools))
        logger.info("目录工具已安装: %d", installed_count)
        logger.info("目录工具缺失: %d", len(tools) - installed_count)

    if CATALOG_PATH.exists():
        import os
        stat = os.stat(CATALOG_PATH)
        import datetime
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
        logger.info("目录最后更新: %s", mtime.isoformat())


def cmd_analyze(args: argparse.Namespace) -> None:
    """AI 分析工具"""
    tool_name = args.tool_name if hasattr(args, "tool_name") else None

    analyzer = AIToolAnalyzer()

    if tool_name:
        analysis = analyzer.analyze_tool(tool_name)
        if analysis:
            logger.info("=" * 60)
            logger.info("[CLI] 工具分析: %s", analysis.tool_name)
            logger.info("=" * 60)
            logger.info("描述: %s", analysis.description)
            logger.info("分类: %s", analysis.category)
            logger.info("AI 能力: %s", analysis.ai_capability)
            logger.info("输入格式: %s", analysis.ai_input_format)
            logger.info("输出格式: %s", analysis.ai_output_format)
            logger.info("标签: %s", ", ".join(analysis.tags))
            logger.info("")
            logger.info("输入模板:\n%s", analysis.input_template)
            logger.info("")

            config = analyzer.generate_integration_config(tool_name)
            if config:
                logger.info("验证规则:")
                for rule in config.validation_rules:
                    logger.info("  - %s", rule)
        else:
            logger.error("[CLI] 未找到工具: %s", tool_name)
            sys.exit(1)
    else:
        analyses = analyzer.analyze_all_tools()
        capability_map = analyzer.get_capability_map()

        logger.info("=" * 60)
        logger.info("[CLI] AI 工具分析完成")
        logger.info("=" * 60)
        logger.info("分析工具数: %d", len(analyses))
        logger.info("能力类别数: %d", len(capability_map))
        logger.info("")

        for capability, tool_list in sorted(capability_map.items()):
            logger.info("[%s] %s", capability, ", ".join(tool_list))


def cmd_vscode(args: argparse.Namespace) -> None:
    """搜索 VSCode 安全扩展"""
    proxy_url = args.proxy if hasattr(args, "proxy") else None

    marketplace = VSCodeMarketplace(proxy_url=proxy_url)
    extensions = marketplace.search_security_extensions()

    if extensions:
        logger.info("=" * 80)
        logger.info("VSCode 安全扩展 (%d 个)", len(extensions))
        logger.info("=" * 80)

        for ext in extensions:
            logger.info("")
            logger.info("  %s (by %s)", ext.display_name, ext.publisher)
            logger.info("    %s", ext.description)
            logger.info("    版本: %s | 下载: %d | 评分: %.1f", ext.version, ext.download_count, ext.rating)
            logger.info("    安装: code --install-extension %s.%s", ext.publisher, ext.name)
    else:
        logger.info("[CLI] 未找到安全扩展")


def main(argv: Optional[list[str]] = None) -> None:
    """CLI 入口"""
    parser = argparse.ArgumentParser(
        prog="python -m src.sysmgr.cli",
        description="安全工具管理 CLI",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="启用详细日志",
    )
    parser.add_argument(
        "--proxy",
        help="HTTP 代理 URL",
    )

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    subparsers.add_parser("discover", help="检测所有已注册工具状态")

    install_parser = subparsers.add_parser("install", help="安装指定工具或全部")
    install_parser.add_argument(
        "tool_name",
        nargs="?",
        help="要安装的工具名称（不指定则安装全部）",
    )

    catalog_parser = subparsers.add_parser("catalog", help="显示工具目录")
    catalog_parser.add_argument(
        "--tags",
        nargs="+",
        help="按标签过滤",
    )

    update_parser = subparsers.add_parser("update", help="更新工具库")
    update_parser.add_argument(
        "--github-token",
        help="GitHub API Token",
    )

    subparsers.add_parser("status", help="显示状态报告")

    analyze_parser = subparsers.add_parser("analyze", help="AI 分析工具")
    analyze_parser.add_argument(
        "tool_name",
        nargs="?",
        help="要分析的工具名称（不指定则分析全部）",
    )

    subparsers.add_parser("vscode", help="搜索 VSCode 安全扩展")

    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    command_map = {
        "discover": cmd_discover,
        "install": cmd_install,
        "catalog": cmd_catalog,
        "update": cmd_update,
        "status": cmd_status,
        "analyze": cmd_analyze,
        "vscode": cmd_vscode,
    }

    handler = command_map.get(args.command)
    if handler:
        handler(args)
    else:
        logger.error("[CLI] 未知命令: %s", args.command)
        sys.exit(1)


if __name__ == "__main__":
    main()
