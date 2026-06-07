"""侦察命令组

提供快速侦察与信息收集 CLI 入口。
"""

import asyncio
import json
import os
import shutil
import sys
from datetime import datetime
from typing import Optional

# Fix Windows console encoding
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table

console = Console(emoji=False, force_terminal=True, legacy_windows=False)

# ---------------------------------------------------------------------------
# 已知侦察工具
# ---------------------------------------------------------------------------

RECON_TOOLS = {
    "subfinder": {"desc": "子域名枚举", "cmd": "subfinder"},
    "nmap": {"desc": "端口扫描", "cmd": "nmap"},
    "httpx": {"desc": "HTTP 存活检测", "cmd": "httpx"},
    "nuclei": {"desc": "模板化漏洞扫描", "cmd": "nuclei"},
    "ffuf": {"desc": "目录模糊测试", "cmd": "ffuf"},
    "whatweb": {"desc": "技术栈识别", "cmd": "whatweb"},
    "amass": {"desc": "主动资产发现", "cmd": "amass"},
}

# ---------------------------------------------------------------------------
# 工具可用性检查
# ---------------------------------------------------------------------------

def _check_tool(cmd: str) -> bool:
    return shutil.which(cmd) is not None

# ---------------------------------------------------------------------------
# Click 命令
# ---------------------------------------------------------------------------

@click.command("recon")
@click.argument("target")
@click.option("--subdomain", "do_subdomain", is_flag=True, help="子域名枚举")
@click.option("--port-scan", "do_port_scan", is_flag=True, help="端口扫描")
@click.option("--tech-detect", "do_tech_detect", is_flag=True, help="技术栈识别")
@click.option("--all", "do_all", is_flag=True, help="全部侦察")
@click.option("--output", "-o", default=None, help="输出路径 (JSON)")
@click.option("--tools", default=None, help="指定工具 (逗号分隔)")
@click.pass_context
def recon(
    ctx: click.Context,
    target: str,
    do_subdomain: bool,
    do_port_scan: bool,
    do_tech_detect: bool,
    do_all: bool,
    output: Optional[str],
    tools: Optional[str],
) -> None:
    """快速侦察与信息收集

    TARGET: 目标地址（域名或 IP）

    示例:
        hos-ls recon example.com --all
        hos-ls recon example.com --subdomain --port-scan
        hos-ls recon example.com --tools subfinder,nmap
    """
    config = ctx.obj.get("config")
    if config is None:
        from src.core.config import Config
        config = Config()

    # ── 任务解析 ──
    if do_all:
        do_subdomain = True
        do_port_scan = True
        do_tech_detect = True

    # 如果没有指定任何任务，默认全部
    if not (do_subdomain or do_port_scan or do_tech_detect):
        do_subdomain = True
        do_port_scan = True
        do_tech_detect = True

    # ── 工具列表 ──
    tool_list: list[str] = []
    if tools:
        tool_list = [t.strip().lower() for t in tools.split(",") if t.strip()]

    # ── 工具可用性 ──
    if tool_list:
        for t in tool_list:
            info = RECON_TOOLS.get(t)
            if info and not _check_tool(info["cmd"]):
                console.print(f"[yellow][WARN] 工具未安装: {t} ({info['cmd']})[/yellow]")

    # ── Banner ──
    tasks_display = []
    if do_subdomain:
        tasks_display.append("子域名枚举")
    if do_port_scan:
        tasks_display.append("端口扫描")
    if do_tech_detect:
        tasks_display.append("技术栈识别")

    if not config.quiet:
        console.print(Panel(
            f"[bold cyan]侦察任务启动[/bold cyan]\n"
            f"  目标: {target}\n"
            f"  任务: {', '.join(tasks_display)}\n"
            f"  工具: {', '.join(tool_list) if tool_list else '[dim]自动[/dim]'}",
            title="[bold]HOS-LS Recon[/bold]",
            border_style="cyan",
        ))

    # ── 执行 ──
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            _run_recon(
                config=config,
                target=target,
                do_subdomain=do_subdomain,
                do_port_scan=do_port_scan,
                do_tech_detect=do_tech_detect,
                tool_list=tool_list,
            )
        )
    except Exception as e:
        console.print(f"[bold red]侦察执行失败: {e}[/bold red]")
        sys.exit(2)

    # ── 展示结果 ──
    _display_recon_results(result, config)

    # ── 保存 ──
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2, default=str)
        if not config.quiet:
            console.print(f"[bold green][OK] 结果已保存: {output}[/bold green]")


# ---------------------------------------------------------------------------
# 异步执行核心
# ---------------------------------------------------------------------------

async def _run_recon(
    config,
    target: str,
    do_subdomain: bool,
    do_port_scan: bool,
    do_tech_detect: bool,
    tool_list: list[str],
) -> dict:
    """执行侦察任务的异步核心"""
    from src.pentest.agents.recon_agent import ReconAgent
    from src.pentest.agents.base import MemoryRef

    # 创建 ReconAgent
    agent = ReconAgent(config=config)
    memory = MemoryRef()
    agent.set_memory(memory)
    memory.set("recon_target", target)

    result: dict = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "subdomains": [],
        "ports": [],
        "technologies": [],
        "attack_surface": None,
    }

    total_steps = sum([do_subdomain, do_port_scan, do_tech_detect])

    if not getattr(config, "quiet", False):
        with Progress(
            TextColumn("[bold cyan][ {task.description} ][/bold cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("开始侦察...", total=total_steps)

            if do_subdomain:
                progress.update(task, description="[bold cyan]子域名枚举中...[/bold cyan]")
                subs = await _do_subdomain_recon(agent, target, tool_list)
                result["subdomains"] = subs
                progress.advance(task)

            if do_port_scan:
                progress.update(task, description="[bold cyan]端口扫描中...[/bold cyan]")
                ports = await _do_port_recon(agent, target, tool_list)
                result["ports"] = ports
                progress.advance(task)

            if do_tech_detect:
                progress.update(task, description="[bold cyan]技术栈检测中...[/bold cyan]")
                techs = await _do_tech_recon(agent, target, tool_list)
                result["technologies"] = techs
                progress.advance(task)

            progress.update(task, description="[bold green]侦察完成![/bold green]")
    else:
        # 静默模式
        if do_subdomain:
            result["subdomains"] = await _do_subdomain_recon(agent, target, tool_list)
        if do_port_scan:
            result["ports"] = await _do_port_recon(agent, target, tool_list)
        if do_tech_detect:
            result["technologies"] = await _do_tech_recon(agent, target, tool_list)

    # 攻击面分析
    try:
        agent._findings = (
            [{"type": "subdomain", **s} for s in result["subdomains"]]
            + [{"type": "port_scan_config", **p} for p in result["ports"]]
            + [{"type": "tech_detection", **t} for t in result["technologies"]]
        )
        analysis = await agent.analyze_attack_surface(target)
        result["attack_surface"] = analysis
    except Exception:
        pass

    return result


async def _do_subdomain_recon(agent, target: str, tool_list: list[str]) -> list[dict]:
    """子域名枚举"""
    # 尝试使用 subfinder 工具
    if not tool_list or "subfinder" in tool_list:
        subfinder_result = await _run_subfinder(target)
        if subfinder_result:
            return subfinder_result

    # 回退到 ReconAgent
    try:
        findings = await agent.enumerate_subdomains(target)
        return [
            {
                "subdomain": f.get("subdomain", ""),
                "full_domain": f.get("full_domain", ""),
                "likelihood": f.get("likelihood", "unknown"),
                "source": "ai_prediction",
            }
            for f in findings
            if f.get("type") in ("subdomain", "subdomain_prediction")
        ]
    except Exception:
        return []


async def _run_subfinder(target: str) -> list[dict]:
    """使用 subfinder 进行子域名枚举"""
    if not shutil.which("subfinder"):
        return []

    try:
        import subprocess
        proc = subprocess.run(
            ["subfinder", "-d", target, "-silent", "-json"],
            capture_output=True, text=True, timeout=120,
        )
        findings = []
        for line in proc.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "subdomain": data.get("host", data.get("subdomain", "")),
                    "full_domain": data.get("host", data.get("subdomain", "")),
                    "source": data.get("source", "subfinder"),
                    "likelihood": "high",
                })
            except json.JSONDecodeError:
                pass
        return findings
    except Exception:
        return []


async def _do_port_recon(agent, target: str, tool_list: list[str]) -> list[dict]:
    """端口扫描"""
    # 尝试使用 nmap
    if not tool_list or "nmap" in tool_list:
        nmap_result = await _run_nmap(target)
        if nmap_result:
            return nmap_result

    # 回退到 ReconAgent
    try:
        findings = await agent.scan_ports(target)
        return [
            {
                "type": f.get("type", "port_scan_config"),
                "target": f.get("target", target),
                "common_ports": f.get("common_ports_to_check", []),
                "status": f.get("status", "pending"),
                "source": "ai_recon",
            }
            for f in findings
        ]
    except Exception:
        return []


async def _run_nmap(target: str) -> list[dict]:
    """使用 nmap 进行端口扫描"""
    if not shutil.which("nmap"):
        return []

    try:
        import subprocess
        proc = subprocess.run(
            ["nmap", "-sV", "--open", "-oX", "-", "--top-ports", "100", target],
            capture_output=True, text=True, timeout=180,
        )
        # 简化解析：从 XML 中提取 port 信息
        findings = []
        if proc.returncode == 0:
            # 简单解析
            import re
            for match in re.finditer(
                r'<port protocol="(\w+)" portid="(\d+)">.*?<state state="open".*?<service name="([^"]*)"',
                proc.stdout, re.DOTALL
            ):
                protocol, portid, service = match.groups()
                findings.append({
                    "port": int(portid),
                    "protocol": protocol,
                    "service": service,
                    "state": "open",
                    "source": "nmap",
                })
        return findings
    except Exception:
        return []


async def _do_tech_recon(agent, target: str, tool_list: list[str]) -> list[dict]:
    """技术栈检测"""
    # 尝试使用 whatweb
    if not tool_list or "whatweb" in tool_list:
        whatweb_result = await _run_whatweb(target)
        if whatweb_result:
            return whatweb_result

    # 回退到 ReconAgent
    try:
        findings = await agent.detect_tech(target)
        return [
            {
                "type": f.get("type", "tech_detection"),
                "target": f.get("target", target),
                "categories": f.get("detection_categories", []),
                "status": f.get("status", "pending"),
                "source": "ai_recon",
            }
            for f in findings
        ]
    except Exception:
        return []


async def _run_whatweb(target: str) -> list[dict]:
    """使用 whatweb 进行技术栈检测"""
    if not shutil.which("whatweb"):
        return []

    try:
        import subprocess
        proc = subprocess.run(
            ["whatweb", "--color=never", target],
            capture_output=True, text=True, timeout=60,
        )
        findings = []
        if proc.returncode == 0:
            # 解析 whatweb 输出: target [200] Title, Technologies...
            for line in proc.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split("[")
                if len(parts) >= 2:
                    tech_str = parts[1].split("]")[1] if "]" in parts[1] else ""
                    findings.append({
                        "target": parts[0].strip(),
                        "technologies": [t.strip() for t in tech_str.split(",") if t.strip()],
                        "source": "whatweb",
                    })
        return findings
    except Exception:
        return []


# ---------------------------------------------------------------------------
# 结果展示
# ---------------------------------------------------------------------------

def _display_recon_results(result: dict, config) -> None:
    """用 rich 展示侦察结果"""
    if config.quiet:
        return

    target = result.get("target", "unknown")
    subdomains = result.get("subdomains", [])
    ports = result.get("ports", [])
    techs = result.get("technologies", [])

    console.print(Panel(
        f"[bold]侦察完成: {target}[/bold]\n"
        f"  子域名: [cyan]{len(subdomains)}[/cyan]\n"
        f"  开放端口: [green]{len(ports)}[/green]\n"
        f"  技术栈: [yellow]{len(techs)}[/yellow]",
        title="[bold]HOS-LS Recon Results[/bold]",
        border_style="cyan",
    ))

    # 子域名表
    if subdomains:
        table = Table(title="[bold]子域名发现[/bold]")
        table.add_column("#", style="dim", width=4)
        table.add_column("子域名", style="cyan")
        table.add_column("来源", style="dim", width=15)
        for i, s in enumerate(subdomains[:30], 1):
            table.add_row(
                str(i),
                s.get("full_domain", s.get("subdomain", "unknown")),
                s.get("source", "unknown"),
            )
        console.print(table)
        if len(subdomains) > 30:
            console.print(f"[dim]... 还有 {len(subdomains) - 30} 条未显示[/dim]")

    # 端口表
    if ports:
        table = Table(title="[bold]端口扫描结果[/bold]")
        table.add_column("#", style="dim", width=4)
        table.add_column("端口", style="green", width=8)
        table.add_column("协议", width=8)
        table.add_column("服务", style="yellow")
        table.add_column("来源", style="dim", width=12)
        for i, p in enumerate(ports[:30], 1):
            table.add_row(
                str(i),
                str(p.get("port", p.get("common_ports", []))),
                p.get("protocol", "tcp"),
                str(p.get("service", p.get("status", ""))),
                p.get("source", "unknown"),
            )
        console.print(table)

    # 技术栈表
    if techs:
        table = Table(title="[bold]技术栈检测[/bold]")
        table.add_column("#", style="dim", width=4)
        table.add_column("目标", style="cyan", width=30)
        table.add_column("类别/技术", style="yellow")
        table.add_column("来源", style="dim", width=12)
        for i, t in enumerate(techs[:20], 1):
            cats = t.get("categories", t.get("technologies", []))
            if isinstance(cats, list):
                cats_str = ", ".join(str(c) for c in cats)
            else:
                cats_str = str(cats)
            table.add_row(
                str(i),
                t.get("target", "")[:30],
                cats_str[:50],
                t.get("source", "unknown"),
            )
        console.print(table)

    # 攻击面分析
    attack_surface = result.get("attack_surface")
    if attack_surface:
        console.print(Panel(
            f"[bold]攻击面分析[/bold]\n\n{attack_surface}",
            title="[bold yellow]AI Analysis[/bold yellow]",
            border_style="yellow",
        ))
