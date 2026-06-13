"""配置相关命令"""

from typing import Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pydantic import BaseModel

console = Console(emoji=False, force_terminal=True)


def mask_api_key(key: str) -> str:
    """掩码API Key"""
    if not key:
        return "(未设置)"
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]


def _config_to_dict(cfg) -> dict:
    """将配置对象转换为字典"""
    result = {
        "version": cfg.version,
        "debug": cfg.debug,
        "verbose": cfg.verbose,
        "quiet": cfg.quiet,
        "test_mode": cfg.test_mode,
        "pure_ai": cfg.pure_ai,
        "scan_mode": cfg.scan_mode,
        "filter_hallucinations": cfg.filter_hallucinations,
        "language": cfg.language,
        "resume": cfg.resume,
        "truncate_output": cfg.truncate_output,
        "max_duration": cfg.max_duration,
        "max_files": cfg.max_files,
    }

    def sanitize_value(v):
        if isinstance(v, BaseModel):
            return v.model_dump()
        elif isinstance(v, dict):
            return {k: sanitize_value(val) for k, val in v.items()}
        elif isinstance(v, list):
            return [sanitize_value(item) for item in v]
        elif isinstance(v, bool):
            return v
        elif isinstance(v, (str, int, float, type(None))):
            return v
        else:
            return str(v)

    result["ai"] = sanitize_value(cfg.ai)
    result["scan"] = sanitize_value(cfg.scan)
    result["rules"] = sanitize_value(cfg.rules)
    result["report"] = sanitize_value(cfg.report)
    result["tools"] = sanitize_value(cfg.tools)
    result["priority"] = sanitize_value(cfg.priority)
    result["validation"] = sanitize_value(cfg.validation)
    result["sandbox"] = sanitize_value(cfg.sandbox)

    return result


def _print_config_table(title: str, items: list) -> None:
    """打印配置表格"""
    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("配置项", style="cyan", width=30)
    table.add_column("当前值", style="green", width=35)
    table.add_column("默认值", style="dim", width=15)
    table.add_column("描述", style="white", width=25)

    for item in items:
        table.add_row(*[str(x) if x else "" for x in item])

    console.print(table)
    console.print()


def _apply_imported_config(cfg, imported: dict) -> None:
    """将导入的配置应用到Config对象"""
    if not imported:
        return

    if "debug" in imported:
        cfg.debug = bool(imported["debug"])
    if "verbose" in imported:
        cfg.verbose = bool(imported["verbose"])
    if "quiet" in imported:
        cfg.quiet = bool(imported["quiet"])
    if "test_mode" in imported:
        cfg.test_mode = bool(imported["test_mode"])
    if "filter_hallucinations" in imported:
        cfg.filter_hallucinations = bool(imported["filter_hallucinations"])
    if "language" in imported:
        cfg.language = str(imported["language"])
    if "pure_ai" in imported:
        cfg.pure_ai = bool(imported["pure_ai"])
    if "scan_mode" in imported:
        cfg.scan_mode = str(imported["scan_mode"])

    if "ai" in imported and isinstance(imported["ai"], dict):
        ai_config = imported["ai"]
        if "provider" in ai_config:
            cfg.ai.provider = str(ai_config["provider"])
        if "model" in ai_config:
            cfg.ai.model = str(ai_config["model"])
        if "api_key" in ai_config:
            cfg.ai.api_key = str(ai_config["api_key"]) if ai_config["api_key"] else ""
        if "max_tokens" in ai_config:
            cfg.ai.max_tokens = int(ai_config["max_tokens"])
        if "temperature" in ai_config:
            cfg.ai.temperature = float(ai_config["temperature"])
        if "timeout" in ai_config:
            cfg.ai.timeout = int(ai_config["timeout"])

    if "scan" in imported and isinstance(imported["scan"], dict):
        scan_config = imported["scan"]
        if "max_workers" in scan_config:
            cfg.scan.max_workers = int(scan_config["max_workers"])
        if "incremental" in scan_config:
            cfg.scan.incremental = bool(scan_config["incremental"])
        if "cache_enabled" in scan_config:
            cfg.scan.cache_enabled = bool(scan_config["cache_enabled"])

    if "validation" in imported and isinstance(imported["validation"], dict):
        val_config = imported["validation"]
        if "auto_validate_high" in val_config:
            cfg.validation.auto_validate_high = bool(val_config["auto_validate_high"])
        if "auto_validate_medium" in val_config:
            cfg.validation.auto_validate_medium = bool(val_config["auto_validate_medium"])
        if "min_confidence_threshold" in val_config:
            cfg.validation.min_confidence_threshold = float(val_config["min_confidence_threshold"])
        if "line_number_tolerance" in val_config:
            cfg.validation.line_number_tolerance = int(val_config["line_number_tolerance"])

    if "sandbox" in imported and isinstance(imported["sandbox"], dict):
        sandbox_config = imported["sandbox"]
        if "enabled" in sandbox_config:
            cfg.sandbox.enabled = bool(sandbox_config["enabled"])
        if "timeout" in sandbox_config:
            cfg.sandbox.timeout = int(sandbox_config["timeout"])

    console.print("[cyan]已应用的配置项:[/cyan]")
    for key in imported.keys():
        if key not in ("ai", "scan", "validation", "sandbox", "rules", "report", "tools", "priority"):
            console.print(f"  - {key}")


@click.command()
@click.option("--export", "-e", type=click.Choice(["yaml", "json"], case_sensitive=False), default=None, help="导出配置为指定格式")
@click.option("--import", "-i", "--input", "import_file", type=click.Path(exists=True), default=None, help="从文件导入配置")
@click.option("--output", "-o", type=click.Path(), default=None, help="导出文件路径")
@click.pass_context
def config(ctx: click.Context, export: str, import_file: str, output: str) -> None:
    """显示、导入或导出配置"""
    from src.core.config import Config, ConfigManager

    cfg: Config = ctx.obj["config"]

    if import_file:
        if import_file.endswith('.yaml') or import_file.endswith('.yml'):
            import yaml
            with open(import_file, 'r', encoding='utf-8') as f:
                imported_config = yaml.safe_load(f)
        elif import_file.endswith('.json'):
            import json
            with open(import_file, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
        else:
            console.print(f"[red]不支持的文件格式，请使用 .yaml/.yml 或 .json 文件[/red]")
            return

        if imported_config:
            _apply_imported_config(cfg, imported_config)
            console.print(f"[green]配置已从 {import_file} 导入[/green]")

            config_manager = ConfigManager()
            config_manager.save_config(cfg)
            console.print(f"[green]配置已保存[/green]")
        else:
            console.print(f"[red]导入的配置为空[/red]")
        return

    if export:
        if export == "yaml":
            import yaml
            config_dict = _config_to_dict(cfg)
            yaml_content = yaml.dump(config_dict, allow_unicode=True, default_flow_style=False)
            if output:
                with open(output, 'w', encoding='utf-8') as f:
                    f.write(yaml_content)
                console.print(f"[green]配置已导出到: {output}[/green]")
            else:
                console.print(yaml_content)
        elif export == "json":
            import json
            config_dict = _config_to_dict(cfg)
            json_content = json.dumps(config_dict, ensure_ascii=False, indent=2)
            if output:
                with open(output, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                console.print(f"[green]配置已导出到: {output}[/green]")
            else:
                console.print(json_content)
        return

    console.print(Panel("[bold]HOS-LS 完整配置[/bold]", border_style="cyan"))

    table = Table(title="全局配置", show_header=True, header_style="bold cyan")
    table.add_column("配置项", style="cyan", width=30)
    table.add_column("当前值", style="green", width=40)
    table.add_column("默认值", style="dim", width=20)
    table.add_column("描述", style="white", width=30)

    table.add_row("调试模式 (debug)", str(cfg.debug), "False", "启用调试输出")
    table.add_row("详细输出 (verbose)", str(cfg.verbose), "False", "显示详细日志")
    table.add_row("静默模式 (quiet)", str(cfg.quiet), "False", "静默运行")
    table.add_row("测试模式 (test_mode)", str(cfg.test_mode), "False", "测试模式")
    table.add_row("纯AI模式 (pure_ai)", str(cfg.pure_ai), "False", "使用纯AI深度分析")
    table.add_row("扫描模式 (scan_mode)", cfg.scan_mode, "auto", "扫描模式")
    table.add_row("过滤幻觉 (filter_hallucinations)", str(cfg.filter_hallucinations), "True", "过滤AI幻觉发现")
    table.add_row("界面语言 (language)", cfg.language, "zh", "zh=中文, en=英文")
    table.add_row("从断点恢复 (resume)", str(cfg.resume), "False", "从中断处继续扫描")
    table.add_row("截断输出 (truncate_output)", str(cfg.truncate_output), "False", "达到条件后停止")
    table.add_row("最大扫描时长", str(cfg.max_duration), "0", "秒，0表示不限制")
    table.add_row("最大扫描文件数", str(cfg.max_files), "0", "0表示不限制")
    console.print(table)
    console.print()

    _print_config_table("AI 配置", [
        ("提供商 (provider)", cfg.ai.provider, "deepseek", "AI服务提供商"),
        ("模型 (model)", cfg.ai.model, "deepseek-v4-flash", "AI模型"),
        ("API Key", mask_api_key(cfg.ai.api_key), "-", "API密钥"),
        ("最大Token (max_tokens)", str(cfg.ai.max_tokens), "4096", "单次请求最大Token数"),
        ("温度参数 (temperature)", str(cfg.ai.temperature), "0.1", "生成随机性，0-1"),
        ("超时 (timeout)", str(cfg.ai.timeout), "60", "请求超时秒数"),
    ])

    _print_config_table("AI - 阿里云配置", [
        ("启用", str(cfg.ai.aliyun.enabled), "False", "是否启用阿里云API"),
        ("API Key", mask_api_key(cfg.ai.aliyun.api_key), "-", "阿里云API密钥"),
        ("模型", cfg.ai.aliyun.model, "qwen3-coder-next", "阿里云模型"),
    ])

    _pure_ai_mod = cfg.ai.modules.get("pure_ai")
    _print_config_table("AI - 模块配置 (pure_ai)", [
        ("启用", str(_pure_ai_mod.enabled if _pure_ai_mod else True), "True", "纯AI模块启用"),
        ("模型", _pure_ai_mod.model if _pure_ai_mod and _pure_ai_mod.model else "deepseek-v4-flash", "deepseek-v4-flash", "pure_ai专用模型"),
        ("提供商", _pure_ai_mod.provider if _pure_ai_mod and _pure_ai_mod.provider else "deepseek", "deepseek", "pure_ai专用提供商"),
    ])

    _rag_mod = cfg.ai.modules.get("rag")
    _print_config_table("AI - RAG配置", [
        ("启用", str(_rag_mod.enabled if _rag_mod else True), "True", "RAG检索启用"),
        ("嵌入模型", _rag_mod.model if _rag_mod and _rag_mod.model else "N/A", "Qwen/Qwen3-Embedding-0.6B", "嵌入模型"),
        ("重排模型", _rag_mod.provider if _rag_mod and _rag_mod.provider else "N/A", "BAAI/bge-reranker-large", "重排模型"),
    ])

    _print_config_table("扫描配置", [
        ("最大工作线程 (max_workers)", str(cfg.scan.max_workers), "4", "并行扫描线程数"),
        ("增量扫描 (incremental)", str(cfg.scan.incremental), "True", "增量扫描"),
        ("缓存启用 (cache_enabled)", str(cfg.scan.cache_enabled), "True", "启用扫描缓存"),
    ])

    _print_config_table("规则配置", [
        ("规则集 (ruleset)", cfg.rules.ruleset, "default", "使用的规则集"),
        ("启用规则数", str(len(cfg.rules.enabled)), "0", "启用的规则数量"),
        ("禁用规则数", str(len(cfg.rules.disabled)), "0", "禁用的规则数量"),
        ("严重级别阈值", cfg.rules.severity_threshold, "low", "严重级别阈值"),
    ])

    _print_config_table("报告配置", [
        ("格式 (format)", cfg.report.format, "html", "报告格式"),
        ("输出路径 (output)", cfg.report.output or "(未设置)", "", "报告输出路径"),
        ("包含代码片段", str(cfg.report.include_code_snippets), "True", "报告中包含代码片段"),
        ("包含修复建议", str(cfg.report.include_fix_suggestions), "True", "报告中包含修复建议"),
    ])

    _print_config_table("工具配置", [
        ("工具链启用", str(cfg.tools.enabled), "True", "是否启用工具链"),
        ("Semgrep启用", str(cfg.tools.semgrep.enabled), "True", "Semgrep扫描启用"),
        ("Trivy启用", str(cfg.tools.trivy.enabled), "True", "Trivy扫描启用"),
        ("Gitleaks启用", str(cfg.tools.gitleaks.enabled), "True", "Gitleaks扫描启用"),
    ])

    _print_config_table("验证配置", [
        ("启用验证", str(cfg.validation.enabled), "True", "是否启用自动验证"),
        ("自动验证HIGH漏洞", str(cfg.validation.auto_validate_high), "True", "自动验证高置信度漏洞"),
        ("自动验证MEDIUM漏洞", str(cfg.validation.auto_validate_medium), "False", "自动验证中置信度漏洞"),
        ("最小置信度阈值", str(cfg.validation.min_confidence_threshold), "0.7", "置信度阈值"),
        ("POC自动验证HIGH", str(cfg.validation.poc_auto_validate_high), "True", "POC自动验证高危漏洞"),
    ])

    _print_config_table("优先级配置", [
        ("CVSS权重", str(cfg.priority.weights.cvss), "0.40", "CVSS评分权重"),
        ("可利用性权重", str(cfg.priority.weights.exploitability), "0.35", "可利用性权重"),
        ("可达性权重", str(cfg.priority.weights.reachability), "0.25", "可达性权重"),
    ])

    _print_config_table("沙盒配置", [
        ("启用 (enabled)", str(cfg.sandbox.enabled), "False", "沙盒动态验证"),
        ("最大CPU时间 (max_cpu_time)", str(cfg.sandbox.max_cpu_time), "30", "沙盒执行最大CPU秒数"),
        ("最大内存 (max_memory)", str(cfg.sandbox.max_memory), "536870912", "沙盒最大内存字节"),
    ])

    _print_config_table("国际化配置", [
        ("语言 (language)", cfg.language, "zh", "界面语言: zh=中文, en=英文"),
    ])

    console.print("[dim]提示: 使用 --export yaml|json [-o output] 导出配置[/dim]")
    console.print("[dim]提示: 使用 `hosls config test-api` 测试API连接[/dim]")


@click.command()
@click.pass_context
def test_api(ctx: click.Context) -> None:
    """测试AI API连接是否正常"""
    cfg: Config = ctx.obj["config"]

    console.print(Panel("[bold]API 连接测试[/bold]", border_style="cyan"))

    provider = cfg.ai.provider
    model = cfg.ai.model
    api_key = cfg.ai.api_key

    console.print(f"[dim]提供商: {provider}[/dim]")
    console.print(f"[dim]模型: {model}[/dim]")
    console.print(f"[dim]API Key: {mask_api_key(api_key)}[/dim]")
    console.print()

    if not api_key:
        console.print("[bold red]错误: API Key 未设置[/bold red]")
        console.print("[yellow]请运行: hosls config 查看并配置 API Key[/yellow]")
        return

    console.print("[yellow]正在测试 API 连接...[/yellow]")

    try:
        import litellm
        
        # 构建litellm格式的model名称 (provider/model)
        litellm_model = model
        if '/' not in model and provider:
            provider_map = {
                'deepseek': 'deepseek',
                'openai': 'openai',
                'anthropic': 'anthropic',
                'aliyun': 'openai',  # 阿里云兼容OpenAI格式
                'qwen': 'openai',
            }
            litellm_prefix = provider_map.get(provider.lower(), provider)
            litellm_model = f"{litellm_prefix}/{model}"
        
        litellm.api_base = cfg.ai.base_url if hasattr(cfg.ai, 'base_url') and cfg.ai.base_url else None
        
        response = litellm.completion(
            model=litellm_model,
            api_key=api_key,
            base_url=cfg.ai.base_url if hasattr(cfg.ai, 'base_url') and cfg.ai.base_url else None,
            messages=[{"role": "user", "content": "Reply with exactly: HOS-LS API test OK"}],
            max_tokens=20,
            temperature=0.0,
        )
        content = response.choices[0].message.content.strip() if response.choices else ""
        if "OK" in content:
            console.print("[bold green]API 连接测试成功![/bold green]")
            console.print(f"[green]AI 响应: {content}[/green]")
            console.print()
            console.print("[green]Token 消耗:[/green]")
            console.print(f"  输入: {response.usage.prompt_tokens} tokens")
            console.print(f"  输出: {response.usage.completion_tokens} tokens")
            console.print(f"  总计: {response.usage.total_tokens} tokens")
        else:
            console.print("[bold yellow]API 连接成功，但响应异常[/bold yellow]")
            console.print(f"[yellow]AI 响应: {content}[/yellow]")
    except ImportError:
        console.print("[bold red]错误: litellm 未安装[/bold red]")
        console.print("[yellow]请运行: pip install litellm[/yellow]")
    except Exception as e:
        error_msg = str(e)
        if "authentication" in error_msg.lower() or "api_key" in error_msg.lower() or "invalid_api_key" in error_msg.lower():
            console.print("[bold red]API Key 无效或已过期[/bold red]")
        elif "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
            console.print("[bold red]API 请求超时，请检查网络或代理设置[/bold red]")
        elif "rate" in error_msg.lower() or "quota" in error_msg.lower():
            console.print("[bold red]API 额度已用完或触发限流[/bold red]")
        else:
            console.print(f"[bold red]API 连接失败: {error_msg}[/bold red]")
        console.print()
        console.print("[yellow]请检查:[/yellow]")
        console.print("[yellow]  1. API Key 是否正确[/yellow]")
        console.print("[yellow]  2. 网络连接是否正常[/yellow]")
        console.print("[yellow]  3. 代理设置是否正确[/yellow]")
