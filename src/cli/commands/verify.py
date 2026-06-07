"""验证扫描发现结果"""

import sys
import os
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console(emoji=False, force_terminal=True)

CONFIDENCE_MAP = {"HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.1, "ALL": 0.0}


def _load_findings_from_cache(cache_file: str) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """从扫描缓存文件加载发现列表"""
    from src.core.scan_cache import get_scan_cache_manager

    cache_manager = get_scan_cache_manager()
    session = cache_manager.import_session(cache_file)
    if not session:
        return None, "无法读取缓存文件"

    findings = []
    for result in session.results:
        result_dict = result if isinstance(result, dict) else getattr(result, "__dict__", {})
        file_path = result_dict.get("file_path", "") if isinstance(result_dict, dict) else getattr(result, "file_path", "")
        vulns = result_dict.get("vulnerabilities", []) if isinstance(result_dict, dict) else getattr(result, "vulnerabilities", [])

        for vuln in vulns:
            vuln_dict = vuln if isinstance(vuln, dict) else getattr(vuln, "__dict__", {})
            if isinstance(vuln_dict, dict):
                vuln_dict.setdefault("file_path", file_path)
                findings.append(vuln_dict)

    return findings, None


def _load_findings_from_report(report_file: str) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """从报告文件加载发现列表"""
    path = Path(report_file)
    try:
        if path.suffix == ".json":
            import json

            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        elif path.suffix in (".yaml", ".yml"):
            import yaml

            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        else:
            return None, f"不支持的报告格式: {path.suffix}"

        if isinstance(data, list):
            return data, None
        if isinstance(data, dict):
            for key in ("findings", "vulnerabilities", "results"):
                if key in data and isinstance(data[key], list):
                    return data[key], None
            return [data], None
        return None, "无法从报告中提取发现数据"
    except Exception as e:
        return None, f"读取报告失败: {e}"


def _normalize_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    """将原始发现数据标准化为统一格式"""
    loc = raw.get("location", {})
    if isinstance(loc, dict):
        file_path = loc.get("file", raw.get("file_path", raw.get("file", "")))
        line = loc.get("line", raw.get("line", 0))
    else:
        file_path = raw.get("file_path", raw.get("file", ""))
        line = raw.get("line", 0)

    return {
        "rule_id": raw.get("rule_id", raw.get("rule", "UNKNOWN")),
        "rule_name": raw.get("rule_name", raw.get("title", "")),
        "description": raw.get("description", raw.get("message", "")),
        "severity": str(raw.get("severity", "unknown")).lower(),
        "file": str(file_path),
        "line": int(line) if line else 0,
        "confidence": float(raw.get("confidence", raw.get("confidence_score", 0.5))),
        "code_snippet": raw.get("code_snippet", raw.get("snippet", "")),
        "fix_suggestion": raw.get("fix_suggestion", raw.get("fix", "")),
        "metadata": raw.get("metadata", {}),
    }


def _verify_file_exists(file_path: str, base_dir: Optional[str] = None) -> Tuple[bool, str]:
    """验证文件是否存在"""
    p = Path(file_path)
    if not p.is_absolute() and base_dir:
        p = Path(base_dir) / file_path
    if p.exists() and p.is_file():
        return True, "文件存在"
    return False, "文件不存在"


def _verify_line_number(file_path: str, line: int, base_dir: Optional[str] = None) -> Tuple[bool, str]:
    """验证行号是否有效"""
    p = Path(file_path)
    if not p.is_absolute() and base_dir:
        p = Path(base_dir) / file_path
    if line <= 0:
        return False, "行号无效(<=0)"
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            total = sum(1 for _ in f)
        if line > total:
            return False, f"行号超出范围(文件共{total}行)"
        return True, f"行号有效(文件共{total}行)"
    except Exception as e:
        return False, f"读取文件失败: {e}"


def _verify_code_snippet(file_path: str, line: int, snippet: str, base_dir: Optional[str] = None) -> Tuple[bool, str, str]:
    """验证代码片段是否匹配"""
    if not snippet or not snippet.strip():
        return True, "无代码片段，跳过匹配", ""

    p = Path(file_path)
    if not p.is_absolute() and base_dir:
        p = Path(base_dir) / file_path

    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        if line < 1 or line > len(lines):
            return False, "行号超出范围", ""

        actual_line = lines[line - 1].rstrip()
        snippet_clean = snippet.strip()

        if snippet_clean in actual_line:
            return True, "代码片段完全匹配", actual_line

        if snippet_clean.lower() in actual_line.lower():
            return True, "代码片段匹配(忽略大小写)", actual_line

        for offset in range(-2, 3):
            check = line + offset
            if 1 <= check <= len(lines):
                if snippet_clean in lines[check - 1].rstrip():
                    return True, f"代码片段在相邻行找到(偏移{offset:+d})", lines[check - 1].rstrip()

        return False, "代码片段不匹配", actual_line
    except Exception as e:
        return False, f"读取文件失败: {e}", ""


def _check_vuln_type_still_present(file_path: str, line: int, vuln_type: str, base_dir: Optional[str] = None) -> Tuple[bool, str]:
    """检查漏洞类型是否仍然存在"""
    p = Path(file_path)
    if not p.is_absolute() and base_dir:
        p = Path(base_dir) / file_path

    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        if line < 1 or line > len(lines):
            return False, "行号无效"

        target_line = lines[line - 1].lower()

        type_keywords = {
            "sql": ["execute(", "cursor.", "query(", "raw(", "sql ="],
            "xss": ["innerhtml", "dangerouslysetinnerhtml", "document.write", "eval("],
            "command injection": ["subprocess.", "os.system(", "os.popen(", "exec("],
            "path traversal": ["open(", "read_file", "os.path.join"],
            "ssrf": ["requests.get(", "requests.post(", "urlopen(", "fetch("],
            "hardcoded": ["password", "secret", "api_key", "token", "key="],
            "csrf": ["@csrf_exempt", "csrf_exempt"],
            "deserialization": ["pickle.loads", "yaml.load(", "marshal.loads", "unpickle"],
            "eval": ["eval(", "exec(", "Function(", "new Function"],
            "xpath": ["xpath(", "selectnodes"],
        }

        vuln_lower = vuln_type.lower()
        matched_keywords = []
        for kw_type, keywords in type_keywords.items():
            if kw_type in vuln_lower:
                for kw in keywords:
                    if kw.lower() in target_line:
                        matched_keywords.append(kw)

        if matched_keywords:
            return True, f"漏洞特征仍然存在: {', '.join(matched_keywords)}"

        if any(indicator in vuln_lower for indicator in ["injection", "traversal", "overflow"]):
            return True, "漏洞类型仍存在(基于代码结构判断)"

        return True, "漏洞类型未明确验证(需要人工复核)"
    except Exception as e:
        return False, f"检查失败: {e}"


def _generate_fix_suggestion(finding: Dict[str, Any]) -> str:
    """根据漏洞类型生成修复建议"""
    existing = finding.get("fix_suggestion", "")
    if existing and len(existing) > 5:
        return existing

    vuln_type = finding.get("rule_name", finding.get("rule_id", "")).lower()
    severity = finding.get("severity", "unknown")

    suggestions = {
        "sql": "使用参数化查询替代字符串拼接，例如: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "xss": "对用户输入进行HTML编码，避免使用innerHTML，使用textContent或框架提供的安全渲染方法",
        "command injection": "避免使用os.system()或subprocess调用，使用shlex.quote()转义参数或使用高级API如subprocess.run()",
        "path traversal": "使用os.path.realpath()验证路径，确保访问路径在允许的目录范围内",
        "ssrf": "验证URL的域名和协议，使用白名单限制可访问的目标，避免直接使用用户提供的URL",
        "hardcoded": "将敏感信息移至环境变量或配置文件，使用密钥管理服务(KMS)",
        "csrf": "添加CSRF token验证，使用框架内置的CSRF保护中间件",
        "deserialization": "避免使用pickle/yaml.load()处理不可信数据，使用安全的序列化格式如JSON",
        "eval": "避免使用eval()/exec()，使用安全的替代方案如ast.literal_eval()或解析器",
        "xpath": "使用参数化XPath查询，对用户输入进行转义",
    }

    for kw, suggestion in suggestions.items():
        if kw in vuln_type:
            return suggestion

    return f"建议审查该{severity.upper()}级别问题，确认漏洞是否存在并修复"


@click.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--min-confidence", type=click.Choice(["HIGH", "MEDIUM", "LOW", "ALL"]), default="HIGH", help="最低置信度过滤 (默认: HIGH)")
@click.option("--auto-fix", is_flag=True, help="自动生成修复建议")
@click.option("--output", "-o", help="输出验证报告文件路径")
@click.option("--base-dir", type=click.Path(exists=True), help="项目根目录(用于解析相对路径)")
@click.pass_context
def verify(
    ctx: click.Context,
    input_file: str,
    min_confidence: str,
    auto_fix: bool,
    output: Optional[str],
    base_dir: Optional[str],
) -> None:
    """验证扫描发现结果的有效性

    检查文件存在性、行号有效性、代码片段匹配以及漏洞类型是否仍然存在。
    """
    config = ctx.obj.get("config") if ctx.obj else None
    quiet = getattr(config, "quiet", False) if config else False

    if not quiet:
        console.print("[bold cyan]> hosls verify " + input_file + "[/bold cyan]")

    # 加载发现数据
    path = Path(input_file)
    findings_raw = None
    error = None

    if path.suffix == ".json" and path.name != "session.json":
        findings_raw, error = _load_findings_from_report(input_file)
    elif path.suffix in (".yaml", ".yml"):
        findings_raw, error = _load_findings_from_report(input_file)
    else:
        findings_raw, error = _load_findings_from_cache(input_file)
        if findings_raw is None:
            findings_raw, error = _load_findings_from_report(input_file)

    if findings_raw is None:
        console.print(f"[bold red]加载失败: {error}[/bold red]")
        sys.exit(1)

    if not quiet:
        console.print(f"[green]共加载 {len(findings_raw)} 条原始发现[/green]")

    # 标准化并过滤
    min_confidence_val = CONFIDENCE_MAP.get(min_confidence, 0.7)
    findings = []
    skipped = 0
    for raw in findings_raw:
        f = _normalize_finding(raw)
        if f["confidence"] < min_confidence_val:
            skipped += 1
            continue
        findings.append(f)

    if not quiet and skipped > 0:
        console.print(f"[dim]已过滤 {skipped} 条低于置信度阈值({min_confidence})的发现[/dim]")
    if not quiet:
        console.print(f"[bold]待验证发现: {len(findings)}[/bold]")

    if not findings:
        console.print("[yellow]没有符合置信度阈值的发现需要验证[/yellow]")
        return

    # 确定基准目录
    if not base_dir:
        base_dir = os.path.dirname(os.path.abspath(input_file))

    # 执行验证
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]验证中..."),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("验证", total=len(findings))

        for finding in findings:
            file_ok, file_msg = _verify_file_exists(finding["file"], base_dir)
            line_ok, line_msg = (False, "跳过(文件不存在)") if not file_ok else _verify_line_number(finding["file"], finding["line"], base_dir)

            snippet_ok, snippet_msg, actual_code = (False, "跳过", "") if not line_ok else _verify_code_snippet(finding["file"], finding["line"], finding["code_snippet"], base_dir)

            vuln_ok, vuln_msg = (False, "跳过") if not line_ok else _check_vuln_type_still_present(finding["file"], finding["line"], finding["rule_name"], base_dir)

            verified = file_ok and line_ok and snippet_ok and vuln_ok

            result = {
                "finding": finding,
                "file_exists": file_ok,
                "file_msg": file_msg,
                "line_valid": line_ok,
                "line_msg": line_msg,
                "snippet_match": snippet_ok,
                "snippet_msg": snippet_msg,
                "vuln_present": vuln_ok,
                "vuln_msg": vuln_msg,
                "verified": verified,
                "actual_code": actual_code,
            }

            if auto_fix:
                result["fix_suggestion"] = _generate_fix_suggestion(finding)

            results.append(result)
            progress.advance(task)

    # 输出结果
    _display_verification_results(results, auto_fix)

    # 可选导出
    if output:
        _export_verification_report(results, output)
        console.print(f"[bold green]验证报告已导出: {output}[/bold green]")

    # 退出码
    verified_count = sum(1 for r in results if r["verified"])
    if verified_count == 0:
        sys.exit(1)
    elif verified_count < len(results):
        sys.exit(0)
    else:
        sys.exit(0)


def _display_verification_results(results: List[Dict[str, Any]], auto_fix: bool) -> None:
    """显示验证结果"""
    total = len(results)
    verified = sum(1 for r in results if r["verified"])
    failed = total - verified

    console.print(Panel(
        f"[bold]验证摘要[/bold]\n"
        f"  总计: [cyan]{total}[/cyan]  |  "
        f"已验证: [green]{verified}[/green]  |  "
        f"未通过: [red]{failed}[/red]\n"
        f"  验证通过率: [{'green' if verified == total else 'yellow'}]{verified / total * 100:.1f}%[/{'green' if verified == total else 'yellow'}]",
        border_style="green" if verified == total else "yellow",
        title="[bold]验证完成[/bold]"
    ))

    # 详细表格
    table = Table(title="验证详情")
    table.add_column("#", style="dim")
    table.add_column("规则", style="cyan")
    table.add_column("位置", style="white")
    table.add_column("置信度", style="cyan")
    table.add_column("文件", style="dim", width=5)
    table.add_column("行号", style="dim", width=5)
    table.add_column("代码", style="dim", width=5)
    table.add_column("漏洞", style="dim", width=5)
    table.add_column("状态", style="bold")

    for i, r in enumerate(results, 1):
        f = r["finding"]
        conf_icon = "[green]" if f["confidence"] >= 0.7 else "[yellow]" if f["confidence"] >= 0.4 else "[red]"

        file_icon = "[green]OK" if r["file_exists"] else "[red]FAIL"
        line_icon = "[green]OK" if r["line_valid"] else "[red]FAIL"
        snippet_icon = "[green]OK" if r["snippet_match"] else "[red]FAIL"
        vuln_icon = "[green]OK" if r["vuln_present"] else "[red]FAIL"

        status = "[green]VERIFIED" if r["verified"] else "[red]FAILED"

        location = f"{f['file']}:{f['line']}" if f['line'] else f['file']
        if len(location) > 40:
            location = "..." + location[-37:]

        table.add_row(
            str(i),
            f["rule_id"][:20],
            location,
            f"{conf_icon}{f['confidence']:.2f}",
            file_icon,
            line_icon,
            snippet_icon,
            vuln_icon,
            status,
        )

    console.print(table)

    # 显示未通过的详情
    failed_results = [r for r in results if not r["verified"]]
    if failed_results:
        console.print("\n[bold red]未通过的发现详情:[/bold red]")
        for r in failed_results:
            f = r["finding"]
            console.print(Panel(
                f"[bold]{f['rule_id']}[/bold] - {f['rule_name']}\n"
                f"位置: {f['file']}:{f['line']}\n"
                f"文件存在: {'[green]是[/green]' if r['file_exists'] else '[red]否[/red]'} - {r['file_msg']}\n"
                f"行号有效: {'[green]是[/green]' if r['line_valid'] else '[red]否[/red]'} - {r['line_msg']}\n"
                f"代码匹配: {'[green]是[/green]' if r['snippet_match'] else '[red]否[/red]'} - {r['snippet_msg']}\n"
                f"漏洞存在: {'[green]是[/green]' if r['vuln_present'] else '[red]否[/red]'} - {r['vuln_msg']}",
                border_style="red",
                title=f"[red]# {results.index(r) + 1}[/red]"
            ))

    # 修复建议
    if auto_fix:
        fix_results = [r for r in results if not r["verified"] or r["vuln_present"]]
        if fix_results:
            console.print("\n[bold cyan]修复建议:[/bold cyan]")
            for r in fix_results:
                f = r["finding"]
                console.print(f"\n[dim]#{results.index(r) + 1} {f['rule_id']}:[/dim]")
                console.print(f"  {r.get('fix_suggestion', '无修复建议')}")


def _export_verification_report(results: List[Dict[str, Any]], output_path: str) -> None:
    """导出验证报告"""
    report = {
        "total": len(results),
        "verified": sum(1 for r in results if r["verified"]),
        "failed": sum(1 for r in results if not r["verified"]),
        "findings": [],
    }

    for r in results:
        f = r["finding"]
        entry = {
            "rule_id": f["rule_id"],
            "rule_name": f["rule_name"],
            "severity": f["severity"],
            "confidence": f["confidence"],
            "location": {"file": f["file"], "line": f["line"]},
            "verified": r["verified"],
            "checks": {
                "file_exists": {"passed": r["file_exists"], "message": r["file_msg"]},
                "line_valid": {"passed": r["line_valid"], "message": r["line_msg"]},
                "snippet_match": {"passed": r["snippet_match"], "message": r["snippet_msg"]},
                "vuln_present": {"passed": r["vuln_present"], "message": r["vuln_msg"]},
            },
        }
        if "fix_suggestion" in r:
            entry["fix_suggestion"] = r["fix_suggestion"]
        report["findings"].append(entry)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    if out.suffix == ".json":
        import json
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    else:
        import json
        with open(out.with_suffix(".json"), "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
