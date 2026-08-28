"""文件分析器

从 SecurityScanner 中提取的 _analyze_files 方法。
包含纯AI模式和正常模式的文件分析逻辑。
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console

from src.ai.models import AnalysisContext, SecurityAnalysisResult, VulnerabilityFinding
from src.core.config import Config
from src.core.engine import Finding, Location, Severity
from src.core.file_filter import RiskLevel, SecurityFileFilter
from src.core.scan_state import ScanState
from src.core.scanner_finding import deduplicate_findings, merge_duplicate_findings, protect_verified_sources, convert_to_finding
from src.core.types import AnalysisLevel
from src.utils.file_discovery import FileInfo
from src.utils.logger import get_logger
from src.utils.priority_engine import FilePriorityEngine, PriorityStrategy

logger = get_logger(__name__)
console = Console()


async def analyze_files(scanner, files):
    """分析文件（提取自 SecurityScanner._analyze_files）

    Args:
        scanner: SecurityScanner 实例引用
        files: 文件信息列表

    Returns:
        (发现列表, 分析文件数)
    """

    findings = []

    if scanner.tool_orchestrator and scanner.tool_chain_enabled and not scanner.config.pure_ai:
        tool_target = str(Path(files[0].path).parent) if files else "."
        console.print("[bold cyan][TOOL] Running tool chain pre-scan...[/bold cyan]")
        tool_findings = await scanner._tool_prescan(tool_target)
        if tool_findings:
            console.print(
                f"[bold cyan][OK] Tool chain pre-scan found[/bold cyan] [bold red]{len(tool_findings)}[/bold red] [bold cyan]security issues[/bold cyan]"
            )
            findings.extend(tool_findings)

    # 评估文件优先级
    prioritized_files = []

    # 显示文件优先级评估信息
    if not scanner.config.quiet:
        console.print("[bold cyan][SCAN] Evaluating file priority...[/bold cyan]")

    # 获取优先级策略配置
    priority_strategy_str = (
        getattr(scanner.config.scan, "priority_strategy", "full-scan")
        if hasattr(scanner.config, "scan")
        else "full-scan"
    )
    # priority_rules_path = (
    #     getattr(scanner.config.scan, "priority_rules_path", "")
    #     if hasattr(scanner.config, "scan")
    #     else ""
    # )

    # 映射配置字符串到PriorityStrategy枚举
    strategy_mapping = {
        "api-first": PriorityStrategy.API_FIRST,
        "security-first": PriorityStrategy.SECURITY_FIRST,
        "performance-first": PriorityStrategy.COMPLEXITY_FIRST,
        "full-scan": PriorityStrategy.BALANCED,
        "balanced": PriorityStrategy.BALANCED,
    }
    priority_strategy = strategy_mapping.get(priority_strategy_str, PriorityStrategy.BALANCED)

    if not scanner.config.quiet:
        console.print(f"[dim][DEBUG] 使用优先级策略: {priority_strategy.value}[/dim]")

    # 初始化优先级引擎
    priority_engine = FilePriorityEngine()

    # 纯AI模式下使用专门的文件优先级评估器
    if scanner.config.pure_ai:
        # 导入并使用纯净AI模式的文件优先级评估器
        try:
            from src.ai.pure_ai.file_prioritizer import FilePrioritizer as PureAIFilePrioritizer

            pure_ai_prioritizer = PureAIFilePrioritizer()
            if scanner.config.debug:
                console.print("[dim][DEBUG] 使用纯净AI模式的文件优先级评估器[/dim]")

            max_files_limit = getattr(scanner.config, "max_files", 0)

            if max_files_limit > 0:
                top_files = pure_ai_prioritizer._pre_filter_by_rules(
                    [f.path for f in files],
                )[:max_files_limit]
                file_info_map = {str(f.path): f for f in files}
                top_files_with_info = [
                    (file_info_map[f], 0.0, "high") for f in top_files if f in file_info_map
                ]
                console.print(
                    f"[bold cyan][SCAN] 截断模式: 仅扫描前 {len(top_files_with_info)} 个高优先级文件(含OWASP关键词)[/bold cyan]"
                )
            else:
                quick_prioritized = []
                for file_info in files:
                    path = Path(file_info.path)
                    owasp_score = pure_ai_prioritizer._calculate_owasp_score(path)
                    importance_score = pure_ai_prioritizer._calculate_importance(path)
                    problem_probability = pure_ai_prioritizer._calculate_problem_probability(
                        path
                    )
                    combined_score = (
                        owasp_score * 0.5 + importance_score * 0.25 + problem_probability * 0.25
                    )
                    quick_prioritized.append(
                        (
                            file_info,
                            combined_score,
                            "high" if combined_score > 0.5 else "medium",
                        )
                    )

                quick_prioritized.sort(key=lambda x: x[1], reverse=True)
                top_files_with_info = quick_prioritized
                if scanner.config.debug:
                    console.print("[dim][DEBUG] 使用OWASP关键词加权后的快速筛选[/dim]")

            if scanner.config.debug:
                console.print(
                    f"[dim][DEBUG] 快速筛选后，对前{len(top_files_with_info)}个文件进行AI优先级评估[/dim]"
                )

            # 第二步：对筛选出的文件进行AI优先级评估（分批处理）
            async def calculate_ai_priorities():
                results = []
                batch_size = 5  # 每次处理5个文件

                for i in range(0, len(top_files_with_info), batch_size):
                    batch = top_files_with_info[i : i + batch_size]
                    if scanner.config.debug:
                        console.print(
                            f"[dim][DEBUG] 处理文件批次 {i // batch_size + 1}/{(len(top_files_with_info) + batch_size - 1) // batch_size}[/dim]"
                        )

                    tasks = []
                    for file_info, _, _ in batch:
                        tasks.append(
                            pure_ai_prioritizer.calculate_priority(str(file_info.path))
                        )

                    # 处理当前批次
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    results.extend(batch_results)

                return results

            # 执行异步计算
            ai_results = await calculate_ai_priorities()

            # 处理AI评估结果
            for (file_info, _, _), ai_result in zip(top_files_with_info, ai_results):
                if isinstance(ai_result, Exception):
                    # 处理异常，使用传统评估结果
                    if scanner.config.debug:
                        console.print(f"[dim][DEBUG] AI评估失败: {ai_result}，使用传统评估结果[/dim]")
                    score, priority = scanner.file_prioritizer.evaluate_file_priority(
                        Path(file_info.path)
                    )
                else:
                    # 正常处理AI评估结果
                    score = ai_result["priority_score"]
                    # 根据分数确定优先级级别
                    if score >= 0.7:
                        priority = "high"
                    elif score >= 0.4:
                        priority = "medium"
                    else:
                        priority = "low"
                prioritized_files.append((file_info, score, priority))

            # 确保至少有一些文件
            if not prioritized_files:
                # 回退到传统评估，使用max_files配置限制
                max_files_limit = getattr(scanner.config, "max_files", 0)
                fallback_files = files[:max_files_limit] if max_files_limit > 0 else files
                for file_info in fallback_files:
                    score, priority = scanner.file_prioritizer.evaluate_file_priority(
                        Path(file_info.path)
                    )
                    prioritized_files.append((file_info, score, priority))
        except Exception as e:
            if scanner.config.debug:
                console.print(f"[dim][DEBUG] 纯净AI文件优先级评估器初始化失败，使用传统评估: {e}[/dim]")
            # 回退到传统评估，使用max_files配置限制
            max_files_limit = getattr(scanner.config, "max_files", 0)
            fallback_files = files[:max_files_limit] if max_files_limit > 0 else files
            for file_info in fallback_files:
                score, priority = scanner.file_prioritizer.evaluate_file_priority(
                    Path(file_info.path)
                )
                prioritized_files.append((file_info, score, priority))
    else:
        # 使用FilePriorityEngine进行优先级评估
        file_priorities = priority_engine.rank_files(files, priority_strategy)
        for fp in file_priorities:
            prioritized_files.append((fp.file_info, fp.total_score, fp.priority_level.value))

    # 按优先级排序
    prioritized_files.sort(key=lambda x: x[1], reverse=True)

    # 测试模式：只处理指定数量的优先级最高的文件
    # 在 pure-ai 模式下：限制文件数量，但所有文件都进行 AI 分析（不跳过）
    if scanner.config.test_mode:
        test_file_count = getattr(scanner.config, "test_file_count", 10)
        original_count = len(prioritized_files)
        if not scanner.config.pure_ai:
            prioritized_files = prioritized_files[:test_file_count]
            console.print(
                f"[yellow][!] Test mode enabled, only processing first {test_file_count} highest priority files (total {original_count})[/yellow]"
            )
        else:
            # pure-ai 模式：限制数量，但所有文件都进入 AI 分析
            prioritized_files = prioritized_files[:test_file_count]
            console.print(
                f"[yellow][!] Test mode enabled, processing {len(prioritized_files)} files with AI analysis (total {original_count})[/yellow]"
            )

    if scanner.config.debug:
        console.print(f"[dim][DEBUG] 文件优先级评估完成，总计 {len(prioritized_files)} 个文件[/dim]")
        high_count = sum(1 for _, _, p in prioritized_files if p == "high")
        medium_count = sum(1 for _, _, p in prioritized_files if p == "medium")
        low_count = sum(1 for _, _, p in prioritized_files if p == "low")
        console.print(
            f"[dim][DEBUG] 高优先级: {high_count}, 中优先级: {medium_count}, 低优先级: {low_count}[/dim]"
        )

    # 文件类型过滤配置
    file_type_analysis_config = {
        "python": {
            "static": True,
            "rule": True,
            "semantic": True,
            "library": True,
            "web": True,
            "ai": True,
        },
        "javascript": {
            "static": True,
            "rule": True,
            "semantic": True,
            "library": True,
            "web": True,
            "ai": True,
        },
        "html": {
            "static": True,
            "rule": True,
            "semantic": True,
            "library": False,
            "web": True,
            "ai": True,
        },
        "css": {
            "static": False,
            "rule": False,
            "semantic": False,
            "library": False,
            "web": False,
            "ai": False,
        },
        "json": {
            "static": False,
            "rule": True,
            "semantic": False,
            "library": False,
            "web": False,
            "ai": False,
        },
        "markdown": {
            "static": False,
            "rule": False,
            "semantic": False,
            "library": False,
            "web": False,
            "ai": False,
        },
        "txt": {
            "static": False,
            "rule": False,
            "semantic": False,
            "library": False,
            "web": False,
            "ai": False,
        },
        "unknown": {
            "static": False,
            "rule": True,
            "semantic": False,
            "library": False,
            "web": False,
            "ai": False,
        },
    }

    # 显示文件分析信息
    if not scanner.config.quiet:
        console.print("[bold cyan][TOOL] Analyzing files...[/bold cyan]")

    # 纯AI模式：先进行配置扫描，再用批量AI分析
    if scanner.config.pure_ai:
        if scanner.config.debug:
            console.print("[dim][DEBUG] 纯AI模式：使用批量分析[/dim]")

        # 获取测试模式下的目标文件列表
        target_files = prioritized_files if scanner.config.test_mode else files

        # Step 1: 快速配置扫描 - 找出配置文件中的硬编码凭证
        try:
            from src.analyzers.config_scanner import ConfigScanner

            config_scanner = ConfigScanner()
            # Normalize target_files to list of FileInfo
            normalized_targets = [f[0] if isinstance(f, tuple) else f for f in target_files]
            config_files = [
                f for f in normalized_targets if config_scanner.is_config_file(str(f.path))
            ]

            if config_files:
                console.print(
                    f"[yellow][SCAN] Scanning {len(config_files)} config files...[/yellow]"
                )
                config_result = config_scanner.scan_files([str(f.path) for f in config_files])

                if config_result.findings:
                    console.print(
                        f"[yellow][!] Found {len(config_result.findings)} sensitive info in {config_result.files_with_findings} config files[/yellow]"
                    )

                    # 导入配置发现增强器
                    from src.analyzers.config_finding_enhancer import enhance_config_finding

                    # 将配置扫描发现转换为标准 Finding 格式
                    # 标记为verified=True，表示这是已知风险，AI不应降低其严重级别
                    for cf in config_result.findings:
                        from src.core.engine import Finding, Location, Severity

                        # 增强发现：结合上下文评估实际风险等级，提供详细描述和针对性修复建议
                        enhanced = enhance_config_finding(cf)

                        location = Location(file=cf.file_path, line=cf.line_number)

                        finding = Finding(
                            rule_id=enhanced["rule_id"],
                            rule_name=(
                                enhanced["description"].split("，")[0]
                                if "，" in enhanced["description"]
                                else enhanced["description"][:30]
                            ),
                            description=enhanced["description"],
                            severity=Severity[enhanced["severity"]],
                            location=location,
                            code_snippet=cf.value,
                            fix_suggestion=enhanced["remediation"],
                            metadata={
                                "source": "config_scanner",
                                "verified": True,
                                "risk_factors": enhanced.get("risk_factors", []),
                            },
                        )
                        findings.append(finding)
        except Exception as e:
            if scanner.config.debug:
                console.print(f"[dim][DEBUG] 配置扫描失败: {e}[/dim]")

        # Step 1.5: 轻量级代码漏洞扫描 - 使用正则模式快速检测常见漏洞
        try:
            from src.analyzers.code_vuln_scanner import CodeVulnScanner
            from src.core.file_filter import RiskLevel, SecurityFileFilter

            code_vuln_scanner = CodeVulnScanner()
            file_filter = SecurityFileFilter()

            # 智能筛选：只对可疑文件进行完整扫描
            for file_info, _, _ in prioritized_files:
                file_path = str(file_info.path)
                if code_vuln_scanner.is_code_file(
                    file_path
                ) or code_vuln_scanner.is_mybatis_mapper(file_path):
                    # 使用文件过滤器预判风险
                    classified = file_filter.classify_file(file_path)

                    # 只有中高风险文件才进行完整代码扫描
                    if classified.risk_level in (
                        RiskLevel.CRITICAL,
                        RiskLevel.HIGH,
                        RiskLevel.MEDIUM,
                    ):
                        vuln_findings = code_vuln_scanner.scan_file(file_path)

                        if vuln_findings:
                            from src.core.engine import Finding, Location, Severity

                            severity_map = {
                                "critical": Severity.CRITICAL,
                                "high": Severity.HIGH,
                                "medium": Severity.MEDIUM,
                                "low": Severity.LOW,
                            }

                            for vf in vuln_findings:
                                location = Location(file=vf.file_path, line=vf.line_number)

                                finding = Finding(
                                    rule_id=vf.vuln_type,
                                    rule_name=vf.description,
                                    description=vf.description,
                                    severity=severity_map.get(vf.level.value, Severity.MEDIUM),
                                    location=location,
                                    code_snippet=vf.code_snippet,
                                    fix_suggestion=vf.remediation,
                                    metadata={"source": "code_vuln_scanner", "verified": True},
                                )
                                findings.append(finding)

                            console.print(
                                f"[yellow]! Found {len(vuln_findings)} code vulnerabilities in {Path(file_path).name} (risk level: {classified.risk_level.value})[/yellow]"
                            )
        except Exception as e:
            if scanner.config.debug:
                console.print(f"[dim][DEBUG] 代码漏洞扫描失败: {e}[/dim]")
                import traceback

                traceback.print_exc()

        # Step 2: 依赖声明文件库版本CVE匹配
        # 对pom.xml, build.gradle, package.json等依赖文件进行NVD CVE匹配
        try:
            dependency_findings = await scanner._dependency_cve_scan(prioritized_files)
            findings.extend(dependency_findings)
        except Exception as e:
            if scanner.config.debug:
                console.print(f"[dim][DEBUG] 依赖CVE扫描失败: {e}[/dim]")

        # Step 3: 批量AI分析（仅对非Java/非配置文件进行深度AI分析）
        ai_findings = []
        if scanner.pure_ai_analyzer:
            try:
                # 初始化扫描状态
                scan_state = ScanState.create(
                    total_files=len(prioritized_files),
                    max_duration=getattr(scanner.config, "max_duration", 0),
                    max_files=getattr(scanner.config, "max_files", 0),
                )

                from src.utils.cache_manager import get_cache_manager

                cache_manager = get_cache_manager()
                state_file = cache_manager.get_path("scan_state", "scan_state.json")

                # 尝试加载续传状态
                if getattr(scanner.config, "resume", False):
                    loaded_state = ScanState.load(str(state_file))
                    if loaded_state:
                        scan_state = loaded_state
                        console.print(
                            f"[yellow][!] Resuming scan from previous state: {len(scan_state.completed_files)}/{scan_state.total_files} files completed[/yellow]"
                        )
                        # 合并已有发现
                        for f in scan_state.findings:
                            if hasattr(f, "to_finding"):
                                ai_findings.append(f.to_finding())
                            elif isinstance(f, dict):
                                from src.core.engine import CodeContext, Finding, Location

                                loc_data = f.get("location", {})
                                if isinstance(loc_data, dict):
                                    location = Location(
                                        file=loc_data.get("file", ""),
                                        line=loc_data.get("line", 0),
                                        column=loc_data.get("column", 0),
                                        end_line=loc_data.get("end_line", 0),
                                        end_column=loc_data.get("end_column", 0),
                                    )
                                else:
                                    location = Location(file=str(loc_data) if loc_data else "")
                                code_context_data = f.get("code_context")
                                code_context = None
                                if code_context_data and isinstance(code_context_data, dict):
                                    code_context = CodeContext(
                                        context_before=code_context_data.get(
                                            "context_before", []
                                        ),
                                        vulnerable_line=code_context_data.get(
                                            "vulnerable_line", ""
                                        ),
                                        context_after=code_context_data.get(
                                            "context_after", []
                                        ),
                                        line_number=code_context_data.get("line_number", 0),
                                    )
                                finding_kwargs = {
                                    "rule_id": f.get("rule_id", ""),
                                    "rule_name": f.get("rule_name", ""),
                                    "description": f.get("description", ""),
                                    "severity": f.get("severity", "INFO"),
                                    "location": location,
                                    "confidence": f.get("confidence", 0.5),
                                    "message": f.get("message", ""),
                                    "code_snippet": f.get("code_snippet", ""),
                                    "fix_suggestion": f.get("fix_suggestion", ""),
                                    "references": f.get("references", []),
                                    "metadata": f.get("metadata", {}),
                                    "code_context": code_context,
                                }
                                ai_findings.append(Finding(**finding_kwargs))

                # 检查是否启用截断模式
                truncate_mode = getattr(scanner.config, "truncate_output", False)
                max_files_limit = getattr(scanner.config, "max_files", 0)

                # 过滤待处理文件（跳过已完成的）
                pending_files = []
                for i, (file_info, _, _) in enumerate(prioritized_files):
                    if (
                        scan_state.completed_files
                        and str(file_info.path) in scan_state.completed_files
                    ):
                        if scanner.config.debug:
                            console.print(
                                f"[dim][DEBUG] Skipping already completed file: {file_info.path}[/dim]"
                            )
                        continue
                    pending_files.append((i, file_info))

                # 如果启用截断模式且设置了max_files，限制待处理文件数量
                if truncate_mode and max_files_limit > 0:
                    pending_files = pending_files[:max_files_limit]

                # 纯AI模式下文件数量超过100时进行Token消耗预估和费用确认
                if scanner.config.pure_ai and len(pending_files) > 100:
                    file_count = len(pending_files)
                    provider = (
                        scanner.pure_ai_analyzer.ai_provider
                        if scanner.pure_ai_analyzer
                        else "deepseek"
                    )
                    model = scanner.pure_ai_analyzer.ai_model if scanner.pure_ai_analyzer else "v4"

                    cost_estimator = get_cost_estimator()
                    if cost_estimator is not None:
                        estimate = cost_estimator.estimate(file_count, provider, model)
                        estimated_tokens = estimate.estimated_total_tokens
                        estimated_cost = estimate.estimated_total_cost
                    else:
                        estimated_tokens = 0
                        estimated_cost = 0.0

                    token_tracker = get_token_tracker()
                    historical_total = 0
                    recent_tokens = 0
                    if token_tracker is not None:
                        usage_stats = token_tracker.get_usage_stats()
                        historical_total = usage_stats.get("total_tokens", 0)
                        recent_usage = (
                            token_tracker._token_usage[-1]
                            if token_tracker._token_usage
                            else None
                        )
                        recent_tokens = recent_usage["total_tokens"] if recent_usage else 0  # type: ignore[index]

                    console.print(f"[bold yellow]⚠ 文件数量 {file_count} 超过100[/bold yellow]")
                    console.print(
                        f"[dim]  历史总Token消耗: {historical_total:,} | 最近一次扫描: {recent_tokens:,} tokens[/dim]"
                    )
                    console.print(
                        f"[bold yellow]⚠ 预估Token消耗: {estimated_tokens:,} | 预估费用: ${estimated_cost:.4f} ({estimated_cost * 7:.2f}元)[/bold yellow]"
                    )
                    if cost_estimator is not None and estimate:
                        console.print(f"[dim]  定价来源: {estimate.pricing_source}[/dim]")

                    confirm = console.input("[bold yellow]是否确认继续扫描？ (Y/n): [/bold yellow]")
                    if confirm.lower() == "n":
                        console.print("[red]扫描已取消[/red]")
                        return None  # type: ignore[return-value]

                console.print(
                    f"[bold cyan][TOOL] AI analyzing {len(pending_files)} files...[/bold cyan]"
                )

                # [OPT-SASTR] SAST 深度前置过滤：AI 之前先让硬检测出结果（0 LLM token）
                sast_filtered_paths: set = set()
                sast_pipeline_evidence: Dict[str, str] = {}
                hard_sast_findings: list = []
                # [OPT-DEDUP] SAST 候选 (file -> 行号集合)，供 AI 结果去重归属
                sast_candidate_lines: Dict[str, set] = {}
                sast_cfg = getattr(scanner.config, "sast_prefilter", None)
                if scanner.config.pure_ai and sast_cfg and sast_cfg.enabled:
                    try:
                        from src.analyzers.sast_prefilter import SastPrefilter

                        sast = SastPrefilter(sast_cfg)
                        mode = getattr(sast, "mode", "cascade")
                        paths = [str(file_info.path) for _, file_info in pending_files]
                        if mode == "cascade" or mode == "hard-first":
                            # 三级/硬优先：codeql 确认 -> 硬 findings（不耗 AI）；其余 -> AI
                            src_root = os.path.commonpath(paths) if paths else "."
                            if mode == "cascade":
                                c = sast.cascade(src_root, paths)
                            else:
                                s2 = sast.codeql_hits_for(src_root, paths)
                                c = {"s1_by_file": {}, "s2_by_file": s2,
                                     "hard_files": list(s2.keys()),
                                     "ai_files": [p for p in paths if p not in s2],
                                     "note": "hard-first"}
                            if c.get("hard_files"):
                                from src.core.engine import Finding, Location, Severity

                                # [OPT-C1] 相关性筛选：硬候选过确定性污点门（M4 InputTracer）
                                # 可解释性不足（is_exploitable=False）的 codeql 命中降级回 AI，避免硬层 FP
                                hard_keep, demoted = [], []
                                try:
                                    from src.analyzers.input_tracer import InputTracer

                                    tracer = InputTracer(src_root)
                                except Exception:
                                    tracer = None
                                for hpath in c["hard_files"]:
                                    hhits = c["s2_by_file"].get(hpath, [])
                                    if tracer is not None and hhits:
                                        taint_ok = False
                                        for h in hhits:
                                            try:
                                                r_ = tracer.trace_controllability(
                                                    hpath, int(h.get("line", 0) or 0), ""
                                                )
                                                if getattr(r_, "is_exploitable", False):
                                                    taint_ok = True
                                                    break
                                            except Exception:
                                                pass
                                        if not taint_ok:
                                            demoted.append(hpath)
                                            continue
                                    hard_keep.append(hpath)
                                for hpath in demoted:
                                    sast_filtered_paths.discard(hpath)
                                if demoted:
                                    console.print(
                                        f"[yellow][SAST] {len(demoted)} 个 codeql 候选未过污点门，降级回 AI 验证[/yellow]"
                                    )
                                for hpath in hard_keep:
                                    for h in c["s2_by_file"].get(hpath, []):
                                        sev = Severity.HIGH if str(h.get("severity", "")).lower() in (
                                            "error", "high", "critical") else Severity.MEDIUM
                                        hard_sast_findings.append(Finding(
                                            rule_id=str(h.get("rule", "codeql")),
                                            rule_name=f"CodeQL {h.get('rule', '')}",
                                            description=str(h.get("message", ""))[:300],
                                            severity=sev,
                                            location=Location(file=hpath, line=int(h.get("line", 0) or 1), column=0),
                                            confidence=0.9,
                                            message=str(h.get("message", ""))[:200],
                                            code_snippet="",
                                            fix_suggestion="",
                                            references=[],
                                            metadata={"source": "codeql", "cwe": h.get("cwe", "")},
                                        ))
                                    sast_filtered_paths.add(hpath)
                                console.print(
                                    f"[bold green][SAST] CodeQL 硬检出 {len(hard_keep)} 个文件（0 AI token）[/bold green]"
                                )
                            # 剩余文件进 AI（候选验证 + 盲区）
                            pending_files = [
                                (i, fi) for i, fi in pending_files
                                if str(fi.path) not in sast_filtered_paths
                            ]
                            # [OPT-DEDUP] 收集 SAST 候选位置（S1 semgrep/bandit + S2 codeql）
                            for _sfile, _hits in (c.get("s1_by_file") or {}).items():
                                sast_candidate_lines.setdefault(_sfile, set()).update(
                                    int(h.get("line", 0) or 0) for h in _hits
                                )
                            for _sfile, _hits in (c.get("s2_by_file") or {}).items():
                                sast_candidate_lines.setdefault(_sfile, set()).update(
                                    int(h.get("line", 0) or 0) for h in _hits
                                )
                        else:
                            # skip / evidence-only：单文件证据 + 旧门控
                            pre = sast.prefilter_batch(paths)
                            sast_pipeline_evidence = {
                                str(file_info.path): pre.get(str(file_info.path), {}).get(
                                    "evidence", ""
                                )
                                for _, file_info in pending_files
                            }
                            if mode == "skip":
                                keep = []
                                for i, file_info in pending_files:
                                    if pre.get(str(file_info.path), {}).get("hits"):
                                        keep.append((i, file_info))
                                    else:
                                        sast_filtered_paths.add(str(file_info.path))
                                if len(sast_filtered_paths):
                                    console.print(
                                        f"[yellow][SAST] 前置过滤跳过 {len(sast_filtered_paths)} 个零命中文件（省 AI token）[/yellow]"
                                    )
                                pending_files = keep
                    except Exception as e:
                        logger.debug(f"[SAST] 前置过滤失败，降级为全部 AI 分析: {e}")

                # 执行批量分析（并发数可配置，默认与 --workers 一致）
                if pending_files:
                    if (
                        scanner.pure_ai_analyzer
                        and scanner.pure_ai_analyzer.pipeline
                        and sast_pipeline_evidence
                    ):
                        scanner.pure_ai_analyzer.pipeline.sast_evidence = sast_pipeline_evidence
                    max_concurrent = getattr(scanner.config.scan, "max_workers", 4) or 3
                    ai_pending = [
                        (i, file_info)
                        for i, file_info in pending_files
                        if str(file_info.path) not in sast_filtered_paths
                    ]
                    batch_results_map: Dict[str, list] = {}
                    if ai_pending:
                        # [OPT-CACHE] 批量内容哈希去重：同内容文件只分析一次，结果复用（省 token）
                        hash_map: Dict[str, list] = {}
                        try:
                            for i, file_info in ai_pending:
                                h = scanner._content_hash(str(file_info.path))
                                hash_map.setdefault(h, []).append((i, file_info))
                        except Exception:
                            hash_map = {f"u{idx}": [(i, fi)] for idx, (i, fi) in enumerate(ai_pending)}
                        unique_items = [lst[0] for lst in hash_map.values()]
                        unique_results = await scanner.pure_ai_analyzer.analyze_batch(
                            [file_info for _, file_info in unique_items],
                            max_concurrent=max_concurrent,
                        )
                        for (_, file_info), result in zip(unique_items, unique_results):
                            batch_results_map[str(file_info.path)] = result
                        # 复用：同哈希文件共享结果
                        if len(hash_map) < len(ai_pending):
                            for lst in hash_map.values():
                                if len(lst) > 1:
                                    shared = batch_results_map.get(str(lst[0][1].path), [])
                                    for _, dup in lst[1:]:
                                        batch_results_map[str(dup.path)] = shared
                                    logger.debug(
                                        f"[OPT-CACHE] {len(lst)} 个同内容文件共享一次 AI 分析"
                                    )

                    # 收集结果
                    for idx, (i, file_info) in enumerate(pending_files):
                        result = batch_results_map.get(str(file_info.path), [])
                        if str(file_info.path) in sast_filtered_paths:
                            logger.debug(
                                f"[SAST] {Path(file_info.path).name} 由硬检出覆盖，跳过 AI（0 token）"
                            )
                        ai_findings.extend(result)

                        # 保存文件分析结果到缓存
                        scanner._save_file_result(str(file_info.path), result)

                        # 更新扫描状态
                        findings_dicts = []
                        for item in result:
                            if hasattr(item, "to_dict"):
                                findings_dicts.append(item.to_dict())
                            elif hasattr(item, "__dict__"):
                                findings_dicts.append(item.__dict__)
                        scan_state.add_completed_file(str(file_info.path), findings_dicts)

                        # 实时显示发现的问题
                        if result:
                            console.print(f"Scanning file: {Path(file_info.path).name}")
                            for finding_item in result:
                                sev_val = str(getattr(finding_item, "severity", ""))
                                severity_color = (
                                    "red"
                                    if sev_val
                                    in [
                                        "critical",
                                        "high",
                                        "Severity.CRITICAL",
                                        "Severity.HIGH",
                                    ]
                                    else "yellow"
                                    if sev_val in ["medium", "Severity.MEDIUM"]
                                    else "blue"
                                )
                                console.print(
                                    f"→ [{severity_color}]Found {finding_item.rule_name}[/{severity_color}]"
                                )

                        # 检查是否需要截断
                        if truncate_mode:
                            should_trunc, reason = scan_state.should_truncate()
                            if should_trunc:
                                scan_state.mark_truncated(reason or "")
                                console.print(
                                    f"[yellow][!] Scan truncated: {reason} after {len(scan_state.completed_files)} files[/yellow]"
                                )
                                break

                        # 定期保存状态
                        if len(scan_state.completed_files) % 10 == 0:
                            scan_state.save(str(state_file))

                    # 最终保存状态
                    scan_state.save(str(state_file))

                # [OPT-DEDUP] SAST 候选经 AI 二次核验的发现：打标归属 SAST 层（AI 只保留新发现）
                if sast_candidate_lines and ai_findings:
                    deduped = 0
                    _kept: list = []
                    for _f in ai_findings:
                        _loc = getattr(_f, "location", None)
                        _fname = str(getattr(_loc, "file", ""))
                        _line = int(getattr(_loc, "line", 0) or 0)
                        _matched = False
                        if _fname and _line:
                            for _cfile, _clines in sast_candidate_lines.items():
                                if (
                                    os.path.basename(_cfile) == os.path.basename(_fname)
                                    or _cfile == _fname
                                ) and any(abs(_line - _cl) <= 3 for _cl in _clines):
                                    _matched = True
                                    break
                        if _matched:
                            try:
                                _md = getattr(_f, "metadata", {})
                                if isinstance(_md, dict):
                                    _md["sast_verified"] = True
                                    _md["sast_source"] = "semgrep/codeql"
                                else:
                                    setattr(_f, "metadata", {"sast_verified": True, "sast_source": "semgrep/codeql"})
                            except Exception:
                                pass
                            deduped += 1
                            _kept.append(_f)  # 保留在结果中（归属 SAST 层），供报表区分
                        else:
                            _kept.append(_f)
                    if deduped:
                        logger.debug(f"[OPT-DEDUP] {deduped} 条 SAST 候选经 AI 核验打标归属 SAST 层")
                        console.print(
                            f"[green][OPT-DEDUP] {deduped} 条 SAST 候选经 AI 核验 → 归属 SAST 层（AI 只保留新发现）[/green]"
                        )
                    ai_findings = _kept

                # [OPT-SASTR] 硬检出（codeql 确认）findings 并入结果 + 状态落盘（0 AI token）
                if hard_sast_findings:
                    ai_findings.extend(hard_sast_findings)
                    for hf in hard_sast_findings:
                        path = getattr(getattr(hf, "location", None), "file", "")
                        if not path:
                            continue
                        try:
                            scanner._save_file_result(path, [hf])
                            fd = hf.to_dict() if hasattr(hf, "to_dict") else hf.__dict__
                            scan_state.add_completed_file(path, [fd])
                        except Exception as e:
                            logger.debug(f"[SAST] 硬检出落盘失败 {path}: {e}")
                    console.print(
                        f"[bold green][SAST] 并入 {len(hard_sast_findings)} 条 CodeQL 硬检出（不消耗 AI token）[/bold green]"
                    )

                # 收集调试日志（从 pure_ai_analyzer 获取）
                if scanner.pure_ai_analyzer and hasattr(scanner.pure_ai_analyzer, "debug_logs"):
                    # debug_logs = scanner.pure_ai_analyzer.debug_logs
                    pass
            except Exception as e:
                from src.ai.providers.deepseek import APIError as DeepSeekAPIError

                if isinstance(e, DeepSeekAPIError):
                    error_reason = None
                    if (
                        e.code == 402
                        or "余额" in e.message
                        or "Insufficient Balance" in e.message
                    ):
                        error_reason = "api_insufficient_balance"
                    elif e.code == 429 or "限流" in e.message or "Rate Limit" in e.message:
                        error_reason = "api_rate_limit"
                    elif e.code >= 500 or "服务器错误" in e.message:
                        error_reason = "api_server_error"
                    elif "超时" in e.message or "Timeout" in e.message:
                        error_reason = "api_timeout"
                    else:
                        error_reason = "api_connection_error"

                    scan_state.mark_truncated(error_reason)
                    scan_state.save(str(state_file))
                    console.print(f"[bold red][ERROR] {e.message}，扫描已暂停，已保存断点[/bold red]")
                    console.print(
                        f"[yellow]  已完成: {len(scan_state.completed_files)}/{scan_state.total_files} 文件[/yellow]"
                    )
                    console.print("[yellow]  使用 --resume 恢复扫描[/yellow]")
                else:
                    if scanner.config.debug:
                        console.print(f"[dim][DEBUG] AI批量分析失败: {e}[/dim]")
                        import traceback

                        traceback.print_exc()
                    else:
                        console.print(f"[red]AI analysis failed: {e}[/red]")

        if ai_findings and getattr(scanner.config, "pure_ai", False):
            try:
                project_root = getattr(scanner.config, "project_root", "") or str(Path.cwd())
                dynamic_code_path = Path(project_root) / "dynamic_code"
                config_path = dynamic_code_path / "config.yaml"

                if config_path.exists():
                    from src.analyzers.verification import ResultReviewer

                    reviewer = ResultReviewer(
                        project_root=project_root,
                        dynamic_code_path=str(dynamic_code_path),
                        config_path=str(config_path),
                    )

                    findings_for_verification = []
                    for f in ai_findings:
                        if hasattr(f, "to_dict"):
                            finding_dict = f.to_dict()
                        elif hasattr(f, "__dict__"):
                            finding_dict = f.__dict__
                        else:
                            finding_dict = dict(f) if isinstance(f, dict) else {}

                        if not finding_dict.get("id"):
                            finding_dict["id"] = (
                                f.rule_id if hasattr(f, "rule_id") else str(id(f))
                            )
                        finding_dict["file_path"] = (
                            finding_dict.get("location", {}).get("file", "")
                            if isinstance(finding_dict.get("location"), dict)
                            else ""
                        )
                        finding_dict["line_number"] = (
                            finding_dict.get("location", {}).get("line", 0)
                            if isinstance(finding_dict.get("location"), dict)
                            else 0
                        )
                        finding_dict["vuln_type"] = finding_dict.get("rule_id", "")
                        findings_for_verification.append(finding_dict)

                    if findings_for_verification:
                        verification_results = reviewer.run_verification(
                            findings_for_verification
                        )
                        if verification_results:
                            for i, f in enumerate(ai_findings):
                                if i < len(verification_results):
                                    vr = verification_results[i]
                                    if hasattr(f, "metadata") and f.metadata is None:
                                        f.metadata = {}
                                    if hasattr(f, "metadata"):
                                        f.metadata["dynamic_verification"] = {
                                            "is_valid": vr.get("is_valid"),
                                            "is_false_positive": vr.get("is_false_positive"),
                                            "confidence": vr.get("confidence"),
                                            "reason": vr.get("reason"),
                                        }
                            if scanner.config.debug:
                                verified_count = sum(
                                    1
                                    for vr in verification_results
                                    if vr.get("is_valid") is True
                                )
                                fp_count = sum(
                                    1
                                    for vr in verification_results
                                    if vr.get("is_false_positive") is True
                                )
                                console.print(
                                    f"[dim][DEBUG] 动态验证完成: {len(verification_results)} 个发现, 确认: {verified_count}, 误报: {fp_count}[/dim]"
                                )
            except Exception as e:
                if scanner.config.debug:
                    console.print(f"[dim][DEBUG] 动态验证执行失败: {e}[/dim]")

        findings.extend(ai_findings)

        # 合并重复发现：相同规则ID优先使用更高级别
        findings = merge_duplicate_findings(findings)

        # 后处理：确保已验证来源的发现不被低级别发现覆盖
        # config_scanner 和 code_vuln_scanner 的发现是已知的、可复现的安全风险
        # 应该使用它们自己确定的严重级别，而不是被 AI 分析器的判定覆盖
        findings = protect_verified_sources(findings)

        if scanner.config.debug:
            console.print(f"[dim][DEBUG] 纯AI模式批量分析完成，发现 {len(ai_findings)} 个问题[/dim]")
    else:
        # 正常模式：逐个文件分析
        for file_info, score, priority in prioritized_files:
            if scanner.config.debug:
                console.print(
                    f"[dim][DEBUG] 分析文件: {file_info.path} (优先级: {priority}, 分数: {score:.2f})[/dim]"
                )

            # 获取文件类型配置
            file_type = file_info.language.value if file_info.language else "unknown"
            analysis_config = file_type_analysis_config.get(
                file_type, file_type_analysis_config["unknown"]
            )

            if scanner.config.debug:
                console.print(f"[dim][DEBUG] 文件类型: {file_type}, 分析配置: {analysis_config}[/dim]")

            # 正常模式：执行所有分析
            # 显示实时扫描信息
            console.print(f"Scanning file: {Path(file_info.path).name}")

            # 静态分析
            static_findings = []
            if analysis_config["static"]:
                static_findings = scanner._static_analyze(file_info)
                findings.extend(static_findings)

                # 实时显示发现的问题
                if static_findings:
                    for finding in static_findings:
                        severity_color = (
                            "red"
                            if finding.severity in ["critical", "high"]
                            else "yellow"
                            if finding.severity == "medium"
                            else "blue"
                        )
                        console.print(
                            f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]"
                        )

            # 本地语义分析（始终启用，轻量级）
            semantic_findings = []
            if analysis_config["semantic"]:
                semantic_findings = scanner._semantic_analyze(file_info)
                findings.extend(semantic_findings)

                # 实时显示发现的问题
                if semantic_findings:
                    for finding in semantic_findings:
                        severity_color = (
                            "red"
                            if finding.severity in ["critical", "high"]
                            else "yellow"
                            if finding.severity == "medium"
                            else "blue"
                        )
                        console.print(
                            f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]"
                        )

            # 库匹配分析
            library_findings = []
            if analysis_config["library"]:
                library_findings = scanner._library_analyze(file_info)
                findings.extend(library_findings)

                # 实时显示发现的问题
                if library_findings:
                    for finding in library_findings:
                        severity_color = (
                            "red"
                            if finding.severity in ["critical", "high"]
                            else "yellow"
                            if finding.severity == "medium"
                            else "blue"
                        )
                        console.print(
                            f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]"
                        )

            # 规则分析不依赖 legacy AI 结果。
            rule_findings = []
            if analysis_config["rule"]:
                rule_findings = scanner._rule_analyze(file_info, [])
                findings.extend(rule_findings)

                # 实时显示发现的问题
                if rule_findings:
                    for finding in rule_findings:
                        severity_color = (
                            "red"
                            if finding.severity in ["critical", "high"]
                            else "yellow"
                            if finding.severity == "medium"
                            else "blue"
                        )
                        console.print(
                            f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]"
                        )

            # 网络搜索分析（仅基于静态依赖证据）。
            web_findings = []
            if analysis_config["web"] and scanner.web_searcher:
                web_findings = await scanner._web_search_analyze(file_info, library_findings)
                findings.extend(web_findings)

                # 实时显示发现的问题
                if web_findings:
                    for finding in web_findings:
                        severity_color = (
                            "red"
                            if finding.severity in ["critical", "high"]
                            else "yellow"
                            if finding.severity == "medium"
                            else "blue"
                        )
                        console.print(
                            f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]"
                        )

            if scanner.config.debug:
                total_findings = (
                    len(static_findings)
                    + len(rule_findings)
                    + len(semantic_findings)
                    + len(library_findings)
                    + len(web_findings)
                )
                console.print(f"[dim][DEBUG] 文件分析完成，发现 {total_findings} 个问题[/dim]")

    return findings, len(prioritized_files)