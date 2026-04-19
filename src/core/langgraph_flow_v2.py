"""LangGraph V2 流程 - Plan-first 执行系统

实现新的扫描流程：
1. Plan Generator → 生成扫描计划
2. Search Layer → 三层过滤 (AST + Taint + Risk Scoring)
3. Multi-Agent（精简异构版）→ 只在必要时使用 LLM

核心理念：结构化系统 → 极限缩小问题空间 → AI只做最终裁决
"""

from langgraph.graph import StateGraph, END
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
from dataclasses import dataclass, field

from src.core.langgraph_state import ScanState
from src.core.engine import ScanResult, Finding, Severity, Location
from src.core.plan_generator import get_plan_generator, ScanPlan, ScanStrategy, ScanPriority
from src.taint.engine import get_taint_engine, TaintPath
from src.assessment.risk_engine import get_risk_engine, VulnerabilityCandidate, Severity as RiskSeverity
from src.cache.manager import CacheManagerV2


cache_manager_v2 = CacheManagerV2()


@dataclass
class V2ScanState:
    target: str
    plan: Optional[ScanPlan] = None
    layer1_results: List[Dict[str, Any]] = field(default_factory=list)
    taint_paths: List[TaintPath] = field(default_factory=list)
    candidates: List[VulnerabilityCandidate] = field(default_factory=list)
    scan_result: Optional[ScanResult] = None
    error: Optional[str] = None

    def update(self, **kwargs) -> "V2ScanState":
        for key, value in kwargs.items():
            setattr(self, key, value)
        return self


async def plan_generation_node(state: V2ScanState) -> V2ScanState:
    """Plan Generation 节点 (V2 核心)

    根据用户输入生成扫描计划，决定扫描策略、范围和优先级。
    这是 Plan-first 流程的第一步。
    """
    try:
        plan_gen = get_plan_generator()

        cached_plan = cache_manager_v2.get_cached_plan(state.target)
        if cached_plan:
            from src.core.plan_generator import ScanPlan
            plan = ScanPlan(
                targets=cached_plan["targets"],
                focus=cached_plan["focus"],
                strategy=ScanStrategy(cached_plan["strategy"]),
                depth=cached_plan["depth"],
                priority=ScanPriority(cached_plan["priority"]),
                use_rag=cached_plan.get("use_rag", False),
                use_graph=cached_plan.get("use_graph", False),
            )
        else:
            plan = plan_gen.generate_plan(state.target)

        return state.update(plan=plan)

    except Exception as e:
        return state.update(error=f"Plan generation failed: {e}")


async def layer1_ast_filter_node(state: V2ScanState) -> V2ScanState:
    """Layer 1: AST + 结构过滤节点

    只保留 API 入口、DB操作、IO操作、敏感调用点。
    这是三层过滤体系的第一层。
    """
    try:
        if not state.plan:
            return state.update(error="No plan available")

        from src.assessment.risk_engine import Layer1Filter

        layer1 = Layer1Filter()
        files = state.plan.targets

        language = "python"
        if files and Path(files[0]).suffix.lstrip(".") in ["js", "ts", "jsx", "tsx"]:
            language = "javascript"

        results = layer1.filter(files, language)

        return state.update(layer1_results=results)

    except Exception as e:
        return state.update(error=f"Layer 1 filter failed: {e}")


async def layer2_taint_analysis_node(state: V2ScanState) -> V2ScanState:
    """Layer 2: Taint Analysis 节点

    执行跨函数、跨文件的污点传播分析。
    只保留有完整污染路径的代码。
    这是三层过滤体系的第二层。
    """
    try:
        if not state.plan:
            return state.update(error="No plan available")

        if not state.layer1_results:
            return state.update(taint_paths=[])

        taint_engine = get_taint_engine()
        files = state.plan.targets

        language = "python"
        if files and Path(files[0]).suffix.lstrip(".") in ["js", "ts", "jsx", "tsx"]:
            language = "javascript"

        taint_paths = taint_engine.analyze(files, language)

        return state.update(taint_paths=taint_paths)

    except Exception as e:
        return state.update(error=f"Layer 2 taint analysis failed: {e}")


async def layer3_risk_scoring_node(state: V2ScanState) -> V2ScanState:
    """Layer 3: Risk Scoring 节点

    计算 Top 20~50 候选漏洞。
    这是三层过滤体系的第三层。
    """
    try:
        if not state.plan:
            return state.update(error="No plan available")

        if not state.taint_paths:
            return state.update(candidates=[])

        risk_engine = get_risk_engine()
        files = state.plan.targets
        max_candidates = state.plan.max_candidates

        language = "python"
        if files and Path(files[0]).suffix.lstrip(".") in ["js", "ts", "jsx", "tsx"]:
            language = "javascript"

        candidates = risk_engine.analyze(files, language, max_candidates)

        return state.update(candidates=candidates)

    except Exception as e:
        return state.update(error=f"Layer 3 risk scoring failed: {e}")


async def vulnerability_judge_node(state: V2ScanState) -> V2ScanState:
    """Vuln Judge 节点 (LLM)

    使用 LLM 判断漏洞是否为真阳性。
    仅在必要时调用 LLM，减少 Token 消耗。

    注意：这是一个占位符节点，实际 LLM 判断功能需要后续集成。
    当前版本直接跳过，仅使用 Risk Scoring 的结果。
    """
    try:
        if not state.plan or not state.plan.use_llm_judge:
            return state

        if not state.candidates:
            return state

        high_risk_candidates = [
            c for c in state.candidates
            if c.severity in [RiskSeverity.CRITICAL, RiskSeverity.HIGH]
        ]

        if not high_risk_candidates:
            return state

        return state

    except Exception as e:
        return state.update(error=f"Vuln judge failed: {e}")


async def report_generation_node(state: V2ScanState) -> V2ScanState:
    """Report Generation 节点

    将候选漏洞转换为最终报告。
    """
    try:
        scan_result = ScanResult(
            target=state.target,
            status="running"
        )

        for candidate in state.candidates:
            severity_map = {
                RiskSeverity.CRITICAL: Severity.CRITICAL,
                RiskSeverity.HIGH: Severity.HIGH,
                RiskSeverity.MEDIUM: Severity.MEDIUM,
                RiskSeverity.LOW: Severity.LOW,
                RiskSeverity.INFO: Severity.INFO,
            }

            finding = Finding(
                rule_id=candidate.rule_id,
                rule_name=candidate.rule_name,
                description=candidate.description,
                severity=severity_map.get(candidate.severity, Severity.MEDIUM),
                location=Location(
                    file=candidate.location.get("file", state.target),
                    line=candidate.location.get("line", 1),
                    column=candidate.location.get("column", 0),
                ),
                confidence=candidate.confidence,
                message=f"发现 {candidate.rule_name}",
                code_snippet=candidate.code_snippet,
                fix_suggestion=candidate.fix_suggestion,
                metadata=candidate.metadata,
            )
            scan_result.add_finding(finding)

        scan_result.complete()
        return state.update(scan_result=scan_result)

    except Exception as e:
        return state.update(error=f"Report generation failed: {e}")


def should_use_llm_judge(state: V2ScanState) -> str:
    """判断是否使用 LLM Judge

    根据扫描策略和候选漏洞数量决定是否调用 LLM。
    """
    if not state.plan:
        return "skip"

    if not state.plan.use_llm_judge:
        return "skip"

    high_risk_count = sum(
        1 for c in state.candidates
        if c.severity in [RiskSeverity.CRITICAL, RiskSeverity.HIGH]
    )

    if high_risk_count == 0:
        return "skip"

    return "judge"


def should_run_deep_analysis(state: V2ScanState) -> str:
    """判断是否需要深度分析

    根据扫描策略和候选漏洞数量决定是否运行深度分析。
    """
    if not state.plan:
        return "skip"

    if state.plan.strategy == ScanStrategy.DEEP:
        return "deep"

    if state.plan.strategy == ScanStrategy.FAST:
        return "fast"

    return "normal"


def create_v2_scan_graph() -> StateGraph:
    """创建 V2 扫描流程图

    Plan-first 执行流程：
    1. Plan Generation → 生成扫描计划
    2. Layer 1: AST Filter → 结构过滤
    3. Layer 2: Taint Analysis → 污点分析
    4. Layer 3: Risk Scoring → 风险评分 (Top 20~50)
    5. [Optional] Vuln Judge → LLM 判断
    6. Report Generation → 报告生成
    """
    graph = StateGraph(V2ScanState)

    graph.add_node("plan_generation", plan_generation_node)
    graph.add_node("layer1_ast_filter", layer1_ast_filter_node)
    graph.add_node("layer2_taint_analysis", layer2_taint_analysis_node)
    graph.add_node("layer3_risk_scoring", layer3_risk_scoring_node)
    graph.add_node("vulnerability_judge", vulnerability_judge_node)
    graph.add_node("report_generation", report_generation_node)

    graph.set_entry_point("plan_generation")

    graph.add_edge("plan_generation", "layer1_ast_filter")
    graph.add_edge("layer1_ast_filter", "layer2_taint_analysis")
    graph.add_edge("layer2_taint_analysis", "layer3_risk_scoring")

    graph.add_conditional_edges(
        "layer3_risk_scoring",
        should_use_llm_judge,
        {
            "judge": "vulnerability_judge",
            "skip": "report_generation"
        }
    )

    graph.add_edge("vulnerability_judge", "report_generation")
    graph.add_edge("report_generation", END)

    return graph


def compile_v2_graph():
    """编译 V2 流程图"""
    graph = create_v2_scan_graph()
    return graph.compile()


async def run_v2_scan(target: str, config: Any = None) -> ScanResult:
    """运行 V2 扫描流程

    Args:
        target: 扫描目标
        config: 配置

    Returns:
        ScanResult: 扫描结果
    """
    try:
        print("📊 HOS-LS V2 扫描流程启动 (Plan-first)")
        print(f"🎯 扫描目标: {target}")

        cache_manager_v2.initialize()

        initial_state = V2ScanState(target=target)

        app = compile_v2_graph()

        print("🚀 执行 V2 扫描流程")
        result = await app.ainvoke(initial_state)
        print("✅ V2 扫描流程执行完成")

        if result.scan_result:
            print(f"📋 扫描完成，发现 {len(result.scan_result.findings)} 个问题")
            return result.scan_result
        else:
            scan_result = ScanResult(target=target, status="completed")
            scan_result.complete()
            return scan_result

    except Exception as e:
        error_result = ScanResult(target=target, status="failed")
        error_result.fail(str(e))
        print(f"❌ V2 扫描流程失败: {e}")
        return error_result
    finally:
        cache_manager_v2.close()


class V2ScanFlow:
    """V2 扫描流程管理器

    提供 Plan-first 扫描流程的封装。
    """

    def __init__(self, config: Optional[Any] = None) -> None:
        self.config = config
        self._graph = None

    @property
    def graph(self) -> Any:
        if self._graph is None:
            self._graph = compile_v2_graph()
        return self._graph

    async def run(self, target: str) -> ScanResult:
        return await run_v2_scan(target, self.config)

    def get_plan(self, target: str) -> Optional[ScanPlan]:
        plan_gen = get_plan_generator()
        return plan_gen.generate_plan(target)

    def should_use_v2(self, target: str) -> bool:
        plan_gen = get_plan_generator()
        plan = plan_gen.generate_plan(target)

        if plan.strategy in [ScanStrategy.TAINT_FIRST, ScanStrategy.DEEP]:
            return True

        if plan.priority.value in ["critical", "high"]:
            return True

        return False


def get_v2_scan_flow(config: Optional[Any] = None) -> V2ScanFlow:
    return V2ScanFlow(config)
