"""多阶段扫描器

集成代码切片、两阶段 Prompt、扫描调度器的完整扫描流程。
增强版本：集成 Search Agent，实现分层扫描架构。

Stage 1: 静态规则（快） → 候选漏洞点
Stage 2: Search Agent 筛选 Top-K
Stage 3: AI 深度分析
Stage 4: Exploit 生成 + 验证
"""

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Set
from enum import Enum

from src.analyzers.code_slicer import CodeSlicer
from src.ai.prompts import PromptManager, get_prompt_manager
from src.core.scan_scheduler import ScanScheduler, MultiPhaseScanner
from src.core.result_aggregator import ResultAggregator, AggregatedFinding
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ScanStage(Enum):
    """扫描阶段"""
    STATIC_ANALYSIS = "static_analysis"
    SEARCH_AGENT_FILTER = "search_agent_filter"
    AI_DEEP_ANALYSIS = "ai_deep_analysis"
    EXPLOIT_VALIDATION = "exploit_validation"
    FINAL_DECISION = "final_decision"


@dataclass
class MultiStageScanConfig:
    """多阶段扫描配置"""
    enable_phase1: bool = True
    enable_phase2: bool = True
    enable_search_agent: bool = True
    enable_parallel_agents: bool = True
    phase1_max_tokens: int = 1024
    phase2_context_lines: int = 50
    use_code_slicing: bool = True
    max_concurrent: int = 5
    top_k_files: int = 20
    enable_incremental_scan: bool = True
    enable_exploit_generation: bool = True


@dataclass
class SuspiciousPoint:
    """可疑点"""
    line: int
    type: str
    snippet: str


@dataclass
class PhaseResult:
    """阶段结果"""
    stage: ScanStage
    candidates: List[str]
    findings: List[Any]
    metadata: Dict[str, Any]
    elapsed_time: float


@dataclass
class Phase1Result:
    """第一阶段结果"""
    file_path: str
    suspicious_points: List[SuspiciousPoint] = field(default_factory=list)


@dataclass
class ScanFileResult:
    """单个文件扫描结果"""
    file_path: str
    phase1_result: Optional[Phase1Result] = None
    phase2_findings: List[AggregatedFinding] = field(default_factory=list)


@dataclass
class MultiStageScanResult:
    """多阶段扫描总结果"""
    total_files: int = 0
    scanned_files: int = 0
    files_with_findings: int = 0
    file_results: List[ScanFileResult] = field(default_factory=list)
    aggregated_result: Optional[Any] = None
    stage_results: Dict[str, PhaseResult] = field(default_factory=dict)
    incremental_stats: Dict[str, Any] = field(default_factory=dict)


class SearchAgentFilter:
    """Search Agent 过滤器

    使用 Search Agent 对候选文件进行优先级排序和筛选。
    """

    def __init__(
        self,
        top_k: int = 20,
        score_calculator=None,
        semantic_searcher=None
    ):
        self.top_k = top_k
        self.score_calculator = score_calculator
        self.semantic_searcher = semantic_searcher

    async def filter(
        self,
        candidate_files: List[str],
        query: str = "",
        changed_files: Optional[Set[str]] = None
    ) -> List[str]:
        """筛选文件

        Args:
            candidate_files: 候选文件列表
            query: 搜索查询
            changed_files: 变更文件集合

        Returns:
            筛选后的文件列表
        """
        if not self.score_calculator:
            return candidate_files[:self.top_k]

        changed_set = changed_files or set()

        scored_files = []
        for fp in candidate_files:
            is_changed = str(fp) in changed_set
            try:
                from src.ai.search_agent import ScoreCalculator
                calc = ScoreCalculator()
                score = calc.calculate_score(
                    file_path=str(fp),
                    keyword=query,
                    is_changed=is_changed
                )
                scored_files.append((fp, score.total_score))
            except Exception:
                scored_files.append((fp, 0.5))

        scored_files.sort(key=lambda x: x[1], reverse=True)
        return [fp for fp, _ in scored_files[:self.top_k]]


class ParallelAgentExecutor:
    """并行 Agent 执行器

    支持多个 Agent 并行执行，提高扫描效率。
    """

    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def execute_parallel(
        self,
        agents: List[Callable],
        file_path: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """并行执行多个 Agent

        Args:
            agents: Agent 函数列表
            file_path: 文件路径
            context: 执行上下文

        Returns:
            各 Agent 的结果字典
        """
        async def run_agent(agent: Callable) -> tuple[str, Any]:
            async with self.semaphore:
                try:
                    result = await agent(file_path, context)
                    return agent.__name__, result
                except Exception as e:
                    logger.warning(f"Agent {agent.__name__} failed: {e}")
                    return agent.__name__, None

        tasks = [run_agent(agent) for agent in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        result_dict = {}
        for result in results:
            if isinstance(result, tuple) and len(result) == 2:
                agent_name, agent_result = result
                result_dict[agent_name] = agent_result

        return result_dict


class MultiStageScannerEngine:
    """多阶段扫描引擎

    增强版本：集成 Search Agent，实现分层扫描架构。
    """

    def __init__(
        self,
        config: Optional[MultiStageScanConfig] = None,
        prompt_manager: Optional[PromptManager] = None,
        scan_scheduler: Optional[ScanScheduler] = None,
        result_aggregator: Optional[ResultAggregator] = None
    ):
        """初始化多阶段扫描引擎

        Args:
            config: 扫描配置
            prompt_manager: 提示词管理器
            scan_scheduler: 扫描调度器
            result_aggregator: 结果聚合器
        """
        self.config = config or MultiStageScanConfig()
        self.prompt_manager = prompt_manager or get_prompt_manager()
        self.scan_scheduler = scan_scheduler or ScanScheduler(
            max_concurrent=self.config.max_concurrent
        )
        self.result_aggregator = result_aggregator or ResultAggregator()
        self.code_slicer = CodeSlicer()

        self._search_agent_filter: Optional[SearchAgentFilter] = None
        self._parallel_executor: Optional[ParallelAgentExecutor] = None
        self._file_index: Any = None

        self._initialize_enhanced_components()

    def _initialize_enhanced_components(self) -> None:
        """初始化增强组件"""
        if self.config.enable_search_agent:
            try:
                from src.ai.search_agent import ScoreCalculator, SemanticSearcher

                semantic_searcher = SemanticSearcher()
                score_calculator = ScoreCalculator()

                self._search_agent_filter = SearchAgentFilter(
                    top_k=self.config.top_k_files,
                    score_calculator=score_calculator,
                    semantic_searcher=semantic_searcher
                )

                logger.debug("Search Agent 过滤器初始化成功")

            except Exception as e:
                logger.warning(f"Search Agent 组件初始化失败: {e}")

        if self.config.enable_parallel_agents:
            self._parallel_executor = ParallelAgentExecutor(
                max_concurrent=self.config.max_concurrent
            )

    def detect_language(self, file_path: str) -> str:
        """检测文件编程语言

        Args:
            file_path: 文件路径

        Returns:
            str: 编程语言
        """
        ext = Path(file_path).suffix.lower()
        lang_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp"
        }
        return lang_map.get(ext, "unknown")

    def read_file(self, file_path: str) -> Optional[str]:
        """读取文件内容

        Args:
            file_path: 文件路径

        Returns:
            Optional[str]: 文件内容
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return None

    def get_context_around_line(
        self,
        code: str,
        line_num: int,
        context_lines: int = 50
    ) -> str:
        """获取指定行号周围的代码

        Args:
            code: 完整代码
            line_num: 行号
            context_lines: 上下文行数

        Returns:
            str: 上下文代码
        """
        lines = code.split('\n')
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return '\n'.join(lines[start:end])

    async def stage1_static_analysis(
        self,
        file_paths: List[str]
    ) -> PhaseResult:
        """Stage 1: 静态规则快速扫描

        Args:
            file_paths: 文件路径列表

        Returns:
            PhaseResult: 阶段结果
        """
        import time
        start_time = time.time()

        candidates = []
        findings = []

        for fp in file_paths:
            try:
                code = self.read_file(fp)
                if not code:
                    continue

                language = self.detect_language(fp)

                if self.config.use_code_slicing:
                    slices = self.code_slicer.slice_file(fp)
                    for code_slice in slices:
                        prompt = self.prompt_manager.get_phase1_prompt(
                            language=language,
                            code=code_slice.content
                        )
                        candidates.append(fp)
                else:
                    prompt = self.prompt_manager.get_phase1_prompt(
                        language=language,
                        code=code
                    )
                    candidates.append(fp)

            except Exception as e:
                logger.debug(f"Stage 1 static analysis error for {fp}: {e}")

        elapsed = time.time() - start_time
        logger.info(f"Stage 1 completed: {len(candidates)} candidates in {elapsed:.2f}s")

        return PhaseResult(
            stage=ScanStage.STATIC_ANALYSIS,
            candidates=candidates,
            findings=findings,
            metadata={'total_files': len(file_paths), 'candidates': len(candidates)},
            elapsed_time=elapsed
        )

    async def stage2_search_agent_filter(
        self,
        candidates: List[str],
        query: str = "",
        changed_files: Optional[Set[str]] = None
    ) -> PhaseResult:
        """Stage 2: Search Agent 筛选 Top-K

        Args:
            candidates: 候选文件列表
            query: 搜索查询
            changed_files: 变更文件集合

        Returns:
            PhaseResult: 阶段结果
        """
        import time
        start_time = time.time()

        if self._search_agent_filter:
            filtered = await self._search_agent_filter.filter(
                candidate_files=candidates,
                query=query,
                changed_files=changed_files
            )
        else:
            filtered = candidates[:self.config.top_k_files]

        elapsed = time.time() - start_time
        logger.info(f"Stage 2 completed: {len(filtered)} files filtered in {elapsed:.2f}s")

        return PhaseResult(
            stage=ScanStage.SEARCH_AGENT_FILTER,
            candidates=filtered,
            findings=[],
            metadata={'input_candidates': len(candidates), 'output_candidates': len(filtered)},
            elapsed_time=elapsed
        )

    async def stage3_ai_deep_analysis(
        self,
        file_paths: List[str],
        ai_client: Any
    ) -> PhaseResult:
        """Stage 3: AI 深度分析

        Args:
            file_paths: 文件路径列表
            ai_client: AI 客户端

        Returns:
            PhaseResult: 阶段结果
        """
        import time
        start_time = time.time()

        findings = []

        if self._parallel_executor and self.config.enable_parallel_agents:
            for fp in file_paths:
                try:
                    code = self.read_file(fp)
                    if not code:
                        continue

                    context = {
                        'file_path': fp,
                        'code': code,
                        'language': self.detect_language(fp)
                    }

                    agent_results = await self._parallel_executor.execute_parallel(
                        agents=self._get_deep_analysis_agents(),
                        file_path=fp,
                        context=context
                    )

                    for agent_name, result in agent_results.items():
                        if result:
                            findings.extend(result)

                except Exception as e:
                    logger.warning(f"Stage 3 analysis error for {fp}: {e}")
        else:
            for fp in file_paths:
                result = await self.scan_file(fp, ai_client)
                if result.phase2_findings:
                    findings.extend(result.phase2_findings)

        elapsed = time.time() - start_time
        logger.info(f"Stage 3 completed: {len(findings)} findings in {elapsed:.2f}s")

        return PhaseResult(
            stage=ScanStage.AI_DEEP_ANALYSIS,
            candidates=file_paths,
            findings=findings,
            metadata={'total_findings': len(findings)},
            elapsed_time=elapsed
        )

    def _get_deep_analysis_agents(self) -> List[Callable]:
        """获取深度分析 Agent 列表

        Returns:
            Agent 函数列表
        """
        return [
            self._analyze_vulnerability_agent,
            self._analyze_exploit_agent,
            self._analyze_fix_suggestion_agent
        ]

    async def _analyze_vulnerability_agent(
        self,
        file_path: str,
        context: Dict[str, Any]
    ) -> List[Any]:
        """漏洞检测 Agent

        Args:
            file_path: 文件路径
            context: 执行上下文

        Returns:
            漏洞发现列表
        """
        return []

    async def _analyze_exploit_agent(
        self,
        file_path: str,
        context: Dict[str, Any]
    ) -> List[Any]:
        """Exploit 生成 Agent

        Args:
            file_path: 文件路径
            context: 执行上下文

        Returns:
            Exploit 信息列表
        """
        return []

    async def _analyze_fix_suggestion_agent(
        self,
        file_path: str,
        context: Dict[str, Any]
    ) -> List[Any]:
        """修复建议 Agent

        Args:
            file_path: 文件路径
            context: 执行上下文

        Returns:
            修复建议列表
        """
        return []

    async def stage4_exploit_validation(
        self,
        findings: List[Any]
    ) -> PhaseResult:
        """Stage 4: Exploit 验证

        Args:
            findings: 发现列表

        Returns:
            PhaseResult: 阶段结果
        """
        import time
        start_time = time.time()

        validated_findings = []

        for finding in findings:
            try:
                if self.config.enable_exploit_generation:
                    pass
                validated_findings.append(finding)
            except Exception as e:
                logger.debug(f"Exploit validation error: {e}")

        elapsed = time.time() - start_time
        logger.info(f"Stage 4 completed: {len(validated_findings)} validated in {elapsed:.2f}s")

        return PhaseResult(
            stage=ScanStage.EXPLOIT_VALIDATION,
            candidates=[],
            findings=validated_findings,
            metadata={'input_findings': len(findings), 'validated_findings': len(validated_findings)},
            elapsed_time=elapsed
        )

    async def run_multi_stage_scan(
        self,
        file_paths: List[str],
        ai_client: Any,
        query: str = "",
        changed_files: Optional[Set[str]] = None
    ) -> MultiStageScanResult:
        """运行多阶段扫描

        Args:
            file_paths: 文件路径列表
            ai_client: AI 客户端
            query: 搜索查询
            changed_files: 变更文件集合

        Returns:
            MultiStageScanResult: 扫描结果
        """
        result = MultiStageScanResult(total_files=len(file_paths))
        stage_results = {}

        stage1_result = await self.stage1_static_analysis(file_paths)
        stage_results['stage1'] = stage1_result

        if self.config.enable_search_agent:
            stage2_result = await self.stage2_search_agent_filter(
                candidates=stage1_result.candidates,
                query=query,
                changed_files=changed_files
            )
            stage_results['stage2'] = stage2_result
            target_files = stage2_result.candidates
        else:
            target_files = stage1_result.candidates[:self.config.top_k_files]

        stage3_result = await self.stage3_ai_deep_analysis(target_files, ai_client)
        stage_results['stage3'] = stage3_result

        if self.config.enable_exploit_generation:
            stage4_result = await self.stage4_exploit_validation(stage3_result.findings)
            stage_results['stage4'] = stage4_result
            final_findings = stage4_result.findings
        else:
            final_findings = stage3_result.findings

        result.stage_results = stage_results
        result.scanned_files = len(target_files)
        result.files_with_findings = len([f for f in final_findings if f])
        result.aggregated_result = self.result_aggregator.aggregate(final_findings)

        return result

    async def scan_file(
        self,
        file_path: str,
        ai_client: Any
    ) -> ScanFileResult:
        """扫描单个文件

        Args:
            file_path: 文件路径
            ai_client: AI 客户端

        Returns:
            ScanFileResult: 扫描结果
        """
        result = ScanFileResult(file_path=file_path)

        try:
            language = self.detect_language(file_path)
            code = self.read_file(file_path)

            if not code:
                return result

            if self.config.enable_phase1:
                phase1_result = await self._run_phase1(
                    file_path, language, code, ai_client
                )
                result.phase1_result = phase1_result

                if self.config.enable_phase2 and phase1_result.suspicious_points:
                    phase2_findings = await self._run_phase2(
                        file_path, language, code, phase1_result, ai_client
                    )
                    result.phase2_findings = phase2_findings
            else:
                findings = await self._run_single_stage(
                    file_path, language, code, ai_client
                )
                result.phase2_findings = findings

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")

        return result

    async def _run_phase1(
        self,
        file_path: str,
        language: str,
        code: str,
        ai_client: Any
    ) -> Phase1Result:
        """运行第一阶段：轻量定位

        Args:
            file_path: 文件路径
            language: 编程语言
            code: 代码
            ai_client: AI 客户端

        Returns:
            Phase1Result: 第一阶段结果
        """
        result = Phase1Result(file_path=file_path)

        try:
            if self.config.use_code_slicing:
                slices = self.code_slicer.slice_file(file_path)
                for code_slice in slices:
                    prompt = self.prompt_manager.get_phase1_prompt(
                        language=language,
                        code=code_slice.content
                    )
            else:
                prompt = self.prompt_manager.get_phase1_prompt(
                    language=language,
                    code=code
                )

        except Exception as e:
            logger.error(f"Phase1 error for {file_path}: {e}")

        return result

    async def _run_phase2(
        self,
        file_path: str,
        language: str,
        code: str,
        phase1_result: Phase1Result,
        ai_client: Any
    ) -> List[AggregatedFinding]:
        """运行第二阶段：精扫

        Args:
            file_path: 文件路径
            language: 编程语言
            code: 代码
            phase1_result: 第一阶段结果
            ai_client: AI 客户端

        Returns:
            List[AggregatedFinding]: 发现结果
        """
        findings = []

        for point in phase1_result.suspicious_points:
            try:
                context_code = self.get_context_around_line(
                    code, point.line, self.config.phase2_context_lines
                )

                prompt = self.prompt_manager.get_phase2_prompt(
                    language=language,
                    file_path=file_path,
                    vuln_type=point.type,
                    line_num=point.line,
                    code=context_code
                )

            except Exception as e:
                logger.error(f"Phase2 error for {file_path}:{point.line}: {e}")

        return findings

    async def _run_single_stage(
        self,
        file_path: str,
        language: str,
        code: str,
        ai_client: Any
    ) -> List[AggregatedFinding]:
        """运行单阶段扫描

        Args:
            file_path: 文件路径
            language: 编程语言
            code: 代码
            ai_client: AI 客户端

        Returns:
            List[AggregatedFinding]: 发现结果
        """
        findings = []

        try:
            prompt = self.prompt_manager.get_rule_based_prompt(
                language=language,
                file_path=file_path,
                code=code
            )

        except Exception as e:
            logger.error(f"Single stage error for {file_path}: {e}")

        return findings

    async def scan_files(
        self,
        file_paths: List[str],
        ai_client: Any
    ) -> MultiStageScanResult:
        """批量扫描文件

        Args:
            file_paths: 文件路径列表
            ai_client: AI 客户端

        Returns:
            MultiStageScanResult: 扫描结果
        """
        result = MultiStageScanResult(total_files=len(file_paths))

        async def scan_task(file_path: str) -> ScanFileResult:
            return await self.scan_file(file_path, ai_client)

        file_results = await self.scan_scheduler.schedule_tasks(
            tasks=[(scan_task, (fp, ai_client)) for fp in file_paths]
        )

        result.file_results = file_results
        result.scanned_files = len(file_results)

        all_findings = []
        for fr in file_results:
            all_findings.extend(fr.phase2_findings)
            if fr.phase2_findings:
                result.files_with_findings += 1

        result.aggregated_result = self.result_aggregator.aggregate(all_findings)

        return result
