"""多阶段扫描器

集成代码切片、两阶段 Prompt、扫描调度器的完整扫描流程。
"""

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.analyzers.code_slicer import CodeSlicer
from src.ai.prompts import PromptManager, get_prompt_manager
from src.core.scan_scheduler import ScanScheduler, MultiPhaseScanner
from src.core.result_aggregator import ResultAggregator, AggregatedFinding
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class MultiStageScanConfig:
    """多阶段扫描配置"""
    enable_phase1: bool = True
    enable_phase2: bool = True
    phase1_max_tokens: int = 1024
    phase2_context_lines: int = 50
    use_code_slicing: bool = True
    max_concurrent: int = 5


@dataclass
class SuspiciousPoint:
    """可疑点"""
    line: int
    type: str
    snippet: str


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


class MultiStageScannerEngine:
    """多阶段扫描引擎"""

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

            # 第一阶段：轻量定位
            if self.config.enable_phase1:
                phase1_result = await self._run_phase1(
                    file_path, language, code, ai_client
                )
                result.phase1_result = phase1_result

                # 第二阶段：精扫
                if self.config.enable_phase2 and phase1_result.suspicious_points:
                    phase2_findings = await self._run_phase2(
                        file_path, language, code, phase1_result, ai_client
                    )
                    result.phase2_findings = phase2_findings
            else:
                # 单阶段：直接全量扫描
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
            # 使用代码切片
            if self.config.use_code_slicing:
                slices = self.code_slicer.slice_file(file_path)
                for code_slice in slices:
                    prompt = self.prompt_manager.get_phase1_prompt(
                        language=language,
                        code=code_slice.content
                    )
                    # 调用 AI 分析（需接入实际 AI 客户端）
                    # phase1_response = await ai_client.analyze(prompt)
                    # 解析响应并添加到 result.suspicious_points
                    pass
            else:
                prompt = self.prompt_manager.get_phase1_prompt(
                    language=language,
                    code=code
                )
                # 调用 AI 分析
                pass

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
                
                # 调用 AI 分析（需接入实际 AI 客户端）
                # phase2_response = await ai_client.analyze(prompt)
                # 解析响应并添加到 findings
                pass

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
            
            # 调用 AI 分析（需接入实际 AI 客户端）
            # response = await ai_client.analyze(prompt)
            # 解析响应并添加到 findings
            pass

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
        
        # 使用扫描调度器并发扫描
        async def scan_task(file_path: str) -> ScanFileResult:
            return await self.scan_file(file_path, ai_client)
        
        file_results = await self.scan_scheduler.schedule_tasks(
            tasks=[(scan_task, (fp, ai_client)) for fp in file_paths]
        )
        
        result.file_results = file_results
        result.scanned_files = len(file_results)
        
        # 聚合结果
        all_findings = []
        for fr in file_results:
            all_findings.extend(fr.phase2_findings)
            if fr.phase2_findings:
                result.files_with_findings += 1
        
        result.aggregated_result = self.result_aggregator.aggregate(all_findings)
        
        return result
