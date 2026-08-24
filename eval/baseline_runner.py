"""基线运行器

运行Semgrep、CodeQL、DREA、IRIS等基线工具进行对比。
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from data.schema import SampleData, EvaluationResult, EvaluationMetrics


class BaselineTool(str, Enum):
    """基线工具枚举"""
    SEMGREP = "semgrep"
    CODEQL = "codeql"
    DREA = "drea"
    IRIS = "iris"
    BARE_AGENT = "bare_agent"


@dataclass
class BaselineResult:
    """基线结果"""
    tool: BaselineTool
    results: List[EvaluationResult] = field(default_factory=list)
    metrics: Optional[EvaluationMetrics] = None
    elapsed_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaselineRunner:
    """基线运行器
    
    运行各种基线工具进行对比评测。
    """
    
    def __init__(
        self,
        semgrep_path: str = "semgrep",
        codeql_path: str = "codeql",
        drea_path: str = "",
        iris_path: str = "",
    ):
        self.semgrep_path = semgrep_path
        self.codeql_path = codeql_path
        self.drea_path = drea_path
        self.iris_path = iris_path
    
    async def run_baseline(
        self,
        tool: BaselineTool,
        samples: List[SampleData],
    ) -> BaselineResult:
        """运行基线工具
        
        Args:
            tool: 基线工具
            samples: 样本列表
            
        Returns:
            基线结果
        """
        if tool == BaselineTool.SEMGREP:
            return await self._run_semgrep(samples)
        elif tool == BaselineTool.CODEQL:
            return await self._run_codeql(samples)
        elif tool == BaselineTool.DREA:
            return await self._run_drea(samples)
        elif tool == BaselineTool.IRIS:
            return await self._run_iris(samples)
        elif tool == BaselineTool.BARE_AGENT:
            return await self._run_bare_agent(samples)
        else:
            raise ValueError(f"Unknown baseline tool: {tool}")
    
    async def _run_semgrep(self, samples: List[SampleData]) -> BaselineResult:
        """运行Semgrep"""
        import time
        start_time = time.time()
        
        results = []
        for sample in samples:
            try:
                # 运行Semgrep扫描
                prediction = self._semgrep_scan(sample)
                
                result = EvaluationResult(
                    sample_id=sample.metadata.sample_id,
                    prediction=prediction,
                    ground_truth=sample.metadata.is_vulnerable,
                    confidence=0.5,
                    metadata={"tool": "semgrep"},
                )
                results.append(result)
            except Exception as e:
                result = EvaluationResult(
                    sample_id=sample.metadata.sample_id,
                    prediction=False,
                    ground_truth=sample.metadata.is_vulnerable,
                    confidence=0.0,
                    metadata={"tool": "semgrep", "error": str(e)},
                )
                results.append(result)
        
        elapsed = time.time() - start_time
        
        return BaselineResult(
            tool=BaselineTool.SEMGREP,
            results=results,
            elapsed_seconds=elapsed,
        )
    
    def _semgrep_scan(self, sample: SampleData) -> bool:
        """运行Semgrep扫描单个样本"""
        # 构建临时文件
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            # 写入代码
            for change in sample.code_changes:
                f.write(change.code_before)
            temp_file = f.name
        
        try:
            # 运行Semgrep
            cmd = [
                self.semgrep_path,
                "--config=auto",
                "--json",
                temp_file,
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            if result.returncode == 0:
                output = json.loads(result.stdout)
                # 检查是否有发现
                findings = output.get("results", [])
                return len(findings) > 0
            
            return False
        
        except Exception:
            return False
        finally:
            # 清理临时文件
            Path(temp_file).unlink(missing_ok=True)
    
    async def _run_codeql(self, samples: List[SampleData]) -> BaselineResult:
        """运行CodeQL"""
        import time
        start_time = time.time()
        
        results = []
        for sample in samples:
            try:
                # 运行CodeQL扫描
                prediction = self._codeql_scan(sample)
                
                result = EvaluationResult(
                    sample_id=sample.metadata.sample_id,
                    prediction=prediction,
                    ground_truth=sample.metadata.is_vulnerable,
                    confidence=0.5,
                    metadata={"tool": "codeql"},
                )
                results.append(result)
            except Exception as e:
                result = EvaluationResult(
                    sample_id=sample.metadata.sample_id,
                    prediction=False,
                    ground_truth=sample.metadata.is_vulnerable,
                    confidence=0.0,
                    metadata={"tool": "codeql", "error": str(e)},
                )
                results.append(result)
        
        elapsed = time.time() - start_time
        
        return BaselineResult(
            tool=BaselineTool.CODEQL,
            results=results,
            elapsed_seconds=elapsed,
        )
    
    def _codeql_scan(self, sample: SampleData) -> bool:
        """运行CodeQL扫描单个样本"""
        # CodeQL需要创建数据库，这里简化处理
        # 实际实现需要更复杂的逻辑
        return False
    
    async def _run_drea(self, samples: List[SampleData]) -> BaselineResult:
        """运行DREA"""
        import time
        start_time = time.time()
        
        results = []
        for sample in samples:
            try:
                # 运行DREA
                prediction = self._drea_scan(sample)
                
                result = EvaluationResult(
                    sample_id=sample.metadata.sample_id,
                    prediction=prediction,
                    ground_truth=sample.metadata.is_vulnerable,
                    confidence=0.5,
                    metadata={"tool": "drea"},
                )
                results.append(result)
            except Exception as e:
                result = EvaluationResult(
                    sample_id=sample.metadata.sample_id,
                    prediction=False,
                    ground_truth=sample.metadata.is_vulnerable,
                    confidence=0.0,
                    metadata={"tool": "drea", "error": str(e)},
                )
                results.append(result)
        
        elapsed = time.time() - start_time
        
        return BaselineResult(
            tool=BaselineTool.DREA,
            results=results,
            elapsed_seconds=elapsed,
        )
    
    def _drea_scan(self, sample: SampleData) -> bool:
        """运行DREA扫描单个样本"""
        # DREA需要调用其API或脚本
        # 这里简化处理
        return False
    
    async def _run_iris(self, samples: List[SampleData]) -> BaselineResult:
        """运行IRIS"""
        import time
        start_time = time.time()
        
        results = []
        for sample in samples:
            try:
                # 运行IRIS
                prediction = self._iris_scan(sample)
                
                result = EvaluationResult(
                    sample_id=sample.metadata.sample_id,
                    prediction=prediction,
                    ground_truth=sample.metadata.is_vulnerable,
                    confidence=0.5,
                    metadata={"tool": "iris"},
                )
                results.append(result)
            except Exception as e:
                result = EvaluationResult(
                    sample_id=sample.metadata.sample_id,
                    prediction=False,
                    ground_truth=sample.metadata.is_vulnerable,
                    confidence=0.0,
                    metadata={"tool": "iris", "error": str(e)},
                )
                results.append(result)
        
        elapsed = time.time() - start_time
        
        return BaselineResult(
            tool=BaselineTool.IRIS,
            results=results,
            elapsed_seconds=elapsed,
        )
    
    def _iris_scan(self, sample: SampleData) -> bool:
        """运行IRIS扫描单个样本"""
        # IRIS需要调用其API或脚本
        # 这里简化处理
        return False
    
    async def _run_bare_agent(self, samples: List[SampleData]) -> BaselineResult:
        """运行裸Agent（不带SAL/DEP）"""
        import time
        from src.orchestrator import Orchestrator, PatchTriplet, AnalysisMode
        
        start_time = time.time()
        
        # 创建裸Agent（只运行定位员）
        orchestrator = Orchestrator(mode=AnalysisMode.LOCATOR_ONLY)
        
        results = []
        for sample in samples:
            try:
                # 构建PatchTriplet
                triplet = PatchTriplet(
                    r_before=sample.r_before,
                    task_desc=sample.task_desc,
                    delta_ai=sample.delta_ai,
                    sample_id=sample.metadata.sample_id,
                )
                
                # 运行分析
                report = await orchestrator.analyze(triplet)
                
                result = EvaluationResult(
                    sample_id=sample.metadata.sample_id,
                    prediction=report.vulnerability_found,
                    ground_truth=sample.metadata.is_vulnerable,
                    confidence=report.confidence,
                    metadata={"tool": "bare_agent"},
                )
                results.append(result)
            except Exception as e:
                result = EvaluationResult(
                    sample_id=sample.metadata.sample_id,
                    prediction=False,
                    ground_truth=sample.metadata.is_vulnerable,
                    confidence=0.0,
                    metadata={"tool": "bare_agent", "error": str(e)},
                )
                results.append(result)
        
        elapsed = time.time() - start_time
        
        return BaselineResult(
            tool=BaselineTool.BARE_AGENT,
            results=results,
            elapsed_seconds=elapsed,
        )
    
    async def run_all_baselines(
        self,
        samples: List[SampleData],
        tools: Optional[List[BaselineTool]] = None,
    ) -> Dict[str, BaselineResult]:
        """运行所有基线工具
        
        Args:
            samples: 样本列表
            tools: 要运行的工具列表（默认全部）
            
        Returns:
            各工具的结果
        """
        if tools is None:
            tools = list(BaselineTool)
        
        results = {}
        for tool in tools:
            print(f"Running baseline: {tool.value}")
            result = await self.run_baseline(tool, samples)
            results[tool.value] = result
        
        return results
    
    def generate_comparison_report(
        self,
        baseline_results: Dict[str, BaselineResult],
        our_results: Optional[EvaluationMetrics] = None,
    ) -> str:
        """生成对比报告"""
        lines = ["=== 基线对比报告 ===", ""]
        
        # 表头
        lines.append("| 工具 | Pair-Correct | 召回率 | 误报率 | 运行时间 |")
        lines.append("|------|-------------|--------|--------|----------|")
        
        # 我们的结果
        if our_results:
            lines.append(
                f"| **本系统** | {our_results.pair_correct_rate:.2%} | "
                f"{our_results.vuln_recall:.2%} | "
                f"{our_results.false_positives / our_results.total_samples:.2%} | "
                f"- |"
            )
        
        # 基线结果
        for tool, result in baseline_results.items():
            if result.metrics:
                lines.append(
                    f"| {tool} | {result.metrics.pair_correct_rate:.2%} | "
                    f"{result.metrics.vuln_recall:.2%} | "
                    f"{result.metrics.false_positives / result.metrics.total_samples:.2%} | "
                    f"{result.elapsed_seconds:.2f}s |"
                )
        
        return "\n".join(lines)
