"""差分员Agent (Differ Agent)

全新Agent，负责对比改前改后的路径图，标记Suspicious路径。
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.dep.differ import PathDiffer, SuspiciousPath, DiffReason
from src.sal.path_explorer import CandidatePath, CallGraph


@dataclass
class DifferResult:
    """差分员结果"""
    suspicious_paths: List[SuspiciousPath] = field(default_factory=list)
    diff_report: Dict[str, Any] = field(default_factory=dict)
    token_usage: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "suspicious_paths": [s.to_dict() for s in self.suspicious_paths],
            "diff_report": self.diff_report,
            "token_usage": self.token_usage,
            "metadata": self.metadata,
        }


class DifferAgent:
    """差分员Agent
    
    对比改前改后的路径图，标记Suspicious路径。
    这是全新Agent，没有直接可复用的现有Agent。
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.path_differ = PathDiffer()
    
    async def diff_paths(
        self,
        paths_before: List[CandidatePath],
        paths_after: List[CandidatePath],
        modified_funcs: List[str],
        r_before: str,
        r_after: str,
        delta_ai: str,
        task_desc: str = "",
    ) -> DifferResult:
        """对比前后路径，标记Suspicious
        
        Args:
            paths_before: 改前路径列表
            paths_after: 改后路径列表
            modified_funcs: 修改的函数列表
            r_before: 改前仓库路径
            r_after: 改后仓库路径
            delta_ai: AI生成的补丁
            task_desc: 任务描述
            
        Returns:
            差分结果
        """
        # Step 1: 使用PathDiffer进行路径对比
        suspicious_paths = self.path_differ.diff_paths(
            paths_before, paths_after, modified_funcs
        )
        
        # Step 2: 使用LLM增强差分分析（可选）
        if self.llm_client and task_desc:
            enhanced_suspicious = await self._llm_enhance_diff(
                suspicious_paths, paths_before, paths_after,
                modified_funcs, task_desc, delta_ai
            )
            suspicious_paths = enhanced_suspicious
        
        # Step 3: 构建差分报告
        diff_report = self._build_diff_report(
            paths_before, paths_after, suspicious_paths
        )
        
        return DifferResult(
            suspicious_paths=suspicious_paths,
            diff_report=diff_report,
            metadata={
                "r_before": r_before,
                "r_after": r_after,
                "modified_funcs": modified_funcs,
                "task_desc": task_desc,
            }
        )
    
    async def _llm_enhance_diff(
        self,
        suspicious_paths: List[SuspiciousPath],
        paths_before: List[CandidatePath],
        paths_after: List[CandidatePath],
        modified_funcs: List[str],
        task_desc: str,
        delta_ai: str,
    ) -> List[SuspiciousPath]:
        """使用LLM增强差分分析"""
        if not self.llm_client:
            return suspicious_paths
        
        # 构建prompt
        prompt = self._build_diff_prompt(
            suspicious_paths, paths_before, paths_after,
            modified_funcs, task_desc, delta_ai
        )
        
        try:
            # 调用LLM
            response = await self.llm_client.generate(prompt)
            
            # 解析LLM响应
            enhanced = self._parse_llm_response(response, suspicious_paths)
            
            return enhanced
        except Exception as e:
            # LLM调用失败，返回原始结果
            return suspicious_paths
    
    def _build_diff_prompt(
        self,
        suspicious_paths: List[SuspiciousPath],
        paths_before: List[CandidatePath],
        paths_after: List[CandidatePath],
        modified_funcs: List[str],
        task_desc: str,
        delta_ai: str,
    ) -> str:
        """构建LLM增强prompt"""
        suspicious_desc = "\n".join([
            f"- {s.reason.value}: {s.description}"
            for s in suspicious_paths[:10]
        ])
        
        return f"""你是一个安全分析专家。请分析以下路径差异，评估AI补丁的安全影响。

## 任务描述
{task_desc}

## 修改的函数
{', '.join(modified_funcs)}

## AI生成的补丁
```diff
{delta_ai[:2000]}
```

## 改前路径数量
{len(paths_before)}

## 改后路径数量
{len(paths_after)}

## 发现的可疑路径
{suspicious_desc}

## 分析要求
1. 评估每个可疑路径的安全风险
2. 检查是否有跨文件契约违背
3. 识别可能的攻击向量
4. 评估漏洞的可利用性

## 输出格式
请以JSON格式输出，包含：
- "risk_assessment": 风险评估
- "additional_suspicious": 新发现的可疑路径（如果有）
- "false_positives": 可能是误报的路径（如果有）
"""
    
    def _parse_llm_response(
        self, response: str, original_suspicious: List[SuspiciousPath]
    ) -> List[SuspiciousPath]:
        """解析LLM响应"""
        try:
            result = json.loads(response)
            
            # 如果LLM发现了新的可疑路径，添加到列表中
            additional = result.get("additional_suspicious", [])
            for item in additional:
                if isinstance(item, dict):
                    # 将LLM发现的路径转换为SuspiciousPath
                    # 这里需要更复杂的转换逻辑
                    pass
            
            # 如果LLM标记了误报，可以从列表中移除
            # 注意：这里只是标记，实际移除需要更谨慎
            
            return original_suspicious
        except Exception:
            return original_suspicious
    
    def _build_diff_report(
        self,
        paths_before: List[CandidatePath],
        paths_after: List[CandidatePath],
        suspicious_paths: List[SuspiciousPath],
    ) -> Dict[str, Any]:
        """构建差分报告"""
        # 按原因分类统计
        reason_counts = {}
        for s in suspicious_paths:
            reason = s.reason.value
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        
        # 按Sink分类统计
        sink_counts = {}
        for s in suspicious_paths:
            sink = s.path.sink
            sink_counts[sink] = sink_counts.get(sink, 0) + 1
        
        return {
            "paths_before_count": len(paths_before),
            "paths_after_count": len(paths_after),
            "suspicious_count": len(suspicious_paths),
            "reason_counts": reason_counts,
            "sink_counts": sink_counts,
            "high_confidence_count": sum(
                1 for s in suspicious_paths if s.confidence >= 0.7
            ),
        }
