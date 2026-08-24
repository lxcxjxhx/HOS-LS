"""定位员Agent (Locator Agent)

基于Agent 2改造，负责从Modified_Funcs出发，找到到Sink的路径。
复用Agent 2的框架，修改prompt以适应差分漏洞验证场景。
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.sal.sink_registry import SinkRegistry, SinkDefinition
from src.sal.path_explorer import SALExplorer, CandidatePath, CallGraph


@dataclass
class LocatorResult:
    """定位员结果"""
    candidate_paths: List[CandidatePath] = field(default_factory=list)
    modified_functions: List[str] = field(default_factory=list)
    sink_matches: Dict[str, List[str]] = field(default_factory=dict)
    token_usage: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_paths": [p.to_dict() for p in self.candidate_paths],
            "modified_functions": self.modified_functions,
            "sink_matches": self.sink_matches,
            "token_usage": self.token_usage,
            "metadata": self.metadata,
        }


class LocatorAgent:
    """定位员Agent
    
    从Modified_Funcs出发，探索到Sink的路径。
    复用Agent 2的框架，但专注于路径定位而非风险枚举。
    """
    
    def __init__(
        self,
        llm_client=None,
        sink_registry: Optional[SinkRegistry] = None,
        sal_explorer: Optional[SALExplorer] = None,
    ):
        self.llm_client = llm_client
        self.sink_registry = sink_registry or SinkRegistry()
        self.sal_explorer = sal_explorer or SALExplorer(self.sink_registry)
    
    async def locate_paths(
        self,
        modified_funcs: List[str],
        r_before: str,
        r_after: str,
        delta_ai: str,
        task_desc: str = "",
        language: str = "python",
    ) -> LocatorResult:
        """定位从Modified_Funcs到Sink的路径
        
        Args:
            modified_funcs: 修改的函数列表
            r_before: 改前仓库路径
            r_after: 改后仓库路径
            delta_ai: AI生成的补丁
            task_desc: 任务描述
            language: 编程语言
            
        Returns:
            定位结果
        """
        # Step 1: 构建调用图（改后版本）
        call_graph = self._build_call_graph(r_after, language)
        
        # Step 2: 使用SAL探索路径
        candidate_paths = self.sal_explorer.explore_paths(
            modified_funcs, call_graph
        )
        
        # Step 3: 使用LLM增强路径分析（可选）
        if self.llm_client and task_desc:
            enhanced_paths = await self._llm_enhance_paths(
                candidate_paths, modified_funcs, task_desc, r_after, delta_ai
            )
            candidate_paths = enhanced_paths
        
        # Step 4: 构建Sink匹配信息
        sink_matches = self._build_sink_matches(candidate_paths)
        
        return LocatorResult(
            candidate_paths=candidate_paths,
            modified_functions=modified_funcs,
            sink_matches=sink_matches,
            metadata={
                "r_before": r_before,
                "r_after": r_after,
                "language": language,
                "task_desc": task_desc,
            }
        )
    
    def _build_call_graph(self, repo_path: str, language: str) -> CallGraph:
        """构建调用图
        
        这里需要集成tree-sitter来构建调用图。
        暂时返回空图，实际实现需要调用CFGBuilder。
        """
        # TODO: 集成tree-sitter调用图构建
        return CallGraph()
    
    async def _llm_enhance_paths(
        self,
        paths: List[CandidatePath],
        modified_funcs: List[str],
        task_desc: str,
        repo_path: str,
        delta_ai: str,
    ) -> List[CandidatePath]:
        """使用LLM增强路径分析
        
        让LLM分析补丁意图，识别可能的安全影响。
        """
        if not self.llm_client:
            return paths
        
        # 构建prompt
        prompt = self._build_enhancement_prompt(
            paths, modified_funcs, task_desc, delta_ai
        )
        
        try:
            # 调用LLM
            response = await self.llm_client.generate(prompt)
            
            # 解析LLM响应，增强路径信息
            enhanced = self._parse_llm_response(response, paths)
            
            return enhanced
        except Exception as e:
            # LLM调用失败，返回原始路径
            return paths
    
    def _build_enhancement_prompt(
        self,
        paths: List[CandidatePath],
        modified_funcs: List[str],
        task_desc: str,
        delta_ai: str,
    ) -> str:
        """构建LLM增强prompt"""
        paths_desc = "\n".join([
            f"- 路径 {i+1}: {p.entry_point} -> {' -> '.join(p.call_chain)} -> {p.sink}"
            for i, p in enumerate(paths[:10])  # 限制路径数量
        ])
        
        return f"""你是一个安全分析专家。请分析以下AI生成的代码补丁，评估其安全影响。

## 任务描述
{task_desc}

## 修改的函数
{', '.join(modified_funcs)}

## AI生成的补丁
```diff
{delta_ai[:2000]}
```

## 已发现的候选路径
{paths_desc}

## 分析要求
1. 评估每个候选路径的安全风险
2. 识别补丁可能引入的新攻击路径
3. 检查是否有跨文件契约违背
4. 评估路径的可达性和可利用性

## 输出格式
请以JSON格式输出，包含：
- "risk_assessment": 风险评估
- "new_paths": 新发现的路径（如果有）
- "warnings": 安全警告
"""
    
    def _parse_llm_response(
        self, response: str, original_paths: List[CandidatePath]
    ) -> List[CandidatePath]:
        """解析LLM响应"""
        try:
            result = json.loads(response)
            
            # 如果LLM发现了新路径，添加到列表中
            new_paths = result.get("new_paths", [])
            for new_path in new_paths:
                if isinstance(new_path, dict):
                    # 将LLM发现的路径转换为CandidatePath
                    candidate = CandidatePath(
                        entry_point=new_path.get("entry_point", "unknown"),
                        sink=new_path.get("sink", "unknown"),
                        call_chain=new_path.get("call_chain", []),
                        modified_functions=new_path.get("modified_functions", []),
                        files_involved=new_path.get("files_involved", []),
                        confidence=new_path.get("confidence", 0.5),
                    )
                    original_paths.append(candidate)
            
            return original_paths
        except Exception:
            return original_paths
    
    def _build_sink_matches(
        self, paths: List[CandidatePath]
    ) -> Dict[str, List[str]]:
        """构建Sink匹配信息"""
        matches = {}
        
        for path in paths:
            sink = path.sink
            if sink not in matches:
                matches[sink] = []
            
            # 添加路径中的函数
            for func in path.call_chain:
                if func not in matches[sink]:
                    matches[sink].append(func)
        
        return matches
    
    def get_sink_info_for_prompt(self, language: str = "python") -> str:
        """获取Sink信息供Prompt使用"""
        return self.sink_registry.export_for_prompt(language)
