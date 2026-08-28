"""Agent 0：上下文构建

从 MultiAgentPipeline 提取，保留 LLM 调用（不可确定性替代）。
"""

from typing import Any, Dict, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


async def run_agent_0(
    self,
    file_path: str,
    context: Dict[str, Any],
    detected_language: str = "Unknown",
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """运行Agent 0：上下文构建

    Args:
        file_path: 文件路径
        context: 上下文信息
        detected_language: 检测到的语言

    Returns:
        (上下文分析结果, token使用信息)
    """
    logger.debug(f" 运行Agent 0 (上下文构建) on: {file_path}")
    self.debug_logs.append(f"[DEBUG] 运行Agent 0 (上下文构建) on: {file_path}")
    # [OPT-COMPACT] 代码压缩：函数骨架摘要（签名+文档首行）注入 function_calls 通道
    skeleton_summary = ""
    if getattr(self, "compaction_enabled", False):
        try:
            structure = context.get("file_structure") or {}
            funcs = structure.get("functions") or []
            lines = []
            for f in funcs[:30]:
                args = ",".join(str(a) for a in (f.get("args") or [])[:6])
                doc = str(f.get("docstring") or "").strip().splitlines()
                doc1 = doc[0][:60] if doc else ""
                lines.append(f"{f.get('name')}({args})  # L{f.get('line')} {doc1}")
            if lines:
                skeleton_summary = "\n".join(["# [函数骨架摘要]"] + lines)
        except Exception as e:
            logger.debug(f"[OPT-COMPACT] 骨架构建失败: {e}")
    from src.ai.prompt_engine import PromptEngine

    function_calls_text = PromptEngine.format_function_calls(
        context.get("function_calls", [])
    )
    if skeleton_summary:
        function_calls_text = skeleton_summary + "\n" + function_calls_text
    prompt = self.prompt_engine.render_agent_prompt(
        "context_builder",
        file_path=file_path,
        file_content=context["file_content"],
        related_files=PromptEngine.format_related_files(context.get("related_files", [])),
        imports=PromptEngine.format_imports(context.get("imports", [])),
        function_calls=function_calls_text,
        detected_language=detected_language,
    )

    response, token_usage = await self._generate_with_retry(
        prompt, "Agent 0", temperature=self.temperature
    )
    result = self._parse_json_response(response, schema_name="context_analysis")
    logger.debug(f" Agent 0 完成，令牌使用: {token_usage['total_tokens']}")
    self.debug_logs.append(f"[DEBUG] Agent 0 完成，令牌使用: {token_usage['total_tokens']}")
    return result, token_usage
