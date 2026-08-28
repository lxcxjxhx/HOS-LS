"""Agent 1：代码理解

从 MultiAgentPipeline 提取，保留 LLM 调用（不可确定性替代）。
"""

import json
from typing import Any, Dict, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


async def run_agent_1(
    self,
    file_path: str,
    context: Dict[str, Any],
    context_analysis: Dict[str, Any],
    detected_language: str = "Unknown",
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """运行Agent 1：代码理解

    Args:
        file_path: 文件路径
        context: 上下文信息
        context_analysis: 上下文分析结果
        detected_language: 检测到的语言

    Returns:
        (代码理解结果, token使用信息)
    """
    logger.debug(f" 运行Agent 1 (代码理解) on: {file_path}")
    self.debug_logs.append(f"[DEBUG] 运行Agent 1 (代码理解) on: {file_path}")
    context_info = json.dumps(context_analysis, ensure_ascii=False)
    prompt = self.prompt_engine.render_agent_prompt(
        "code_understanding",
        file_path=file_path,
        file_content=context["file_content"],
        context_info=context_info,
        detected_language=detected_language,
    )

    response, token_usage = await self._generate_with_retry(
        prompt, "Agent 1", temperature=self.temperature
    )
    result = self._parse_json_response(response, schema_name="code_understanding")
    logger.debug(f" Agent 1 完成，令牌使用: {token_usage['total_tokens']}")
    self.debug_logs.append(f"[DEBUG] Agent 1 完成，令牌使用: {token_usage['total_tokens']}")
    return result, token_usage
