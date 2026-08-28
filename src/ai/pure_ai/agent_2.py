"""Agent 2：风险枚举

从 MultiAgentPipeline 提取，保留 LLM 调用（不可确定性替代）。
"""

from typing import Any, Dict, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


async def run_agent_2(
    self,
    file_path: str,
    code_understanding: Dict[str, Any],
    detected_language: str = "Unknown",
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """运行Agent 2：风险枚举

    Args:
        file_path: 文件路径
        code_understanding: 代码理解结果
        detected_language: 检测到的语言

    Returns:
        (风险枚举结果, token使用信息)
    """
    logger.debug(f" 运行Agent 2 (风险枚举) on: {file_path}")
    self.debug_logs.append(f"[DEBUG] 运行Agent 2 (风险枚举) on: {file_path}")
    structured_data = self._slim_structured_data(code_understanding)
    known_file_paths = self._file_registry.get_known_file_paths()
    prompt = self.prompt_engine.render_agent_prompt(
        "risk_enumeration",
        file_path=file_path,
        structured_data=structured_data,
        detected_language=detected_language,
        known_file_paths=known_file_paths,
    )

    response, token_usage = await self._generate_with_retry(
        prompt, "Agent 2", temperature=self.temperature
    )
    result = self._parse_json_response(response, schema_name="risk_enumeration")
    logger.debug(f" Agent 2 完成，令牌使用: {token_usage['total_tokens']}")
    self.debug_logs.append(f"[DEBUG] Agent 2 完成，令牌使用: {token_usage['total_tokens']}")
    return result, token_usage
