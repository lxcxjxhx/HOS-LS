"""JSON 解析工具模块

提供统一的 JSON 解析、提取和修复功能，
消除 multi_agent_pipeline.py 和 schema_validator.py 中的重复代码。
"""

import json
import re
from typing import Any, Dict, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """从文本中提取 JSON 对象

    支持从 markdown 代码块、混合文本中提取 JSON。

    Args:
        text: 包含 JSON 的文本

    Returns:
        解析后的 dict，失败返回 None
    """
    if not text or not isinstance(text, str):
        return None

    # 第1层: 直接解析
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, TypeError):
        pass

    # 第2层: 提取 ```json ``` 代码块
    json_block = re.search(r'```json\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if json_block:
        try:
            result = json.loads(json_block.group(1))
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, TypeError):
            pass

    # 第3层: 提取 ``` ``` 代码块
    code_block = re.search(r'```\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if code_block:
        try:
            result = json.loads(code_block.group(1))
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, TypeError):
            pass

    # 第4层: 正则匹配 {…}
    brace_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
    if brace_match:
        try:
            result = json.loads(brace_match.group())
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, TypeError):
            pass

    # 第5层: 首尾花括号截取
    first_brace = text.find('{')
    last_brace = text.rfind('}')
    if first_brace != -1 and last_brace > first_brace:
        try:
            result = json.loads(text[first_brace:last_brace + 1])
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, TypeError):
            pass

    return None


def safe_json_parse(
    text: str, schema_name: str = "", fallback: Optional[Dict] = None
) -> Tuple[Dict[str, Any], bool]:
    """安全解析 JSON，带标记

    Args:
        text: 待解析的文本
        schema_name: Schema 名称（用于日志）
        fallback: 解析失败时的兜底值

    Returns:
        (parsed_data, parse_failed) - 解析结果和是否失败
    """
    result = extract_json_from_text(text)

    if result is not None:
        return result, False

    # 解析失败
    if schema_name:
        logger.warning(f"[{schema_name}] JSON 所有解析层失败，使用兜底数据")

    if fallback is None:
        fallback = {"raw_response": text}

    fallback["_parse_failed"] = True
    return fallback, True
