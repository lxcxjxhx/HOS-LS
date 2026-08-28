"""LLM 交互工具

包含重试生成和 JSON 响应解析。
"""

import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console

from src.ai.models import AIRequest
from src.ai.pure_ai.schema_validator import SchemaValidator
from src.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


async def generate_with_retry(
    pipeline,
    prompt: str,
    agent_name: str = "unknown",
    temperature: float = 0.0,
) -> Tuple[str, Dict[str, int]]:
    """带重试的生成（提取自 MultiAgentPipeline._generate_with_retry）

    Args:
        pipeline: MultiAgentPipeline 实例引用
        prompt: 提示词
        agent_name: Agent名称
        temperature: 温度值

    Returns:
        (生成的响应, token使用信息)
    """
    from src.ai.providers.deepseek import APIError as DeepSeekAPIError

    for i in range(pipeline.max_retries):
        try:
            json_guard_prompt = (
                "只输出JSON，否则视为失败\n\n"
                "[SYSTEM-CONTRACT-V1] 输出契约：仅输出符合 schema 的 JSON 对象；"
                "禁止 markdown 代码块、解释性文字、多余字段；必须可被 json.loads 解析。\n\n"
                + prompt
            )

            response_format = None
            json_mode = getattr(pipeline, "json_mode", "auto")
            if json_mode in ("auto", "on"):
                response_format = {"type": "json_object"}

            request = AIRequest(
                prompt=json_guard_prompt,
                model=pipeline.agent_model_overrides.get(agent_name, pipeline.model),
                temperature=temperature,
                max_tokens=8192,
                response_format=response_format,
                timeout=getattr(pipeline, "request_timeout", 180),
            )

            response = await pipeline.client.generate(request)

            token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            response_content = ""
            if hasattr(response, "usage") and response.usage:
                token_usage["prompt_tokens"] = response.usage.get("prompt_tokens", 0)
                token_usage["completion_tokens"] = response.usage.get("completion_tokens", 0)
                token_usage["total_tokens"] = response.usage.get("total_tokens", 0)

            if hasattr(response, "content"):
                response_content = response.content
            else:
                response_content = str(response)

            if pipeline.token_tracker:
                pipeline.token_tracker.track_usage(
                    provider=pipeline.client.__class__.__name__,
                    model=pipeline.model,
                    prompt_tokens=token_usage.get("prompt_tokens", 0),
                    completion_tokens=token_usage.get("completion_tokens", 0),
                    total_tokens=token_usage.get("total_tokens", 0),
                    duration=0.0,
                    success=True,
                    prompt=json_guard_prompt,
                    response=response_content,
                    agent_name=agent_name,
                    file_path=getattr(pipeline, "_current_file_path", "unknown"),
                )

            return response_content, token_usage

        except DeepSeekAPIError as e:
            logger.error(f"API错误 (Agent: {agent_name}): {e.message}")
            console.print(f"[red]API错误 (Agent: {agent_name})[/red]")
            if e.should_truncate:
                logger.error("检测到需立即截断的错误，不进行重试")
                raise
            logger.warning(f"生成失败 (Agent: {agent_name}, 尝试 {i + 1}/{pipeline.max_retries}): {e.message}")
            if i == pipeline.max_retries - 1:
                raise
            await asyncio.sleep(2)
        except Exception as e:
            logger.warning(f"生成失败 (Agent: {agent_name}, 尝试 {i + 1}/{pipeline.max_retries}): {e}")
            if i == pipeline.max_retries - 1:
                raise
            await asyncio.sleep(2)

    return "", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def parse_json_response(
    pipeline,
    response: str,
    schema_name: Optional[str] = None,
) -> Dict[str, Any]:
    """解析JSON响应（提取自 MultiAgentPipeline._parse_json_response）

    Args:
        pipeline: MultiAgentPipeline 实例引用
        response: 响应字符串
        schema_name: Schema名称

    Returns:
        解析后的JSON对象
    """

    def _ensure_schema_compliance(result: Dict[str, Any], schema_name: str) -> Dict[str, Any]:
        if schema_name == "vulnerability":
            if "vulnerabilities" not in result or not isinstance(result.get("vulnerabilities"), list):
                result["vulnerabilities"] = []
            if "signal_tracking" not in result or not isinstance(result.get("signal_tracking"), dict):
                result["signal_tracking"] = {
                    "signals_new": 0, "signals_confirmed": 0,
                    "signals_rejected": 0, "signals_refined": 0,
                }
        elif schema_name == "risk_enumeration":
            if "risks" not in result or not isinstance(result.get("risks"), list):
                result["risks"] = []
            if "signal_tracking" not in result or not isinstance(result.get("signal_tracking"), dict):
                result["signal_tracking"] = {
                    "signals_new": 0, "signals_confirmed": 0,
                    "signals_rejected": 0, "signals_refined": 0,
                }
        elif schema_name == "adversarial":
            if "adversarial_analysis" not in result or not isinstance(result.get("adversarial_analysis"), list):
                result["adversarial_analysis"] = []
            if "cross_agent_agreement" not in result or not isinstance(result.get("cross_agent_agreement"), list):
                result["cross_agent_agreement"] = []
        elif schema_name == "attack_chain":
            if "attack_chains" not in result or not isinstance(result.get("attack_chains"), list):
                result["attack_chains"] = []
            if "signal_tracking" not in result or not isinstance(result.get("signal_tracking"), dict):
                result["signal_tracking"] = {
                    "signals_new": 0, "signals_confirmed": 0,
                }
        return result

    try:
        cleaned_response = response.strip()

        try:
            data = json.loads(cleaned_response)
            if schema_name:
                validator = SchemaValidator()
                validated_data, is_valid = validator.validate_with_fallback(data, schema_name)
                result = _ensure_schema_compliance(validated_data, schema_name)
                return result
            if isinstance(data, dict):
                return data
            return {"raw_response": response, "_parse_failed": True}
        except json.JSONDecodeError:
            pass

        for end_char in ("}", "]"):
            idx = cleaned_response.rfind(end_char)
            if idx > 0:
                try:
                    candidate = cleaned_response[: idx + 1]
                    data = json.loads(candidate)
                    if isinstance(data, dict):
                        if schema_name:
                            validator = SchemaValidator()
                            validated_data, is_valid = validator.validate_with_fallback(data, schema_name)
                            return _ensure_schema_compliance(validated_data, schema_name)
                        return data
                except json.JSONDecodeError:
                    continue

        for pattern in [r"```json\s*([\s\S]*?)```", r"```\s*([\s\S]*?)```", r"\{[\s\S]*\}"]:
            json_match = re.search(pattern, cleaned_response)
            if json_match:
                json_str = json_match.group(1) if json_match.lastindex else json_match.group(0)
                try:
                    data = json.loads(json_str.strip())
                    if schema_name:
                        validator = SchemaValidator()
                        validated_data, is_valid = validator.validate_with_fallback(data, schema_name)
                        return _ensure_schema_compliance(validated_data, schema_name)
                    if isinstance(data, dict):
                        return data
                except json.JSONDecodeError:
                    continue

        # 兜底：直接取 {} 之间的内容
        first_brace = cleaned_response.find("{")
        last_brace = cleaned_response.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            json_str = cleaned_response[first_brace: last_brace + 1]
            json_str = re.sub(r"(?<!\\)\'", '"', json_str)
            json_str = re.sub(r"(\w+)\s*:", '"\1":', json_str)
            try:
                data = json.loads(json_str)
                if schema_name:
                    validator = SchemaValidator()
                    validated_data, is_valid = validator.validate_with_fallback(data, schema_name)
                    return _ensure_schema_compliance(validated_data, schema_name)
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass

        if schema_name:
            validator = SchemaValidator()
            validated_data, is_valid = validator.validate_with_fallback({"raw": response}, schema_name)
            result = _ensure_schema_compliance(validated_data, schema_name)
            result["_parse_failed"] = True
            return result

        return {"raw_response": response, "_parse_failed": True}
    except Exception as e:
        logger.warning(f"JSON解析失败: {e}")
        return {"raw_response": response, "error": str(e), "_parse_failed": True}