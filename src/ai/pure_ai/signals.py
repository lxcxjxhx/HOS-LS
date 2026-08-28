"""信号追踪模块

从 MultiAgentPipeline 中提取的信号追踪方法。
"""

from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


async def track_risk_signals(pipeline, file_path, context, agent_2_result, agent_3_result):
    return await pipeline._track_risk_signals(file_path, context, agent_2_result, agent_3_result)


async def track_verification_signals(pipeline, file_path, context, agent_2_result, agent_3_result):
    return await pipeline._track_verification_signals(file_path, context, agent_2_result, agent_3_result)


def match_unverified_signals(pipeline, signals, findings):
    return pipeline._match_unverified_signals(signals, findings)


def check_semantic_consistency(pipeline, agent_1_result, agent_2_result, context):
    return pipeline._check_semantic_consistency(agent_1_result, agent_2_result, context)


def fill_missing_signals_via_refinement(pipeline, file_path, context, detected_language):
    return pipeline._fill_missing_signals_via_refinement(file_path, context, detected_language)


def get_signal_summary(pipeline):
    return pipeline._get_signal_summary()