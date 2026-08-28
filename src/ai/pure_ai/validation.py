"""验证模块

从 MultiAgentPipeline 中提取的验证方法。
"""

from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


def validate_final_findings(pipeline, final_findings, agent_6_result, agent_5_result):
    return pipeline._validate_final_findings(final_findings, agent_6_result, agent_5_result)


def check_agent3_agent6_consistency(pipeline, agent_3_result, agent_6_result):
    return pipeline._check_agent3_agent6_consistency(agent_3_result, agent_6_result)


def validate_result_consistency(pipeline, findings, agent_1_result, agent_2_result):
    return pipeline._validate_result_consistency(findings, agent_1_result, agent_2_result)


def verify_location_exists(pipeline, finding, confidence):
    return pipeline._verify_location_exists(finding, confidence)