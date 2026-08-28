"""Agent 运行器包装

使用代理模式包装 MultiAgentPipeline 的 Agent 方法。
"""

from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


class AgentRunner:
    """Agent 方法包装器"""

    def __init__(self, pipeline):
        self._p = pipeline

    async def run_agent_0(self, file_path, context, detected_language='Unknown'):
        return await self._p._run_agent_0(file_path, context, detected_language)

    async def run_agent_1(self, file_path, agent_0_result, agent_1_context, language):
        return await self._p._run_agent_1(file_path, agent_0_result, agent_1_context, language)

    async def run_agent_2(self, file_path, agent_1_results, context, language):
        return await self._p._run_agent_2(file_path, agent_1_results, context, language)

    async def run_agent_3(self, file_path, agent_2_result, context, language, signals):
        return await self._p._run_agent_3(file_path, agent_2_result, context, language, signals)

    async def run_agent_4(self, file_path, agent_3_result, context, language, signals):
        return await self._p._run_agent_4(file_path, agent_3_result, context, language, signals)

    async def run_agent_5(self, file_path, findings, agent_4_result, context, language, signals):
        return await self._p._run_agent_5(file_path, findings, agent_4_result, context, language, signals)

    async def run_agent_6(self, file_path, all_findings, context, signals):
        return await self._p._run_agent_6(file_path, all_findings, context, signals)