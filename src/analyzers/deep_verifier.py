import asyncio
import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.analyzers.tiered_types import TierDecision, TieredAnalysisResult, TierResult
from src.utils.logger import get_logger

logger = get_logger(__name__)



class DeepVerifier:
    """Tier 3 深度验证器

    模拟多智能体共识验证流程：
    1. 数据流分析智能体 - 追踪污点数据流
    2. 跨文件上下文智能体 - 分析调用链和依赖关系
    3. 攻击链构建智能体 - 构建完整的攻击路径
    4. 仲裁智能体 - 汇总各智能体结论，做出最终判定
    """

    # 各"虚拟智能体"的系统提示词
    AGENT_PROMPTS: Dict[str, str] = {
        "data_flow": (
            "你是数据流分析智能体。请追踪以下代码中用户可控数据（source）到敏感操作（sink）的完整数据流路径。\n"
            "分析要点：\n"
            "1. 识别所有外部输入点（HTTP参数、文件读取、数据库查询结果等）\n"
            "2. 追踪数据在函数间、变量间的传播路径\n"
            "3. 检查路径上是否存在有效的净化/过滤/校验操作\n"
            "4. 判断数据是否最终到达危险操作（SQL执行、命令执行、文件写入等）\n"
            "以JSON格式返回: {\"has_taint_flow\": bool, \"flow_paths\": [{\"source\": str, \"sink\": str, "
            "\"sanitizers\": [str], \"path_length\": int}], \"confidence\": float, \"explanation\": str}"
        ),
        "cross_file": (
            "你是跨文件上下文分析智能体。请分析以下代码在其调用上下文中的安全性。\n"
            "分析要点：\n"
            "1. 该函数/方法被谁调用？调用者是否做了安全检查？\n"
            "2. 该代码依赖的外部模块/类是否有已知的安全问题？\n"
            "3. 框架级别的安全机制（如中间件、拦截器）是否覆盖了这段代码？\n"
            "4. 配置文件中是否有相关的安全设置？\n"
            "以JSON格式返回: {\"context_risk_level\": str, \"caller_chain\": [str], "
            "\"framework_protections\": [str], \"confidence\": float, \"explanation\": str}"
        ),
        "attack_chain": (
            "你是攻击链构建智能体。请基于以下代码漏洞信息，构建一个完整的攻击场景。\n"
            "分析要点：\n"
            "1. 攻击入口点（Entry Point）\n"
            "2. 攻击者需要满足的前置条件（认证、权限等）\n"
            "3. 攻击载荷的构造方式\n"
            "4. 攻击成功后的影响范围（数据泄露、权限提升、RCE等）\n"
            "5. CVSS 3.1 评分估计\n"
            "以JSON格式返回: {\"attack_feasible\": bool, \"entry_point\": str, "
            "\"preconditions\": [str], \"payload_example\": str, \"impact\": str, "
            "\"cvss_estimate\": float, \"confidence\": float, \"explanation\": str}"
        ),
        "arbiter": (
            "你是仲裁智能体。你将收到来自数据流分析、跨文件上下文分析、攻击链构建三个智能体的报告。\n"
            "请综合所有证据，做出最终判定。\n"
            "判定标准：\n"
            "- 至少2个智能体确认漏洞存在，且平均置信度 > 0.6 -> 最终确认\n"
            "- 所有智能体均否定 -> 最终排除\n"
            "- 其他情况 -> 标记为待人工审查\n"
            "以JSON格式返回: {\"final_verdict\": str (CONFIRM/REJECT/REVIEW), "
            "\"final_confidence\": float, \"consensus_level\": str (STRONG/MODERATE/WEAK), "
            "\"key_evidence\": [str], \"recommendation\": str}"
        ),
    }

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        ai_client: Optional[Any] = None,
    ) -> None:
        """初始化深度验证器

        Args:
            config: 可选配置
            ai_client: AI客户端实例
        """
        self._config = config or {}
        self._ai_client = ai_client
        self._semaphore: Optional[asyncio.Semaphore] = None
        # 多智能体并发数（默认3个智能体并行）
        self._agent_concurrency: int = self._config.get("agent_concurrency", 3)

    def set_semaphore(self, semaphore: asyncio.Semaphore) -> None:
        """设置并发信号量"""
        self._semaphore = semaphore

    async def verify(
        self,
        file_path: Path,
        file_content: str,
        tier1_findings: List[Dict[str, Any]],
        tier2_findings: List[Dict[str, Any]],
    ) -> TierResult:
        """执行深度验证

        Args:
            file_path: 文件路径
            file_content: 文件内容
            tier1_findings: Tier 1 发现
            tier2_findings: Tier 2 发现

        Returns:
            TierResult: 深度验证结果
        """
        start_time = time.perf_counter()
        total_tokens = 0

        # 截断文件内容
        truncated_content = file_content[:20000]

        # ---- 阶段1: 三个分析智能体并行执行 ----
        agent_tasks = {
            "data_flow": self._run_agent(
                "data_flow", file_path, truncated_content,
                tier1_findings, tier2_findings,
            ),
            "cross_file": self._run_agent(
                "cross_file", file_path, truncated_content,
                tier1_findings, tier2_findings,
            ),
            "attack_chain": self._run_agent(
                "attack_chain", file_path, truncated_content,
                tier1_findings, tier2_findings,
            ),
        }

        # 并行执行三个智能体
        agent_results = await asyncio.gather(
            *agent_tasks.values(), return_exceptions=True
        )

        # 收集结果
        agent_reports: Dict[str, Optional[Dict[str, Any]]] = {}
        for agent_name, result in zip(agent_tasks.keys(), agent_results):
            if isinstance(result, Exception):
                logger.warning(f"Tier 3 智能体 [{agent_name}] 执行失败: {result}")
                agent_reports[agent_name] = None
            elif isinstance(result, tuple):
                report, tokens = result
                total_tokens += tokens
                agent_reports[agent_name] = report
            else:
                agent_reports[agent_name] = None

        # ---- 阶段2: 仲裁智能体汇总 ----
        arbiter_result, arbiter_tokens = await self._run_arbiter(
            file_path, agent_reports, tier1_findings, tier2_findings
        )
        total_tokens += arbiter_tokens

        # ---- 阶段3: 构建最终结果 ----
        confidence, findings, decision = self._compile_final_result(
            arbiter_result, agent_reports
        )

        elapsed = (time.perf_counter() - start_time) * 1000

        return TierResult(
            tier=3,
            decision=decision.value,
            confidence=confidence,
            findings=findings,
            elapsed_ms=elapsed,
            token_cost=total_tokens,
        )

    async def _run_agent(
        self,
        agent_name: str,
        file_path: Path,
        content: str,
        tier1_findings: List[Dict[str, Any]],
        tier2_findings: List[Dict[str, Any]],
    ) -> Tuple[Optional[Dict[str, Any]], int]:
        """运行单个分析智能体

        Args:
            agent_name: 智能体名称
            file_path: 文件路径
            content: 文件内容
            tier1_findings: Tier 1 发现
            tier2_findings: Tier 2 发现

        Returns:
            (智能体报告字典, token消耗)
        """
        if self._ai_client is None:
            return None, 0

        try:
            from src.ai.models import AIRequest
        except ImportError:
            return None, 0

        system_prompt = self.AGENT_PROMPTS.get(agent_name, self.AGENT_PROMPTS["arbiter"])
        user_prompt = self._build_agent_prompt(agent_name, file_path, content, tier1_findings, tier2_findings)

        request = AIRequest(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.2,
            max_tokens=3072,
        )

        try:
            if self._semaphore is not None:
                async with self._semaphore:
                    response = await self._ai_client.generate_with_retry(request)
            else:
                response = await self._ai_client.generate_with_retry(request)

            tokens = response.usage.get("total_tokens", 0) if response.usage else 0
            parsed = self._parse_json_response(response.content)
            return parsed, tokens
        except Exception as exc:
            logger.warning(f"Tier 3 智能体 [{agent_name}] LLM调用失败: {exc}")
            return None, 0

    async def _run_arbiter(
        self,
        file_path: Path,
        agent_reports: Dict[str, Optional[Dict[str, Any]]],
        tier1_findings: List[Dict[str, Any]],
        tier2_findings: List[Dict[str, Any]],
    ) -> Tuple[Optional[Dict[str, Any]], int]:
        """运行仲裁智能体

        Args:
            file_path: 文件路径
            agent_reports: 各分析智能体的报告
            tier1_findings: Tier 1 发现
            tier2_findings: Tier 2 发现

        Returns:
            (仲裁结果, token消耗)
        """
        if self._ai_client is None:
            return None, 0

        try:
            from src.ai.models import AIRequest
        except ImportError:
            return None, 0

        # 构建仲裁提示词
        reports_summary = self._format_agent_reports(agent_reports)
        t1_summary = self._format_findings_summary(tier1_findings, "Tier 1")
        t2_summary = self._format_findings_summary(tier2_findings, "Tier 2")

        user_prompt = (
            f"## 文件路径\n`{file_path}`\n\n"
            f"## 前序分析结果\n{t1_summary}\n{t2_summary}\n\n"
            f"## 多智能体分析报告\n{reports_summary}\n\n"
            "请综合以上所有证据，做出最终裁定。"
        )

        request = AIRequest(
            prompt=user_prompt,
            system_prompt=self.AGENT_PROMPTS["arbiter"],
            temperature=0.1,
            max_tokens=2048,
        )

        try:
            if self._semaphore is not None:
                async with self._semaphore:
                    response = await self._ai_client.generate_with_retry(request)
            else:
                response = await self._ai_client.generate_with_retry(request)

            tokens = response.usage.get("total_tokens", 0) if response.usage else 0
            parsed = self._parse_json_response(response.content)
            return parsed, tokens
        except Exception as exc:
            logger.warning(f"Tier 3 仲裁智能体调用失败: {exc}")
            return None, 0

    def _build_agent_prompt(
        self,
        agent_name: str,
        file_path: Path,
        content: str,
        tier1_findings: List[Dict[str, Any]],
        tier2_findings: List[Dict[str, Any]],
    ) -> str:
        """为特定智能体构建提示词

        Args:
            agent_name: 智能体名称
            file_path: 文件路径
            content: 文件内容
            tier1_findings: Tier 1 发现
            tier2_findings: Tier 2 发现

        Returns:
            格式化的提示词
        """
        lang = AIAssistedAnalyzer._guess_language(file_path)
        parts = [f"## 文件路径\n`{file_path}`\n"]

        # 前序发现
        all_findings = tier1_findings + tier2_findings
        if all_findings:
            parts.append("## 前序分析发现\n")
            for i, f in enumerate(all_findings[:15], 1):
                desc = f.get("description", f.get("explanation", "未知"))
                parts.append(f"{i}. {desc}")
            parts.append("")

        parts.append(f"## 代码内容\n```{lang}\n{content}\n```\n")

        # 智能体特定指令
        if agent_name == "data_flow":
            parts.append("请重点分析数据流路径，追踪从source到sink的完整链路。")
        elif agent_name == "cross_file":
            parts.append("请重点分析该代码在项目上下文中的安全性，考虑调用链和框架保护。")
        elif agent_name == "attack_chain":
            parts.append("请重点构建攻击场景，评估漏洞的实际可利用性。")

        return "\n".join(parts)

    def _parse_json_response(self, content: str) -> Optional[Dict[str, Any]]:
        """解析LLM的JSON响应

        Args:
            content: LLM返回的文本

        Returns:
            解析后的字典或None
        """
        if not content:
            return None

        json_match = re.search(r"```json\s*(.*?)\s*```", content, re.DOTALL)
        json_str = json_match.group(1) if json_match else content.strip()

        try:
            return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            logger.debug(f"Tier 3: JSON解析失败，内容前100字符: {content[:100]}")
            return None

    def _format_agent_reports(self, reports: Dict[str, Optional[Dict[str, Any]]]) -> str:
        """格式化各智能体报告为可读文本

        Args:
            reports: 智能体名称到报告的映射

        Returns:
            格式化文本
        """
        parts: List[str] = []
        name_map = {
            "data_flow": "数据流分析智能体",
            "cross_file": "跨文件上下文智能体",
            "attack_chain": "攻击链构建智能体",
        }
        for agent_name, report in reports.items():
            display_name = name_map.get(agent_name, agent_name)
            if report:
                parts.append(f"### {display_name}\n```json\n{json.dumps(report, ensure_ascii=False, indent=2)}\n```")
            else:
                parts.append(f"### {display_name}\n（未返回有效报告）")
        return "\n\n".join(parts)

    def _format_findings_summary(self, findings: List[Dict[str, Any]], label: str) -> str:
        """格式化发现列表

        Args:
            findings: 发现列表
            label: 标签名

        Returns:
            格式化文本
        """
        if not findings:
            return f"### {label}\n（无发现）"

        parts = [f"### {label} ({len(findings)} 条发现)\n"]
        for i, f in enumerate(findings[:10], 1):
            desc = f.get("description", f.get("explanation", ""))
            conf = f.get("confidence", f.get("severity", 0))
            parts.append(f"{i}. {desc} (置信度/严重度: {conf})")
        return "\n".join(parts)

    def _compile_final_result(
        self,
        arbiter_result: Optional[Dict[str, Any]],
        agent_reports: Dict[str, Optional[Dict[str, Any]]],
    ) -> Tuple[float, List[Dict[str, Any]], TierDecision]:
        """汇总最终结果

        Args:
            arbiter_result: 仲裁智能体的结果
            agent_reports: 各分析智能体的报告

        Returns:
            (最终置信度, 发现列表, 决策)
        """
        findings: List[Dict[str, Any]] = []

        if arbiter_result is None:
            # 仲裁失败，基于各智能体报告做降级判定
            return self._fallback_verdict(agent_reports)

        verdict = arbiter_result.get("final_verdict", "REVIEW").upper()
        confidence = float(arbiter_result.get("final_confidence", 0.5))
        consensus = arbiter_result.get("consensus_level", "WEAK")
        key_evidence = arbiter_result.get("key_evidence", [])
        recommendation = arbiter_result.get("recommendation", "")

        # 构建最终发现
        findings.append({
            "rule_id": "TIER3-DEEP-VERIFY",
            "description": "深度验证结果",
            "verdict": verdict,
            "confidence": confidence,
            "consensus_level": consensus,
            "key_evidence": key_evidence,
            "recommendation": recommendation,
            "agent_reports": {
                name: report for name, report in agent_reports.items() if report
            },
            "source": "tier3_deep_verification",
        })

        # 决策映射
        if verdict == "CONFIRM":
            decision = TierDecision.FINAL_CONFIRM
        elif verdict == "REJECT":
            decision = TierDecision.FINAL_REJECT
        else:
            # REVIEW 或其他情况 -> 保守处理，标记为确认但降低置信度
            decision = TierDecision.FINAL_CONFIRM
            confidence *= 0.8  # 审查中的结果降低置信度

        return confidence, findings, decision

    def _fallback_verdict(
        self, agent_reports: Dict[str, Optional[Dict[str, Any]]]
    ) -> Tuple[float, List[Dict[str, Any]], TierDecision]:
        """当仲裁智能体失败时的降级判定

        Args:
            agent_reports: 各分析智能体的报告

        Returns:
            (置信度, 发现列表, 决策)
        """
        valid_reports = {k: v for k, v in agent_reports.items() if v is not None}

        if not valid_reports:
            return 0.0, [], TierDecision.FINAL_REJECT

        # 简单多数投票
        confirm_count = 0
        total_confidence = 0.0
        for report in valid_reports.values():
            conf = float(report.get("confidence", 0.5))
            total_confidence += conf
            # 数据流和攻击链的权重更高
            if report.get("has_taint_flow") or report.get("attack_feasible"):
                confirm_count += 1
            elif conf > 0.6:
                confirm_count += 1

        avg_confidence = total_confidence / len(valid_reports)

        if confirm_count >= 2 and avg_confidence > 0.5:
            return avg_confidence, [], TierDecision.FINAL_CONFIRM
        elif confirm_count == 0 and avg_confidence < 0.3:
            return avg_confidence, [], TierDecision.FINAL_REJECT
        else:
            return avg_confidence, [], TierDecision.FINAL_CONFIRM


# ============================================================================
# 主管道: 三层渐进式分析管道
# ============================================================================
