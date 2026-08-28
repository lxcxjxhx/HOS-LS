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



class AIAssistedAnalyzer:
    """Tier 2 AI辅助分析器

    使用LLM对Tier 1筛选出的可疑文件进行单次分析。
    采用自一致性策略（运行3次取多数投票）提升准确率。
    """

    # CWE 专用提示词模板
    CWE_PROMPT_TEMPLATES: Dict[str, str] = {
        "CWE-89": (
            "你是一名SQL注入漏洞分析专家。请分析以下代码片段，判断是否存在SQL注入漏洞。\n"
            "重点关注：用户输入是否未经参数化就直接拼接到SQL语句中。\n"
            "请检查是否存在ORM框架的安全查询方法被绕过的情况。\n"
            "以JSON格式返回分析结果，包含字段: is_vulnerable(bool), confidence(float 0-1), "
            "explanation(str), affected_lines(list[int]), remediation(str)。"
        ),
        "CWE-78": (
            "你是一名命令注入漏洞分析专家。请分析以下代码片段，判断是否存在命令注入漏洞。\n"
            "重点关注：外部输入是否通过字符串拼接传入系统命令执行函数。\n"
            "请区分安全的白名单校验和不安全的拼接。\n"
            "以JSON格式返回分析结果，包含字段: is_vulnerable(bool), confidence(float 0-1), "
            "explanation(str), affected_lines(list[int]), remediation(str)。"
        ),
        "CWE-79": (
            "你是一名XSS跨站脚本漏洞分析专家。请分析以下代码片段，判断是否存在XSS漏洞。\n"
            "重点关注：用户输入是否未经转义/过滤就输出到HTML页面或写入DOM。\n"
            "请区分服务端渲染XSS和客户端DOM型XSS。\n"
            "以JSON格式返回分析结果，包含字段: is_vulnerable(bool), confidence(float 0-1), "
            "explanation(str), affected_lines(list[int]), remediation(str)。"
        ),
        "CWE-22": (
            "你是一名路径穿越漏洞分析专家。请分析以下代码片段，判断是否存在路径穿越漏洞。\n"
            "重点关注：用户输入是否被直接用于文件路径操作而缺少路径规范化/白名单校验。\n"
            "以JSON格式返回分析结果，包含字段: is_vulnerable(bool), confidence(float 0-1), "
            "explanation(str), affected_lines(list[int]), remediation(str)。"
        ),
        "CWE-918": (
            "你是一名SSRF漏洞分析专家。请分析以下代码片段，判断是否存在SSRF漏洞。\n"
            "重点关注：用户是否可以控制HTTP请求的目标URL，是否缺少URL白名单或协议限制。\n"
            "以JSON格式返回分析结果，包含字段: is_vulnerable(bool), confidence(float 0-1), "
            "explanation(str), affected_lines(list[int]), remediation(str)。"
        ),
        "CWE-798": (
            "你是一名凭证安全分析专家。请分析以下代码片段，判断是否存在硬编码凭证问题。\n"
            "重点关注：密码、密钥、Token等敏感信息是否直接写在源代码中。\n"
            "请区分测试代码中的占位符和真实凭证。\n"
            "以JSON格式返回分析结果，包含字段: is_vulnerable(bool), confidence(float 0-1), "
            "explanation(str), affected_lines(list[int]), remediation(str)。"
        ),
        "CWE-502": (
            "你是一名反序列化漏洞分析专家。请分析以下代码片段，判断是否存在不安全的反序列化。\n"
            "重点关注：来自不可信来源的数据是否被直接反序列化为对象。\n"
            "以JSON格式返回分析结果，包含字段: is_vulnerable(bool), confidence(float 0-1), "
            "explanation(str), affected_lines(list[int]), remediation(str)。"
        ),
    }

    # 通用提示词模板（当CWE没有专用模板时使用）
    GENERIC_PROMPT_TEMPLATE = (
        "你是一名代码安全审计专家。请分析以下代码片段，判断是否存在安全漏洞。\n"
        "请综合考虑以下方面：输入验证、认证授权、数据保护、加密安全、错误处理。\n"
        "以JSON格式返回分析结果，包含字段: is_vulnerable(bool), confidence(float 0-1), "
        "explanation(str), affected_lines(list[int]), remediation(str), cwe_id(str)。"
    )

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        ai_client: Optional[Any] = None,
    ) -> None:
        """初始化AI辅助分析器

        Args:
            config: 可选配置
            ai_client: AI客户端实例（兼容 AIClient 接口）
        """
        self._config = config or {}
        self._ai_client = ai_client
        # 自一致性投票次数
        self._consistency_runs: int = self._config.get("consistency_runs", 3)
        # 各决策阈值
        self._reject_threshold: float = self._config.get("reject_threshold", 0.4)
        self._confirm_threshold: float = self._config.get("confirm_threshold", 0.7)
        # 并发信号量（在管道层统一控制，此处预留）
        self._semaphore: Optional[asyncio.Semaphore] = None

    def set_semaphore(self, semaphore: asyncio.Semaphore) -> None:
        """设置并发信号量

        Args:
            semaphore: asyncio信号量
        """
        self._semaphore = semaphore

    async def analyze(
        self,
        file_path: Path,
        file_content: str,
        tier1_findings: List[Dict[str, Any]],
    ) -> TierResult:
        """对文件执行AI辅助分析

        Args:
            file_path: 文件路径
            file_content: 文件内容
            tier1_findings: Tier 1 的初步发现，用于构造针对性提示

        Returns:
            TierResult: AI分析结果
        """
        start_time = time.perf_counter()
        total_tokens = 0

        # 确定主要CWE类型，选择对应提示词
        primary_cwe = self._determine_primary_cwe(tier1_findings)
        system_prompt = self.CWE_PROMPT_TEMPLATES.get(primary_cwe, self.GENERIC_PROMPT_TEMPLATE)

        # 截断文件内容以避免超出上下文窗口
        truncated_content = file_content[:15000]

        # 构建用户提示词
        user_prompt = self._build_user_prompt(file_path, truncated_content, tier1_findings)

        # 自一致性投票：运行 N 次取多数结果
        votes: List[Dict[str, Any]] = []
        for run_idx in range(self._consistency_runs):
            try:
                result, tokens = await self._single_llm_call(
                    system_prompt, user_prompt, run_idx
                )
                total_tokens += tokens
                if result is not None:
                    votes.append(result)
            except Exception as exc:
                logger.warning(
                    f"Tier 2 LLM调用失败 (第{run_idx + 1}次): {exc}"
                )

        # 多数投票聚合
        aggregated = self._aggregate_votes(votes)
        confidence = aggregated.get("confidence", 0.0)
        findings = aggregated.get("findings", [])

        # 决策
        decision = self._make_decision(confidence)
        elapsed = (time.perf_counter() - start_time) * 1000

        return TierResult(
            tier=2,
            decision=decision.value,
            confidence=confidence,
            findings=findings,
            elapsed_ms=elapsed,
            token_cost=total_tokens,
        )

    async def _single_llm_call(
        self,
        system_prompt: str,
        user_prompt: str,
        run_idx: int,
    ) -> Tuple[Optional[Dict[str, Any]], int]:
        """执行单次LLM调用

        Args:
            system_prompt: 系统提示词
            user_prompt: 用户提示词
            run_idx: 当前是第几次运行（用于日志区分）

        Returns:
            (解析后的结果字典, token消耗数)
        """
        if self._ai_client is None:
            logger.warning("Tier 2: AI客户端未配置，跳过LLM分析")
            return None, 0

        try:
            from src.ai.models import AIRequest
        except ImportError:
            logger.error("Tier 2: 无法导入AIRequest模型")
            return None, 0

        request = AIRequest(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.3,  # 略高的温度以增加投票多样性
            max_tokens=2048,
        )

        # 使用信号量控制并发
        if self._semaphore is not None:
            async with self._semaphore:
                response = await self._ai_client.generate_with_retry(request)
        else:
            response = await self._ai_client.generate_with_retry(request)

        tokens = response.usage.get("total_tokens", 0) if response.usage else 0

        # 解析JSON响应
        parsed = self._parse_llm_response(response.content)
        return parsed, tokens

    def _build_user_prompt(
        self,
        file_path: Path,
        content: str,
        tier1_findings: List[Dict[str, Any]],
    ) -> str:
        """构建用户提示词

        Args:
            file_path: 文件路径
            content: 文件内容（可能已截断）
            tier1_findings: Tier 1 发现

        Returns:
            格式化的用户提示词
        """
        parts = [f"## 文件路径\n`{file_path}`\n"]

        # 加入Tier 1的初步发现作为上下文
        if tier1_findings:
            parts.append("## Tier 1 快速筛查初步发现\n")
            for i, f in enumerate(tier1_findings[:10], 1):  # 最多展示10条
                parts.append(
                    f"{i}. [{f['rule_id']}] {f['description']} "
                    f"(第{f.get('line_number', '?')}行, 严重度: {f.get('severity', 0):.2f})"
                )
            parts.append("")

        parts.append("## 代码内容\n```")
        # 根据文件扩展名推断语言
        lang = self._guess_language(file_path)
        parts[parts.index("## 代码内容\n```")] = f"## 代码内容\n```{lang}"
        parts.append(content)
        parts.append("```\n")
        parts.append("请分析上述代码，判断是否存在真实的安全漏洞，并给出置信度评分。")

        return "\n".join(parts)

    def _determine_primary_cwe(self, findings: List[Dict[str, Any]]) -> str:
        """从Tier 1发现中确定主要CWE类型

        Args:
            findings: Tier 1的发现列表

        Returns:
            CWE编号字符串
        """
        if not findings:
            return "GENERIC"

        # 统计CWE出现频率，取最高频
        cwe_counter = Counter(f.get("cwe_id", "") for f in findings if f.get("cwe_id"))
        if cwe_counter:
            return cwe_counter.most_common(1)[0][0]
        return "GENERIC"

    def _parse_llm_response(self, content: str) -> Optional[Dict[str, Any]]:
        """解析LLM的JSON响应

        Args:
            content: LLM返回的文本内容

        Returns:
            解析后的字典，或None
        """
        if not content:
            return None

        # 尝试提取JSON块
        json_match = re.search(r"```json\s*(.*?)\s*```", content, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # 尝试直接解析
            json_str = content.strip()

        try:
            data = json.loads(json_str)
            # 规范化字段
            result = {
                "is_vulnerable": bool(data.get("is_vulnerable", False)),
                "confidence": float(data.get("confidence", 0.5)),
                "explanation": str(data.get("explanation", "")),
                "affected_lines": data.get("affected_lines", []),
                "remediation": str(data.get("remediation", "")),
                "cwe_id": str(data.get("cwe_id", "")),
            }
            return result
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.debug(f"Tier 2: LLM响应JSON解析失败: {exc}")
            return None

    def _aggregate_votes(self, votes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """对多次LLM调用的结果进行多数投票聚合

        Args:
            votes: 各次调用的解析结果列表

        Returns:
            聚合后的结果
        """
        if not votes:
            return {"confidence": 0.0, "findings": []}

        # 投票: is_vulnerable 的多数决定
        vuln_votes = Counter(v.get("is_vulnerable", False) for v in votes)
        majority_vulnerable = vuln_votes.most_common(1)[0][0]

        # 置信度取中位数
        confidences = sorted(v.get("confidence", 0.5) for v in votes)
        median_confidence = confidences[len(confidences) // 2]

        # 如果多数判定为无漏洞，降低置信度
        if not majority_vulnerable:
            median_confidence = min(median_confidence, 0.3)

        # 收集所有发现
        findings: List[Dict[str, Any]] = []
        if majority_vulnerable:
            # 合并所有投票中的解释
            explanations = [v.get("explanation", "") for v in votes if v.get("is_vulnerable")]
            affected_lines_set: set = set()
            cwe_ids: set = set()
            for v in votes:
                if v.get("is_vulnerable"):
                    for line in v.get("affected_lines", []):
                        affected_lines_set.add(line)
                    if v.get("cwe_id"):
                        cwe_ids.add(v["cwe_id"])

            findings.append({
                "rule_id": "TIER2-AI",
                "cwe_id": ", ".join(cwe_ids) if cwe_ids else "",
                "description": "AI辅助分析确认的漏洞",
                "explanation": " | ".join(explanations[:3]),
                "affected_lines": sorted(affected_lines_set),
                "confidence": median_confidence,
                "source": "tier2_ai",
                "voting_detail": {
                    "total_votes": len(votes),
                    "vulnerable_votes": vuln_votes.get(True, 0),
                    "safe_votes": vuln_votes.get(False, 0),
                },
            })

        return {"confidence": median_confidence, "findings": findings}

    def _make_decision(self, confidence: float) -> TierDecision:
        """根据置信度做出决策

        Args:
            confidence: AI分析的置信度

        Returns:
            TierDecision
        """
        if confidence < self._reject_threshold:
            return TierDecision.REJECT
        elif confidence >= self._confirm_threshold:
            return TierDecision.CONFIRM
        else:
            return TierDecision.PROCEED_TO_TIER3

    @staticmethod
    def _guess_language(file_path: Path) -> str:
        """根据文件扩展名推断编程语言

        Args:
            file_path: 文件路径

        Returns:
            语言标识字符串
        """
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".tsx": "tsx", ".jsx": "jsx", ".java": "java",
            ".cpp": "cpp", ".c": "c", ".h": "c", ".go": "go",
            ".rs": "rust", ".php": "php", ".rb": "ruby",
            ".cs": "csharp", ".swift": "swift", ".kt": "kotlin",
            ".xml": "xml", ".yaml": "yaml", ".yml": "yaml",
            ".json": "json", ".sql": "sql", ".html": "html",
        }
        return ext_map.get(file_path.suffix.lower(), "")


# ============================================================================
# Tier 3: 深度验证引擎
# ============================================================================
