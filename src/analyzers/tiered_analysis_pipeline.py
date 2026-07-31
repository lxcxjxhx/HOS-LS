"""三层渐进式分析管道

对标 MultiVer 论文的多层验证方法，实现快速筛查 -> AI辅助分析 -> 深度验证的渐进式分析流程。
通过分层策略显著降低分析成本，同时保持高准确率。

架构概述:
  Tier 1 (快速筛查): 正则匹配 + 启发式评分，100+ 文件/秒
  Tier 2 (AI辅助分析): LLM单次分析 + 自一致性投票，中等深度
  Tier 3 (深度验证): 多智能体共识 + 数据流分析 + 攻击链构建
"""

import asyncio
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# 枚举与数据类定义
# ============================================================================


class TierDecision(Enum):
    """各层分析的决策结果"""

    # Tier 1 决策
    SKIP = "SKIP"  # 风险极低，跳过后续分析
    PROCEED_TO_TIER2 = "PROCEED_TO_TIER2"  # 存在可疑模式，需要AI分析
    FAST_CONFIRM = "FAST_CONFIRM"  # 高风险模式明确匹配，直接确认

    # Tier 2 决策
    REJECT = "REJECT"  # AI判定为误报或低风险
    PROCEED_TO_TIER3 = "PROCEED_TO_TIER3"  # 置信度不足，需要深度验证
    CONFIRM = "CONFIRM"  # AI高置信度确认漏洞

    # Tier 3 决策
    FINAL_REJECT = "FINAL_REJECT"  # 深度验证后排除
    FINAL_CONFIRM = "FINAL_CONFIRM"  # 深度验证后确认


@dataclass
class TierResult:
    """单层分析结果"""

    tier: int  # 1, 2, or 3
    decision: str  # TierDecision 的 value
    confidence: float  # 0.0 ~ 1.0 置信度
    findings: List[Dict[str, Any]]  # 发现的漏洞/问题列表
    elapsed_ms: float  # 本层耗时（毫秒）
    token_cost: int  # 本层消耗的 token 数


@dataclass
class TieredAnalysisResult:
    """完整的三层分析结果"""

    file_path: str
    final_decision: str  # 最终决策
    final_findings: List[Dict[str, Any]]  # 最终发现
    tier_results: List[TierResult]  # 各层分析结果
    total_elapsed_ms: float  # 总耗时（毫秒）
    total_tokens: int  # 总 token 消耗


# ============================================================================
# Tier 1: 快速筛查引擎
# ============================================================================


class FastScreener:
    """Tier 1 快速筛查器

    基于正则表达式模式匹配和启发式评分，实现超高速初筛。
    设计目标: 100+ 文件/秒的处理速度。
    """

    # 危险文件扩展名（高优先级分析）
    HIGH_RISK_EXTENSIONS = {
        ".py", ".java", ".js", ".ts", ".php", ".rb", ".go", ".rs",
        ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt",
    }

    # 中等风险扩展名
    MEDIUM_RISK_EXTENSIONS = {
        ".xml", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
        ".conf", ".properties", ".env", ".sql", ".html", ".jsp",
    }

    # 低风险/可跳过扩展名
    SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".doc", ".docx",
        ".zip", ".tar", ".gz", ".rar", ".7z",
        ".mp3", ".mp4", ".avi", ".mov", ".wav",
        ".lock", ".sum", ".map", ".min.js", ".min.css",
        ".pyc", ".pyo", ".class", ".o", ".so", ".dll", ".exe",
    }

    # 危险文件名模式（直接提升风险分数）
    DANGEROUS_FILENAME_PATTERNS = [
        (re.compile(r"(?i)(auth|login|session|token|credential)"), 0.15),
        (re.compile(r"(?i)(crypto|encrypt|decrypt|hash|password|secret)"), 0.15),
        (re.compile(r"(?i)(sql|query|database|db_|dao)"), 0.12),
        (re.compile(r"(?i)(upload|download|file|path|directory)"), 0.10),
        (re.compile(r"(?i)(command|exec|eval|shell|process|runtime)"), 0.18),
        (re.compile(r"(?i)(config|setting|env|property)"), 0.08),
        (re.compile(r"(?i)(api|endpoint|route|controller|handler)"), 0.06),
    ]

    # ---- 漏洞正则模式库 ----
    # 每条规则: (规则ID, CWE编号, 正则表达式, 严重度基础分, 描述)
    VULN_PATTERNS: List[Tuple[str, str, re.Pattern, float, str]] = [
        # SQL 注入
        (
            "SQLI-001", "CWE-89",
            re.compile(r"""(?i)(execute|exec|cursor\.execute)\s*\(\s*["']?\s*(SELECT|INSERT|UPDATE|DELETE|DROP).*?(\+|%s|\$\{|\.format|f["'])"""),
            0.75, "SQL注入-字符串拼接查询",
        ),
        (
            "SQLI-002", "CWE-89",
            re.compile(r"""\$\{[^}]*\}"""),
            0.55, "MyBatis ${} 占位符（可能SQL注入）",
        ),
        # 命令注入
        (
            "CMDI-001", "CWE-78",
            re.compile(r"""(?i)(os\.system|subprocess\.call|subprocess\.Popen|Runtime\.getRuntime\(\)\.exec)\s*\(.*?(\+|%s|\$\{|\.format|f["'])"""),
            0.80, "命令注入-外部输入拼接",
        ),
        (
            "CMDI-002", "CWE-78",
            re.compile(r"""(?i)(eval|exec)\s*\(.*?(request|param|input|args|argv|user)"""),
            0.85, "危险函数执行-用户输入直接传入eval/exec",
        ),
        # XSS
        (
            "XSS-001", "CWE-79",
            re.compile(r"""(?i)(innerHTML|outerHTML|document\.write|\.html\s*\()\s*[=,]\s*.*?(request|param|input|user|data)"""),
            0.65, "XSS-未过滤的用户输入写入DOM",
        ),
        (
            "XSS-002", "CWE-79",
            re.compile(r"""(?i)(\{\{.*?\}\}|v-html|dangerouslySetInnerHTML)"""),
            0.40, "XSS-模板渲染/危险HTML绑定",
        ),
        # 路径穿越
        (
            "PATH-001", "CWE-22",
            re.compile(r"""(?i)(open|read|write|include|require|load)\s*\(.*?(request|param|input|user|path).*?(\+|%s|\$\{|\.format|f["'])"""),
            0.70, "路径穿越-用户输入拼接文件路径",
        ),
        # SSRF
        (
            "SSRF-001", "CWE-918",
            re.compile(r"""(?i)(requests\.get|requests\.post|urllib|http\.client|HttpClient|RestTemplate|fetch|axios)\s*\(.*?(request|param|input|user|url)"""),
            0.65, "SSRF-用户可控的URL请求",
        ),
        # 硬编码凭证
        (
            "HARC-001", "CWE-798",
            re.compile(r"""(?i)(password|passwd|secret\w*|api_key|apikey|token\w*|access_key)\s*[=:]\s*["'][^"']{6,}["']"""),
            0.60, "硬编码凭证/密钥",
        ),
        (
            "HARC-002", "CWE-321",
            re.compile(r"""(?i)(AES|DES|RSA|MD5|SHA)\s*(KEY|IV|SALT)\s*[=:]\s*["'][^"']{4,}["']"""),
            0.55, "硬编码加密密钥",
        ),
        # 不安全的加密
        (
            "CRYPT-001", "CWE-327",
            re.compile(r"""(?i)(MD5|SHA1|DES|RC4|RC2)\s*[\.(]"""),
            0.45, "使用弱加密算法",
        ),
        # 不安全的随机数
        (
            "RAND-001", "CWE-330",
            re.compile(r"""(?i)(Math\.random|random\.random|java\.util\.Random)\s*\("""),
            0.35, "使用不安全的随机数生成器",
        ),
        # 反序列化
        (
            "DESER-001", "CWE-502",
            re.compile(r"""(?i)(ObjectInputStream|pickle\.loads|yaml\.load|unserialize|JSON\.parse)\s*\(.*?(request|param|input|user|data)"""),
            0.70, "不安全的反序列化-用户输入",
        ),
        # XXE
        (
            "XXE-001", "CWE-611",
            re.compile(r"""(?i)(XMLReader|SAXParser|DocumentBuilder|XMLInputFactory|TransformerFactory)(?!.*setFeature)"""),
            0.50, "XML解析器未禁用外部实体",
        ),
        # 不安全的反序列化 - 额外模式
        (
            "DESER-002", "CWE-502",
            re.compile(r"""(?i)(pickle\.loads|yaml\.unsafe_load|marshal\.loads)\s*\("""),
            0.60, "不安全的反序列化函数调用",
        ),
        # 权限控制缺失
        (
            "AUTH-001", "CWE-862",
            re.compile(r"""(?i)@PermitAll|@AllowAnonym|permitAll\(\)|allow_anonymous\s*=\s*True"""),
            0.40, "权限控制缺失-匿名访问许可",
        ),
        # 日志注入
        (
            "LOGI-001", "CWE-117",
            re.compile(r"""(?i)(log\.info|log\.debug|log\.warn|log\.error|logger\.\w+)\s*\(.*?(request|param|input|user).*?(\+|%s|\$\{|\.format)"""),
            0.45, "日志注入-用户输入未过滤",
        ),
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """初始化快速筛查器

        Args:
            config: 可选配置，支持自定义阈值
        """
        self._config = config or {}
        # 各决策阈值
        self._skip_threshold: float = self._config.get("skip_threshold", 0.2)
        self._fast_confirm_threshold: float = self._config.get("fast_confirm_threshold", 0.6)

    def screen(self, file_path: Path, file_content: str) -> TierResult:
        """对单个文件执行快速筛查

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            TierResult: 包含风险评分和决策的筛查结果
        """
        start_time = time.perf_counter()
        findings: List[Dict[str, Any]] = []
        risk_score: float = 0.0

        # ---- 步骤1: 文件扩展名过滤 ----
        ext = file_path.suffix.lower()
        if ext in self.SKIP_EXTENSIONS:
            elapsed = (time.perf_counter() - start_time) * 1000
            return TierResult(
                tier=1, decision=TierDecision.SKIP.value,
                confidence=1.0, findings=[], elapsed_ms=elapsed, token_cost=0,
            )

        # 扩展名基础分
        if ext in self.HIGH_RISK_EXTENSIONS:
            risk_score += 0.05
        elif ext in self.MEDIUM_RISK_EXTENSIONS:
            risk_score += 0.02

        # ---- 步骤2: 文件名模式匹配 ----
        file_name = file_path.name
        for pattern, score_boost in self.DANGEROUS_FILENAME_PATTERNS:
            if pattern.search(file_name):
                risk_score += score_boost

        # ---- 步骤3: 内容正则匹配（核心） ----
        # 对大文件做截断，避免正则回溯导致性能问题
        content_to_scan = file_content[:50000]  # 最多扫描50KB
        lines = content_to_scan.split("\n")

        for rule_id, cwe_id, pattern, base_severity, description in self.VULN_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                # 跳过注释行（简单启发式）
                stripped = line.strip()
                if stripped.startswith(("#", "//", "/*", "*", "'")):
                    continue
                if stripped.startswith("<!--") or stripped.startswith("{#"):
                    continue

                match = pattern.search(line)
                if match:
                    findings.append({
                        "rule_id": rule_id,
                        "cwe_id": cwe_id,
                        "description": description,
                        "line_number": line_num,
                        "code_snippet": stripped[:200],
                        "severity": min(base_severity, 1.0),
                        "source": "tier1_regex",
                    })
                    # 风险分数取所有匹配中的最大值，并叠加少量增量
                    risk_score = max(risk_score, base_severity)

        # ---- 步骤4: 额外启发式加分 ----
        # 文件包含多个不同类别的匹配 -> 风险提升
        matched_cwes = {f["cwe_id"] for f in findings}
        if len(matched_cwes) >= 3:
            risk_score = min(risk_score + 0.15, 1.0)
        elif len(matched_cwes) >= 2:
            risk_score = min(risk_score + 0.08, 1.0)

        # 文件非常短且无匹配 -> 降低分数
        if len(lines) < 10 and not findings:
            risk_score *= 0.5

        # ---- 步骤5: 决策 ----
        decision = self._make_decision(risk_score)
        elapsed = (time.perf_counter() - start_time) * 1000

        return TierResult(
            tier=1,
            decision=decision.value,
            confidence=risk_score,
            findings=findings,
            elapsed_ms=elapsed,
            token_cost=0,
        )

    def _make_decision(self, risk_score: float) -> TierDecision:
        """根据风险分数做出决策

        Args:
            risk_score: 0.0 ~ 1.0 的风险分数

        Returns:
            TierDecision: 筛查决策
        """
        if risk_score < self._skip_threshold:
            return TierDecision.SKIP
        elif risk_score >= self._fast_confirm_threshold:
            return TierDecision.FAST_CONFIRM
        else:
            return TierDecision.PROCEED_TO_TIER2


# ============================================================================
# Tier 2: AI辅助分析引擎
# ============================================================================


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


class TieredAnalysisPipeline:
    """三层渐进式分析管道

    对标 MultiVer 论文的多层验证方法，将分析流程分为三层：
    - Tier 1: 快速筛查（正则 + 启发式），过滤明显安全/危险的文件
    - Tier 2: AI辅助分析（LLM + 自一致性投票），对可疑文件进行中等深度分析
    - Tier 3: 深度验证（多智能体共识），对高不确定性文件进行深度分析

    核心优势：
    - 通过逐层过滤大幅减少昂贵的LLM调用次数
    - 每层都有明确的置信度阈值控制质量
    - 支持批量分析和并发控制
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """初始化三层分析管道

        Args:
            config: 管道配置，支持的键:
                - max_concurrency: 最大并发数 (默认 8)
                - skip_threshold: Tier 1 跳过阈值 (默认 0.2)
                - fast_confirm_threshold: Tier 1 快速确认阈值 (默认 0.6)
                - reject_threshold: Tier 2 拒绝阈值 (默认 0.4)
                - confirm_threshold: Tier 2 确认阈值 (默认 0.7)
                - consistency_runs: Tier 2 自一致性投票次数 (默认 3)
                - agent_concurrency: Tier 3 智能体并发数 (默认 3)
                - ai_client: AI客户端实例
        """
        self._config = config or {}
        self._max_concurrency: int = self._config.get("max_concurrency", 8)
        self._semaphore = asyncio.Semaphore(self._max_concurrency)

        # 初始化AI客户端
        self._ai_client = self._config.get("ai_client", None)

        # 初始化三层分析器
        tier1_config = {
            "skip_threshold": self._config.get("skip_threshold", 0.2),
            "fast_confirm_threshold": self._config.get("fast_confirm_threshold", 0.6),
        }
        tier2_config = {
            "consistency_runs": self._config.get("consistency_runs", 3),
            "reject_threshold": self._config.get("reject_threshold", 0.4),
            "confirm_threshold": self._config.get("confirm_threshold", 0.7),
        }
        tier3_config = {
            "agent_concurrency": self._config.get("agent_concurrency", 3),
        }

        self._tier1 = FastScreener(tier1_config)
        self._tier2 = AIAssistedAnalyzer(tier2_config, self._ai_client)
        self._tier3 = DeepVerifier(tier3_config, self._ai_client)

        # 设置并发信号量
        self._tier2.set_semaphore(self._semaphore)
        self._tier3.set_semaphore(self._semaphore)

        # 统计计数器
        self._stats = {
            "total_files": 0,
            "tier1_skip": 0,
            "tier1_fast_confirm": 0,
            "tier1_proceed_to_t2": 0,
            "tier2_reject": 0,
            "tier2_confirm": 0,
            "tier2_proceed_to_t3": 0,
            "tier3_final_reject": 0,
            "tier3_final_confirm": 0,
            "total_tokens": 0,
            "total_elapsed_ms": 0.0,
            "errors": 0,
        }

    async def analyze_file(
        self, file_path: Path, file_content: str
    ) -> TieredAnalysisResult:
        """对单个文件执行三层渐进式分析

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            TieredAnalysisResult: 完整的分析结果
        """
        overall_start = time.perf_counter()
        tier_results: List[TierResult] = []
        final_findings: List[Dict[str, Any]] = []
        total_tokens = 0

        try:
            # ======== Tier 1: 快速筛查 ========
            t1_result = self._tier1.screen(file_path, file_content)
            tier_results.append(t1_result)
            total_tokens += t1_result.token_cost

            logger.debug(
                f"Tier 1 [{file_path.name}]: "
                f"decision={t1_result.decision}, "
                f"confidence={t1_result.confidence:.2f}, "
                f"findings={len(t1_result.findings)}, "
                f"elapsed={t1_result.elapsed_ms:.1f}ms"
            )

            # Tier 1 决策路由
            if t1_result.decision == TierDecision.SKIP.value:
                self._stats["tier1_skip"] += 1
                return self._build_result(
                    file_path, TierDecision.SKIP.value, [],
                    tier_results, overall_start, total_tokens,
                )

            if t1_result.decision == TierDecision.FAST_CONFIRM.value:
                self._stats["tier1_fast_confirm"] += 1
                # 快速确认的发现标记为中等置信度（需要后续验证）
                fast_findings = [
                    {**f, "confidence": min(f.get("severity", 0.7), 0.85),
                     "verification_status": "fast_confirm_pending_review"}
                    for f in t1_result.findings
                ]
                return self._build_result(
                    file_path, TierDecision.FAST_CONFIRM.value, fast_findings,
                    tier_results, overall_start, total_tokens,
                )

            # PROCEED_TO_TIER2
            self._stats["tier1_proceed_to_t2"] += 1

            # ======== Tier 2: AI辅助分析 ========
            t2_result = await self._tier2.analyze(
                file_path, file_content, t1_result.findings
            )
            tier_results.append(t2_result)
            total_tokens += t2_result.token_cost

            logger.debug(
                f"Tier 2 [{file_path.name}]: "
                f"decision={t2_result.decision}, "
                f"confidence={t2_result.confidence:.2f}, "
                f"findings={len(t2_result.findings)}, "
                f"tokens={t2_result.token_cost}, "
                f"elapsed={t2_result.elapsed_ms:.1f}ms"
            )

            # Tier 2 决策路由
            if t2_result.decision == TierDecision.REJECT.value:
                self._stats["tier2_reject"] += 1
                return self._build_result(
                    file_path, TierDecision.REJECT.value, [],
                    tier_results, overall_start, total_tokens,
                )

            if t2_result.decision == TierDecision.CONFIRM.value:
                self._stats["tier2_confirm"] += 1
                # 合并Tier 1和Tier 2的发现
                combined = self._merge_findings(t1_result.findings, t2_result.findings)
                return self._build_result(
                    file_path, TierDecision.CONFIRM.value, combined,
                    tier_results, overall_start, total_tokens,
                )

            # PROCEED_TO_TIER3
            self._stats["tier2_proceed_to_t3"] += 1

            # ======== Tier 3: 深度验证 ========
            t3_result = await self._tier3.verify(
                file_path, file_content,
                t1_result.findings, t2_result.findings,
            )
            tier_results.append(t3_result)
            total_tokens += t3_result.token_cost

            logger.debug(
                f"Tier 3 [{file_path.name}]: "
                f"decision={t3_result.decision}, "
                f"confidence={t3_result.confidence:.2f}, "
                f"findings={len(t3_result.findings)}, "
                f"tokens={t3_result.token_cost}, "
                f"elapsed={t3_result.elapsed_ms:.1f}ms"
            )

            # Tier 3 最终决策
            if t3_result.decision == TierDecision.FINAL_CONFIRM.value:
                self._stats["tier3_final_confirm"] += 1
            else:
                self._stats["tier3_final_reject"] += 1

            # 合并所有层的发现
            all_findings = self._merge_findings(
                t1_result.findings,
                self._merge_findings(t2_result.findings, t3_result.findings),
            )

            return self._build_result(
                file_path, t3_result.decision, all_findings,
                tier_results, overall_start, total_tokens,
            )

        except Exception as exc:
            self._stats["errors"] += 1
            logger.error(f"分析管道异常 [{file_path}]: {exc}", exc_info=True)
            elapsed = (time.perf_counter() - overall_start) * 1000
            return TieredAnalysisResult(
                file_path=str(file_path),
                final_decision="ERROR",
                final_findings=[{
                    "error": str(exc),
                    "source": "pipeline_error",
                }],
                tier_results=tier_results,
                total_elapsed_ms=elapsed,
                total_tokens=total_tokens,
            )

    async def analyze_batch(
        self, files: List[Tuple[Path, str]]
    ) -> List[TieredAnalysisResult]:
        """批量分析文件

        使用信号量控制并发，避免资源耗尽。

        Args:
            files: (文件路径, 文件内容) 的列表

        Returns:
            每个文件的分析结果列表
        """
        if not files:
            return []

        batch_start = time.perf_counter()
        self._stats["total_files"] += len(files)

        logger.info(
            f"开始批量分析: {len(files)} 个文件, "
            f"最大并发: {self._max_concurrency}"
        )

        # 创建所有分析任务
        tasks = [
            self._safe_analyze_file(file_path, file_content)
            for file_path, file_content in files
        ]

        # 并发执行（信号量在 analyze_file 内部已控制）
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理异常结果
        final_results: List[TieredAnalysisResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"批量分析中文件异常: {files[i][0]}: {result}")
                self._stats["errors"] += 1
                final_results.append(TieredAnalysisResult(
                    file_path=str(files[i][0]),
                    final_decision="ERROR",
                    final_findings=[{"error": str(result), "source": "batch_error"}],
                    tier_results=[],
                    total_elapsed_ms=0.0,
                    total_tokens=0,
                ))
            else:
                final_results.append(result)

        batch_elapsed = (time.perf_counter() - batch_start) * 1000
        self._stats["total_elapsed_ms"] += batch_elapsed

        logger.info(
            f"批量分析完成: {len(files)} 个文件, "
            f"总耗时: {batch_elapsed:.0f}ms, "
            f"平均: {batch_elapsed / len(files):.0f}ms/文件"
        )

        return final_results

    async def _safe_analyze_file(
        self, file_path: Path, file_content: str
    ) -> TieredAnalysisResult:
        """安全包装的文件分析（捕获所有异常）

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            TieredAnalysisResult
        """
        try:
            return await self.analyze_file(file_path, file_content)
        except Exception as exc:
            logger.error(f"文件分析失败 [{file_path}]: {exc}")
            return TieredAnalysisResult(
                file_path=str(file_path),
                final_decision="ERROR",
                final_findings=[{"error": str(exc)}],
                tier_results=[],
                total_elapsed_ms=0.0,
                total_tokens=0,
            )

    def get_statistics(self) -> Dict[str, Any]:
        """获取管道运行统计信息

        Returns:
            包含各层跳过率、平均token消耗等的统计字典
        """
        total = max(self._stats["total_files"], 1)
        t1_proceeded = (
            self._stats["tier1_fast_confirm"]
            + self._stats["tier1_proceed_to_t2"]
        )
        t2_proceeded = self._stats["tier2_proceed_to_t3"]

        return {
            # 基础统计
            "total_files_analyzed": self._stats["total_files"],
            "total_errors": self._stats["errors"],
            "total_tokens_consumed": self._stats["total_tokens"],
            "total_elapsed_ms": self._stats["total_elapsed_ms"],

            # Tier 1 统计
            "tier1_skip_count": self._stats["tier1_skip"],
            "tier1_skip_rate": self._stats["tier1_skip"] / total,
            "tier1_fast_confirm_count": self._stats["tier1_fast_confirm"],
            "tier1_fast_confirm_rate": self._stats["tier1_fast_confirm"] / total,
            "tier1_proceed_to_t2_count": self._stats["tier1_proceed_to_t2"],
            "tier1_proceed_to_t2_rate": self._stats["tier1_proceed_to_t2"] / total,

            # Tier 2 统计
            "tier2_reject_count": self._stats["tier2_reject"],
            "tier2_reject_rate": (
                self._stats["tier2_reject"] / max(t1_proceeded, 1)
            ),
            "tier2_confirm_count": self._stats["tier2_confirm"],
            "tier2_confirm_rate": (
                self._stats["tier2_confirm"] / max(t1_proceeded, 1)
            ),
            "tier2_proceed_to_t3_count": self._stats["tier2_proceed_to_t3"],
            "tier2_proceed_to_t3_rate": (
                self._stats["tier2_proceed_to_t3"] / max(t1_proceeded, 1)
            ),

            # Tier 3 统计
            "tier3_final_confirm_count": self._stats["tier3_final_confirm"],
            "tier3_final_reject_count": self._stats["tier3_final_reject"],

            # 效率指标
            "llm_call_reduction_rate": (
                1.0 - (t1_proceeded + t2_proceeded) / total
                if total > 0 else 0.0
            ),
            "avg_tokens_per_file": (
                self._stats["total_tokens"] / total
            ),
            "avg_elapsed_per_file_ms": (
                self._stats["total_elapsed_ms"] / total
                if self._stats["total_files"] > 0 else 0.0
            ),
        }

    def reset_statistics(self) -> None:
        """重置统计计数器"""
        for key in self._stats:
            if isinstance(self._stats[key], float):
                self._stats[key] = 0.0
            else:
                self._stats[key] = 0

    # ---- 内部辅助方法 ----

    def _build_result(
        self,
        file_path: Path,
        final_decision: str,
        findings: List[Dict[str, Any]],
        tier_results: List[TierResult],
        overall_start: float,
        total_tokens: int,
    ) -> TieredAnalysisResult:
        """构建最终分析结果

        Args:
            file_path: 文件路径
            final_decision: 最终决策
            findings: 最终发现
            tier_results: 各层结果
            overall_start: 开始时间
            total_tokens: 总token数

        Returns:
            TieredAnalysisResult
        """
        elapsed = (time.perf_counter() - overall_start) * 1000
        self._stats["total_tokens"] += total_tokens
        return TieredAnalysisResult(
            file_path=str(file_path),
            final_decision=final_decision,
            final_findings=findings,
            tier_results=tier_results,
            total_elapsed_ms=elapsed,
            total_tokens=total_tokens,
        )

    @staticmethod
    def _merge_findings(
        findings_a: List[Dict[str, Any]],
        findings_b: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """合并两层分析的发现（去重）

        去重策略: 如果两条发现的 rule_id 和行号相同，保留置信度更高的那条。

        Args:
            findings_a: 第一层的发现
            findings_b: 第二层的发现

        Returns:
            合并后的发现列表
        """
        if not findings_a:
            return findings_b
        if not findings_b:
            return findings_a

        # 使用 (rule_id, line_number) 作为去重键
        seen: Dict[Tuple[str, int], Dict[str, Any]] = {}

        for finding in findings_a:
            key = (
                finding.get("rule_id", ""),
                finding.get("line_number", finding.get("line", 0)),
            )
            seen[key] = finding

        for finding in findings_b:
            key = (
                finding.get("rule_id", ""),
                finding.get("line_number", finding.get("line", 0)),
            )
            if key in seen:
                # 保留置信度更高的
                existing_conf = seen[key].get("confidence", seen[key].get("severity", 0))
                new_conf = finding.get("confidence", finding.get("severity", 0))
                if new_conf > existing_conf:
                    # 合并元数据
                    merged = {**seen[key], **finding}
                    seen[key] = merged
            else:
                seen[key] = finding

        return list(seen.values())
