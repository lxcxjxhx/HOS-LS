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
