"""行级漏洞定位模块

对标 T2L-Agent 论文的精确漏洞定位方法，通过多信号融合（token 相关性、
危险模式匹配、代码上下文分析）对源文件进行行级漏洞概率评分，
输出 top-k 最可能包含漏洞的代码行。

评分融合公式:
    final_score = token_score * 0.2 + pattern_score * 0.5 + context_score * 0.3

支持的 CWE 类型:
    CWE-89  (SQL 注入)
    CWE-78  (命令注入)
    CWE-79  (跨站脚本)
    CWE-22  (路径遍历)
    CWE-502 (反序列化)
    CWE-918 (SSRF)
    CWE-611 (XXE)
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class LineScore:
    """单行漏洞评分

    Attributes:
        line_number: 行号（从 1 开始）
        score: 漏洞概率分数，取值范围 [0, 1]
    """

    line_number: int
    score: float

    def __post_init__(self) -> None:
        """校验分数范围"""
        self.score = max(0.0, min(1.0, self.score))

    def __repr__(self) -> str:
        return f"LineScore(line={self.line_number}, score={self.score:.4f})"

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {"line_number": self.line_number, "score": round(self.score, 4)}


@dataclass
class LocalizationResult:
    """单文件行级定位结果

    Attributes:
        file_path: 文件路径
        vulnerable_lines: 所有行的评分列表
        top_k_lines: top-k 最可能含漏洞的行
        confidence: 整体置信度（top-1 分数）
    """

    file_path: str
    vulnerable_lines: List[LineScore] = field(default_factory=list)
    top_k_lines: List[LineScore] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            "file_path": self.file_path,
            "vulnerable_lines": [ls.to_dict() for ls in self.vulnerable_lines],
            "top_k_lines": [ls.to_dict() for ls in self.top_k_lines],
            "confidence": round(self.confidence, 4),
        }


@dataclass
class LocalizationReport:
    """多文件聚合定位报告

    Attributes:
        results: 每个文件的定位结果
        summary: 汇总统计信息
    """

    results: List[LocalizationResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def add_result(self, result: LocalizationResult) -> None:
        """添加单文件结果并更新汇总"""
        self.results.append(result)
        self._rebuild_summary()

    def _rebuild_summary(self) -> None:
        """重新计算汇总统计"""
        if not self.results:
            self.summary = {
                "total_files": 0,
                "avg_confidence": 0.0,
                "max_confidence": 0.0,
                "total_vulnerable_lines": 0,
            }
            return

        confidences = [r.confidence for r in self.results]
        total_vuln_lines = sum(len(r.top_k_lines) for r in self.results)

        self.summary = {
            "total_files": len(self.results),
            "avg_confidence": round(sum(confidences) / len(confidences), 4),
            "max_confidence": round(max(confidences), 4),
            "total_vulnerable_lines": total_vuln_lines,
        }

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            "results": [r.to_dict() for r in self.results],
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# CWE 危险模式定义
# ---------------------------------------------------------------------------

# 每种 CWE 对应两组模式:
#   - keywords: 与漏洞类型高度相关的 token / 关键字（用于 token 评分）
#   - patterns: 精确的危险函数 / API 正则（用于模式评分）
CWE_PATTERNS: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "keywords": [
            "executeQuery", "executeUpdate", "execute", "createStatement",
            "prepareStatement", "createQuery", "createNativeQuery",
            "sql", "query", "SELECT", "INSERT", "UPDATE", "DELETE",
            "WHERE", "FROM", "concat", "StringBuilder",
            "PreparedStatement", "ResultSet", "Statement",
        ],
        "patterns": [
            r"\.executeQuery\s*\(",
            r"\.executeUpdate\s*\(",
            r"\.execute\s*\(",
            r"\.createStatement\s*\(",
            r"\.prepareStatement\s*\(",
            r'\".*(?:SELECT|INSERT|UPDATE|DELETE)\s.*\".*\+',
            r"\+.*\".*(?:SELECT|INSERT|UPDATE|DELETE)",
            r"String\.format\s*\(\s*\".*(?:SELECT|INSERT|UPDATE|DELETE)",
            r"StringBuilder.*(?:append|insert).*sql",
            r"\$\{.*\}",  # MyBatis ${} 拼接
            r"createQuery\s*\(\s*\"",
            r"createNativeQuery\s*\(\s*\"",
        ],
        "sink_functions": [
            "executeQuery", "executeUpdate", "execute",
            "createStatement", "prepareStatement",
        ],
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "keywords": [
            "Runtime", "exec", "ProcessBuilder", "command",
            "getRuntime", "loadLibrary", "System",
            "shell", "bash", "cmd", "powershell",
        ],
        "patterns": [
            r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(",
            r"new\s+ProcessBuilder\s*\(",
            r"ProcessBuilder\s*\(\s*\)\.command\s*\(",
            r"\.exec\s*\(\s*\"",
            r"\.exec\s*\(\s*\w+\s*\+",
            r"Runtime\.getRuntime\s*\(\s*\)\s*\.loadLibrary\s*\(",
            r"system\s*\(\s*\"",
            r"popen\s*\(\s*\"",
            r"subprocess\.\w+\s*\(",
        ],
        "sink_functions": [
            "exec", "ProcessBuilder", "system", "popen",
        ],
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "keywords": [
            "response", "getWriter", "innerHTML", "document.write",
            "output", "print", "println", "script",
            "html", "body", "div", "onclick", "onerror",
            "innerHTML", "outerHTML", "eval",
        ],
        "patterns": [
            r"response\.getWriter\s*\(\s*\)\s*\.write\s*\(",
            r"response\.getOutputStream\s*\(\s*\)\s*\.write\s*\(",
            r"\.innerHTML\s*=",
            r"document\.write\s*\(",
            r"document\.writeln\s*\(",
            r"\.outerHTML\s*=",
            r"eval\s*\(\s*\w+",
            r"out\.print(ln)?\s*\(\s*\w+",
            r"<%=\s*\w+",
            r"v-html\s*=",
        ],
        "sink_functions": [
            "getWriter", "write", "innerHTML", "eval",
            "document.write", "println",
        ],
    },
    "CWE-22": {
        "name": "Path Traversal",
        "keywords": [
            "FileInputStream", "FileOutputStream", "File",
            "new File", "getPath", "getAbsolutePath",
            "path", "directory", "folder", "read",
            "open", "FileReader", "BufferedReader",
        ],
        "patterns": [
            r"new\s+FileInputStream\s*\(",
            r"new\s+FileOutputStream\s*\(",
            r"new\s+File\s*\(\s*\w+\s*\)",
            r"new\s+File\s*\(\s*\".*\".*\+",
            r"Paths\.get\s*\(\s*\w+\s*\)",
            r"\.getPath\s*\(\s*\)",
            r"\.getAbsolutePath\s*\(\s*\)",
            r"open\s*\(\s*\w+\s*\+.*\)",
            r"File\.readAllBytes\s*\(\s*Paths",
        ],
        "sink_functions": [
            "FileInputStream", "FileOutputStream", "File",
            "Paths.get", "open",
        ],
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "keywords": [
            "ObjectInputStream", "readObject", "readUnshared",
            "deserialize", "XMLDecoder", "Yaml",
            "pickle", "loads", "load", "fromJSON",
            "Serializable", "transient",
        ],
        "patterns": [
            r"ObjectInputStream.*\.readObject\s*\(",
            r"ObjectInputStream.*\.readUnshared\s*\(",
            r"new\s+XMLDecoder\s*\(",
            r"Yaml\s*\(\s*\)\s*\.load\s*\(",
            r"pickle\.loads?\s*\(",
            r"pickle\.Unpickler\s*\(",
            r"ObjectMapper.*enableDefaultTyping\s*\(",
            r"readValue\s*\(.*Object\.class\s*\)",
            r"JSON\.parse\s*\(",
            r"gson\.fromJson\s*\(",
        ],
        "sink_functions": [
            "readObject", "readUnshared", "XMLDecoder",
            "pickle.loads", "Yaml.load",
        ],
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "keywords": [
            "URL", "openConnection", "HttpClient", "HttpURLConnection",
            "RestTemplate", "WebClient", "OkHttp",
            "request", "fetch", "get", "post",
            "send", "connect", "download",
        ],
        "patterns": [
            r"new\s+URL\s*\(\s*\w+\s*\)\s*\.openConnection\s*\(",
            r"URL\s*\(\s*\w+\s*\)\s*\.openConnection\s*\(",
            r"HttpClient\.newHttpClient\s*\(",
            r"new\s+HttpURLConnection\s*\(",
            r"RestTemplate\s*\(\s*\)\s*\.\w+\s*\(",
            r"WebClient\.builder\s*\(",
            r"OkHttpClient\s*\(\s*\)",
            r"requests\.\w+\s*\(\s*\w+\s*\)",
            r"urllib\.request\.urlopen\s*\(",
            r"fetch\s*\(\s*\w+\s*\)",
        ],
        "sink_functions": [
            "openConnection", "HttpClient", "RestTemplate",
            "WebClient", "OkHttpClient", "fetch",
        ],
    },
    "CWE-611": {
        "name": "XML External Entity (XXE)",
        "keywords": [
            "DocumentBuilder", "SAXParser", "XMLReader",
            "TransformerFactory", "SchemaFactory",
            "XMLInputFactory", "Unmarshaller",
            "parse", "FEATURE", "DTD", "ENTITY",
        ],
        "patterns": [
            r"DocumentBuilder.*\.parse\s*\(",
            r"SAXParser.*\.parse\s*\(",
            r"XMLReader.*\.parse\s*\(",
            r"TransformerFactory\.newInstance\s*\(",
            r"SchemaFactory\.newInstance\s*\(",
            r"XMLInputFactory\.newInstance\s*\(",
            r"Unmarshaller\.unmarshal\s*\(",
            r"DocumentBuilderFactory\.newInstance\s*\(",
            r"SAXParserFactory\.newInstance\s*\(",
            r"SAXReader\s*\(\s*\)\s*\.read\s*\(",
        ],
        "sink_functions": [
            "parse", "DocumentBuilder", "SAXParser",
            "XMLReader", "unmarshal",
        ],
    },
}


# ---------------------------------------------------------------------------
# 评分权重
# ---------------------------------------------------------------------------

WEIGHT_TOKEN = 0.2
WEIGHT_PATTERN = 0.5
WEIGHT_CONTEXT = 0.3


# ---------------------------------------------------------------------------
# 核心定位器
# ---------------------------------------------------------------------------

class LineLevelLocator:
    """行级漏洞定位器

    对标 T2L-Agent 论文方法，通过多信号加权融合实现精确的行级漏洞定位。
    支持 CWE-89/78/79/22/502/918/611 等常见漏洞类型的精确定位。

    Example:
        >>> locator = LineLevelLocator()
        >>> result = locator.localize(
        ...     file_path="UserService.java",
        ...     file_content=open("UserService.java").read(),
        ...     vulnerability_desc={"cwe_id": "CWE-89", "description": "SQL injection in query"},
        ... )
        >>> for ls in result.top_k_lines:
        ...     print(f"Line {ls.line_number}: {ls.score:.4f}")
    """

    def __init__(self, top_k: int = 5) -> None:
        """初始化定位器

        Args:
            top_k: 返回的最可能漏洞行数，默认 5
        """
        self.top_k = top_k
        logger.info("LineLevelLocator 初始化完成 (top_k=%d)", top_k)

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def localize(
        self,
        file_path: str,
        file_content: str,
        vulnerability_desc: Dict[str, Any],
    ) -> LocalizationResult:
        """对单个文件执行行级漏洞定位

        Args:
            file_path: 文件路径
            file_content: 文件完整内容
            vulnerability_desc: 漏洞描述字典，至少包含 ``cwe_id`` 键；
                可选 ``description``、``keywords`` 等补充信息。

        Returns:
            LocalizationResult: 包含全行评分、top-k 行和置信度
        """
        cwe_id = vulnerability_desc.get("cwe_id", "").upper()
        logger.info(
            "开始行级定位: file=%s, cwe=%s", file_path, cwe_id,
        )

        # 三路独立评分
        token_scores = self._token_based_scoring(file_content, vulnerability_desc)
        pattern_scores = self._pattern_based_scoring(file_content, vulnerability_desc)
        context_scores = self._context_based_scoring(file_content, vulnerability_desc)

        logger.debug(
            "三路评分完成: token=%d 行, pattern=%d 行, context=%d 行",
            len(token_scores), len(pattern_scores), len(context_scores),
        )

        # 加权融合
        fused_scores = self._fuse_scores(token_scores, pattern_scores, context_scores)

        # top-k
        top_k_lines = self._get_top_k(fused_scores, k=self.top_k)

        confidence = top_k_lines[0].score if top_k_lines else 0.0

        result = LocalizationResult(
            file_path=file_path,
            vulnerable_lines=fused_scores,
            top_k_lines=top_k_lines,
            confidence=confidence,
        )

        logger.info(
            "行级定位完成: file=%s, top-1 置信度=%.4f, top-k=%d 行",
            file_path, confidence, len(top_k_lines),
        )
        return result

    # ------------------------------------------------------------------
    # Token 评分
    # ------------------------------------------------------------------

    def _token_based_scoring(
        self,
        file_content: str,
        vuln_desc: Dict[str, Any],
    ) -> List[LineScore]:
        """基于关键字 / token 相关性的行级评分

        对每一行，统计其中出现的与目标 CWE 相关的关键字数量，
        归一化后得到 [0, 1] 区间的分数。

        Args:
            file_content: 文件完整内容
            vuln_desc: 漏洞描述字典

        Returns:
            List[LineScore]: 每行的 token 相关性分数
        """
        lines = file_content.splitlines()
        if not lines:
            return []

        cwe_id = vuln_desc.get("cwe_id", "").upper()
        cwe_info = CWE_PATTERNS.get(cwe_id, {})
        keywords: List[str] = cwe_info.get("keywords", [])

        # 补充用户自定义关键字
        extra_keywords = vuln_desc.get("keywords", [])
        if isinstance(extra_keywords, list):
            keywords = keywords + extra_keywords

        if not keywords:
            logger.debug("CWE %s 无关键字定义，token 评分全部为 0", cwe_id)
            return [LineScore(line_number=i + 1, score=0.0) for i in range(len(lines))]

        # 预编译关键字正则（忽略大小写）
        keyword_patterns = [
            re.compile(re.escape(kw), re.IGNORECASE) for kw in keywords
        ]

        raw_scores: List[float] = []
        for line in lines:
            hit_count = sum(1 for pat in keyword_patterns if pat.search(line))
            raw_scores.append(float(hit_count))

        # 归一化到 [0, 1]
        max_score = max(raw_scores) if raw_scores else 1.0
        if max_score == 0:
            return [LineScore(line_number=i + 1, score=0.0) for i in range(len(lines))]

        return [
            LineScore(line_number=i + 1, score=s / max_score)
            for i, s in enumerate(raw_scores)
        ]

    # ------------------------------------------------------------------
    # 模式评分
    # ------------------------------------------------------------------

    def _pattern_based_scoring(
        self,
        file_content: str,
        vuln_desc: Dict[str, Any],
    ) -> List[LineScore]:
        """基于危险模式匹配的行级评分

        使用 CWE 对应的危险函数 / API 正则逐行匹配，
        命中越多模式则分数越高。

        Args:
            file_content: 文件完整内容
            vuln_desc: 漏洞描述字典

        Returns:
            List[LineScore]: 每行的危险模式分数
        """
        lines = file_content.splitlines()
        if not lines:
            return []

        cwe_id = vuln_desc.get("cwe_id", "").upper()
        cwe_info = CWE_PATTERNS.get(cwe_id, {})
        patterns: List[str] = cwe_info.get("patterns", [])

        if not patterns:
            logger.debug("CWE %s 无模式定义，pattern 评分全部为 0", cwe_id)
            return [LineScore(line_number=i + 1, score=0.0) for i in range(len(lines))]

        # 预编译正则
        compiled_patterns = [re.compile(pat, re.IGNORECASE) for pat in patterns]

        raw_scores: List[float] = []
        for line in lines:
            hit_count = sum(1 for pat in compiled_patterns if pat.search(line))
            raw_scores.append(float(hit_count))

        max_score = max(raw_scores) if raw_scores else 1.0
        if max_score == 0:
            return [LineScore(line_number=i + 1, score=0.0) for i in range(len(lines))]

        return [
            LineScore(line_number=i + 1, score=s / max_score)
            for i, s in enumerate(raw_scores)
        ]

    # ------------------------------------------------------------------
    # 上下文评分
    # ------------------------------------------------------------------

    def _context_based_scoring(
        self,
        file_content: str,
        vuln_desc: Dict[str, Any],
    ) -> List[LineScore]:
        """基于代码上下文的行级评分

        综合以下上下文信号：
        1. 数据流邻近度：与 sink 函数距离越近的行分数越高
        2. 控制流特征：条件分支、循环体内的 sink 调用分数更高
        3. 方法边界：方法定义行附近的 sink 调用更可疑
        4. 输入传播：包含参数 / 请求读取的行具有更高基础分

        Args:
            file_content: 文件完整内容
            vuln_desc: 漏洞描述字典

        Returns:
            List[LineScore]: 每行的上下文分数
        """
        lines = file_content.splitlines()
        total_lines = len(lines)
        if total_lines == 0:
            return []

        cwe_id = vuln_desc.get("cwe_id", "").upper()
        cwe_info = CWE_PATTERNS.get(cwe_id, {})
        sink_functions: List[str] = cwe_info.get("sink_functions", [])

        if not sink_functions:
            return [LineScore(line_number=i + 1, score=0.0) for i in range(total_lines)]

        # ---- 1. 定位 sink 行 ----
        sink_line_indices: List[int] = []
        sink_pattern = re.compile(
            "|".join(re.escape(sf) for sf in sink_functions),
            re.IGNORECASE,
        )
        for idx, line in enumerate(lines):
            if sink_pattern.search(line):
                sink_line_indices.append(idx)

        if not sink_line_indices:
            return [LineScore(line_number=i + 1, score=0.0) for i in range(total_lines)]

        # ---- 2. 数据流邻近度评分 ----
        # sink 行本身得 1.0，距离越远衰减越快（指数衰减）
        proximity_window = 15  # 邻近窗口
        decay_factor = 0.15    # 衰减系数

        proximity_scores = [0.0] * total_lines
        for sink_idx in sink_line_indices:
            for offset in range(-proximity_window, proximity_window + 1):
                target_idx = sink_idx + offset
                if 0 <= target_idx < total_lines:
                    distance = abs(offset)
                    score = 1.0 / (1.0 + decay_factor * distance * distance)
                    proximity_scores[target_idx] = max(
                        proximity_scores[target_idx], score,
                    )

        # ---- 3. 控制流特征评分 ----
        control_flow_pattern = re.compile(
            r"^\s*(if|else|for|while|do|switch|try|catch|case)\b",
        )
        control_scores = [0.0] * total_lines
        for idx, line in enumerate(lines):
            if control_flow_pattern.search(line):
                control_scores[idx] = 0.3
                # 控制流结构体内部（后续几行）也获得加分
                for inner_offset in range(1, 6):
                    inner_idx = idx + inner_offset
                    if inner_idx < total_lines:
                        control_scores[inner_idx] = max(
                            control_scores[inner_idx], 0.15,
                        )

        # ---- 4. 方法边界评分 ----
        method_def_pattern = re.compile(
            r"(?:public|private|protected|static|def|function|func|fn)\s+\w+\s*\(",
        )
        method_scores = [0.0] * total_lines
        for idx, line in enumerate(lines):
            if method_def_pattern.search(line):
                method_scores[idx] = 0.2
                for inner_offset in range(1, 4):
                    inner_idx = idx + inner_offset
                    if inner_idx < total_lines:
                        method_scores[inner_idx] = max(
                            method_scores[inner_idx], 0.1,
                        )

        # ---- 5. 输入传播评分 ----
        input_pattern = re.compile(
            r"(?:getParameter|getHeader|getInputStream|getReader|"
            r"request\.|@RequestParam|@PathVariable|@RequestBody|"
            r"sys\.argv|input\s*\(|scanf|fgets|argv|environ|"
            r"readLine|readBytes|getBody)\s*[\(\.]",
            re.IGNORECASE,
        )
        input_scores = [0.0] * total_lines
        for idx, line in enumerate(lines):
            if input_pattern.search(line):
                input_scores[idx] = 0.5
                # 输入读取后传播到后续几行
                for propagate_offset in range(1, 8):
                    prop_idx = idx + propagate_offset
                    if prop_idx < total_lines:
                        input_scores[prop_idx] = max(
                            input_scores[prop_idx],
                            0.5 * (1.0 - 0.08 * propagate_offset),
                        )

        # ---- 融合上下文子信号 ----
        context_raw = [0.0] * total_lines
        for idx in range(total_lines):
            # 取各子信号的最大值，再与邻近度加权
            base = max(
                control_scores[idx],
                method_scores[idx],
                input_scores[idx],
            )
            # 邻近度是主要信号，其他上下文作为加成
            combined = proximity_scores[idx] * 0.6 + base * 0.4
            context_raw[idx] = min(combined, 1.0)

        # 归一化
        max_ctx = max(context_raw) if context_raw else 1.0
        if max_ctx == 0:
            return [LineScore(line_number=i + 1, score=0.0) for i in range(total_lines)]

        return [
            LineScore(line_number=i + 1, score=s / max_ctx)
            for i, s in enumerate(context_raw)
        ]

    # ------------------------------------------------------------------
    # 分数融合
    # ------------------------------------------------------------------

    def _fuse_scores(
        self,
        token_scores: List[LineScore],
        pattern_scores: List[LineScore],
        context_scores: List[LineScore],
    ) -> List[LineScore]:
        """加权融合三路评分信号

        融合公式:
            final = token * 0.2 + pattern * 0.5 + context * 0.3

        Args:
            token_scores: token 相关性评分列表
            pattern_scores: 危险模式评分列表
            context_scores: 上下文评分列表

        Returns:
            List[LineScore]: 融合后的行级评分
        """
        # 以行数最多的为准（防御性编程，正常情况三者长度一致）
        max_len = max(len(token_scores), len(pattern_scores), len(context_scores))
        if max_len == 0:
            return []

        # 构建行号 -> 分数的映射，缺失补 0
        token_map = {ls.line_number: ls.score for ls in token_scores}
        pattern_map = {ls.line_number: ls.score for ls in pattern_scores}
        context_map = {ls.line_number: ls.score for ls in context_scores}

        # 收集所有行号
        all_line_numbers = sorted(
            set(token_map.keys())
            | set(pattern_map.keys())
            | set(context_map.keys())
        )

        fused: List[LineScore] = []
        for ln in all_line_numbers:
            t = token_map.get(ln, 0.0)
            p = pattern_map.get(ln, 0.0)
            c = context_map.get(ln, 0.0)
            final = t * WEIGHT_TOKEN + p * WEIGHT_PATTERN + c * WEIGHT_CONTEXT
            fused.append(LineScore(line_number=ln, score=final))

        logger.debug(
            "分数融合完成: 共 %d 行, 权重=(token=%.1f, pattern=%.1f, context=%.1f)",
            len(fused), WEIGHT_TOKEN, WEIGHT_PATTERN, WEIGHT_CONTEXT,
        )
        return fused

    # ------------------------------------------------------------------
    # Top-K 提取
    # ------------------------------------------------------------------

    def _get_top_k(
        self,
        line_scores: List[LineScore],
        k: int = 5,
    ) -> List[LineScore]:
        """返回 top-k 最可能含漏洞的代码行

        按分数降序排列，取前 k 行；分数相同时行号较小的优先。

        Args:
            line_scores: 全行评分列表
            k: 返回行数

        Returns:
            List[LineScore]: top-k 行评分列表（降序）
        """
        if not line_scores:
            return []

        sorted_scores = sorted(
            line_scores,
            key=lambda ls: (-ls.score, ls.line_number),
        )

        top_k = sorted_scores[:k]

        logger.debug(
            "Top-%d 提取完成: 最高分=%.4f (line %d), 最低分=%.4f (line %d)",
            k,
            top_k[0].score if top_k else 0.0,
            top_k[0].line_number if top_k else 0,
            top_k[-1].score if top_k else 0.0,
            top_k[-1].line_number if top_k else 0,
        )
        return top_k


# ---------------------------------------------------------------------------
# 便捷工厂函数
# ---------------------------------------------------------------------------

def create_locator(top_k: int = 5) -> LineLevelLocator:
    """创建行级漏洞定位器实例

    Args:
        top_k: 返回的最可能漏洞行数

    Returns:
        LineLevelLocator: 定位器实例
    """
    return LineLevelLocator(top_k=top_k)


def localize_file(
    file_path: str,
    file_content: str,
    vulnerability_desc: Dict[str, Any],
    top_k: int = 5,
) -> LocalizationResult:
    """便捷函数：对单文件执行行级漏洞定位

    Args:
        file_path: 文件路径
        file_content: 文件完整内容
        vulnerability_desc: 漏洞描述字典
        top_k: 返回的最可能漏洞行数

    Returns:
        LocalizationResult: 定位结果
    """
    locator = LineLevelLocator(top_k=top_k)
    return locator.localize(file_path, file_content, vulnerability_desc)


def localize_batch(
    files: List[Dict[str, str]],
    vulnerability_desc: Dict[str, Any],
    top_k: int = 5,
) -> LocalizationReport:
    """批量行级漏洞定位

    Args:
        files: 文件列表，每项包含 ``file_path`` 和 ``file_content``
        vulnerability_desc: 漏洞描述字典
        top_k: 返回的最可能漏洞行数

    Returns:
        LocalizationReport: 聚合定位报告
    """
    locator = LineLevelLocator(top_k=top_k)
    report = LocalizationReport()

    for file_info in files:
        result = locator.localize(
            file_path=file_info["file_path"],
            file_content=file_info["file_content"],
            vulnerability_desc=vulnerability_desc,
        )
        report.add_result(result)

    logger.info(
        "批量定位完成: %d 个文件, 平均置信度=%.4f",
        report.summary.get("total_files", 0),
        report.summary.get("avg_confidence", 0.0),
    )
    return report
