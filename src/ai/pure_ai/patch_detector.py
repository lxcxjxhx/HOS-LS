"""确定性安全修复模式检测器

通过纯正则/AST 扫描识别代码中已有的安全防御措施（0 LLM token）。
主要用途：在 Agent-3/6 分析前提供先验"已修复"证据，直接打压 patched 误报。

检测范围（覆盖 RepoPairBench 主要 CWE）：
  CWE-89  SQL 注入防御  ：参数化查询、ORM bindparam / execute(text, {})
  CWE-78  命令注入防御  ：subprocess shell=False + list 参数
  CWE-22  路径遍历防御  ：Path.resolve / os.path.normpath / is_relative_to
  CWE-79  XSS 防御     ：html.escape / bleach.clean / markupsafe / Jinja2 autoescaping
  CWE-918 SSRF 防御    ：域名白名单校验、私有 IP 过滤
  CWE-502 反序列化防御  ：pickle 使用受信源检查 / jsonpickle 白名单
  CWE-611 XXE 防御     ：lxml 禁用外部实体 / defusedxml
  CWE-352 CSRF 防御    ：Flask-WTF CSRFProtect / Django CSRF middleware
  CWE-312 明文存储防御  ：bcrypt / argon2 / hashlib.pbkdf2 / passlib
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class FixPattern:
    cwe_id: str
    pattern_name: str
    matched_text: str
    line_no: int
    confidence: float = 1.0  # 确定性检测，默认最高


@dataclass
class PatchDetectionResult:
    file_path: str
    fix_patterns: List[FixPattern] = field(default_factory=list)
    # cwe_id -> list of FixPattern
    by_cwe: Dict[str, List[FixPattern]] = field(default_factory=dict)

    def has_fix_for(self, cwe_id: str) -> bool:
        return bool(self.by_cwe.get(cwe_id))

    def has_fix_near_location(
        self, cwe_id: str, location: str, max_line_distance: int = 8
    ) -> bool:
        """Return whether a same-CWE defense occurs near ``path:line``.

        A defense elsewhere in a file cannot establish that the reported source-to-sink
        path is safe. Locations without a numeric line intentionally do not match.
        """
        match = re.search(r":(\d+)(?:\D*)$", str(location))
        if not match:
            return False
        reported_line = int(match.group(1))
        return any(
            abs(pattern.line_no - reported_line) <= max_line_distance
            for pattern in self.by_cwe.get(cwe_id, [])
        )

    def is_likely_patched(self) -> bool:
        return len(self.fix_patterns) > 0

    def summary(self) -> str:
        if not self.fix_patterns:
            return "未检测到安全修复模式"
        lines = ["[确定性安全修复模式检测结果]"]
        for cwe, patterns in self.by_cwe.items():
            names = ", ".join(p.pattern_name for p in patterns[:3])
            lines.append(f"  ✅ {cwe}: {names} (行 {patterns[0].line_no})")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 各 CWE 的确定性 fix pattern 定义
# ---------------------------------------------------------------------------

# 每条规则: (cwe_id, pattern_name, regex)
_PATTERNS: List[tuple] = [

    # ── CWE-89 SQL 注入防御 ──────────────────────────────────────────────────
    ("CWE-89", "SQLAlchemy_parameterized",
     r"(execute\s*\(\s*text\s*\(|\.execute\s*\([^)]*:\w+|bindparams|:param\b)"),
    ("CWE-89", "SQLAlchemy_ORM_method",
     r"\.(filter\s*\(|filter_by\s*\(|query\s*\()"),
    ("CWE-89", "psycopg2_parameterized",
     r"cursor\.execute\s*\([^)]*%s|cursor\.execute\s*\([^)]*\?"),
    ("CWE-89", "Django_ORM_filter",
     r"(objects\.filter|objects\.get|objects\.exclude|annotate)\s*\("),
    ("CWE-89", "PyMysql_parameterized",
     r"execute\s*\(\s*['\"][^'\"]*(?:%s|\?)[^'\"]*['\"]"),

    # ── CWE-78 命令注入防御 ──────────────────────────────────────────────────
    ("CWE-78", "subprocess_no_shell",
     r"subprocess\.(run|call|check_output|Popen)\s*\(\s*\["),
    ("CWE-78", "subprocess_shell_false",
     r"shell\s*=\s*False"),
    ("CWE-78", "shlex_quote",
     r"shlex\.(quote|split)\s*\("),

    # ── CWE-22 路径遍历防御 ──────────────────────────────────────────────────
    ("CWE-22", "pathlib_resolve",
     r"\.(resolve|is_relative_to)\s*\("),
    ("CWE-22", "os_path_normpath",
     r"os\.path\.(normpath|realpath|abspath)\s*\("),
    ("CWE-22", "safe_join",
     r"(safe_join|send_from_directory)\s*\("),
    ("CWE-22", "werkzeug_safe_join",
     r"from werkzeug.*import.*safe_join|werkzeug\.utils\.safe_join"),

    # ── CWE-79 XSS 防御 ──────────────────────────────────────────────────────
    ("CWE-79", "html_escape",
     r"html\.escape\s*\("),
    ("CWE-79", "markupsafe_escape",
     r"markupsafe\.escape\s*\(|Markup\.escape\s*\("),
    ("CWE-79", "bleach_clean",
     r"bleach\.(clean|linkify)\s*\("),
    ("CWE-79", "jinja2_autoescaping",
     r"(autoescape\s*=\s*True|Environment\s*\([^)]*autoescape)"),

    # ── CWE-918 SSRF 防御 ────────────────────────────────────────────────────
    ("CWE-918", "private_ip_filter",
     r"(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|192\.168|172\.(1[6-9]|2\d|3[01])).*not.*allow|"
     r"(ipaddress|ip_address|is_private|is_loopback|is_link_local)"),
    ("CWE-918", "url_whitelist_check",
     r"(allowed_hosts|ALLOWED_HOSTS|whitelist.*url|url.*whitelist)"),

    # ── CWE-502 反序列化防御 ──────────────────────────────────────────────────
    ("CWE-502", "defusedxml_import",
     r"import defusedxml|from defusedxml"),
    ("CWE-502", "pickle_hmac_verify",
     r"hmac\.(compare_digest|new|verify).*pickle|pickle.*hmac"),

    # ── CWE-611 XXE 防御 ─────────────────────────────────────────────────────
    ("CWE-611", "lxml_no_external",
     r"no_network\s*=\s*True|resolve_entities\s*=\s*False|"
     r"XMLConstants\.ACCESS_EXTERNAL|etree\.(XMLParser|parse).*resolve_entities"),
    ("CWE-611", "defusedxml_parse",
     r"defusedxml\.(lxml|ElementTree|minidom|sax|expatbuilder)"),

    # ── CWE-352 CSRF 防御 ────────────────────────────────────────────────────
    ("CWE-352", "flask_wtf_csrf",
     r"CSRFProtect\s*\(|csrf_protect"),
    ("CWE-352", "django_csrf_middleware",
     r"CsrfViewMiddleware|csrf_token|csrf_protect"),

    # ── CWE-312 密码明文存储防御 ──────────────────────────────────────────────
    ("CWE-312", "bcrypt_hash",
     r"bcrypt\.(hashpw|hash|gensalt|checkpw)\s*\("),
    ("CWE-312", "passlib_hash",
     r"passlib\.(hash|context)|\.hash\s*\(|\.verify\s*\("),
    ("CWE-312", "pbkdf2_hmac",
     r"hashlib\.pbkdf2_hmac\s*\("),
    ("CWE-312", "argon2_hash",
     r"argon2\.(hash|verify|PasswordHasher)"),
    ("CWE-312", "werkzeug_password",
     r"generate_password_hash|check_password_hash"),

    # ── 通用输入验证防御 ──────────────────────────────────────────────────────
    ("GENERIC", "input_validation_decorator",
     r"@(validates|validator|field_validator|validate)\s*[\(\n]"),
    ("GENERIC", "pydantic_model",
     r"(BaseModel|Field\s*\(.*min_length|constr|validator)"),
    ("GENERIC", "wtforms_validators",
     r"DataRequired|Length|Email|Regexp|ValidationError"),
]

# 编译正则（提升多文件分析性能）
_COMPILED = [
    (cwe, name, re.compile(pat, re.IGNORECASE | re.MULTILINE))
    for cwe, name, pat in _PATTERNS
]


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def analyze(file_path: str, file_content: Optional[str] = None) -> PatchDetectionResult:
    """对单个文件执行确定性安全修复模式检测。

    Args:
        file_path:    文件路径（用于读取内容，若 file_content 已提供则跳过 IO）
        file_content: 可选的文件内容字符串（避免重复 IO）

    Returns:
        PatchDetectionResult，包含所有命中的修复模式及按 CWE 分组结果
    """
    result = PatchDetectionResult(file_path=file_path)

    if file_content is None:
        try:
            file_content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return result

    if not file_content:
        return result

    lines = file_content.splitlines()

    for cwe_id, pattern_name, compiled_re in _COMPILED:
        for m in compiled_re.finditer(file_content):
            # 计算行号（1-based）
            line_no = file_content[: m.start()].count("\n") + 1
            matched_text = m.group(0)[:80]  # 截断过长匹配

            fp = FixPattern(
                cwe_id=cwe_id,
                pattern_name=pattern_name,
                matched_text=matched_text,
                line_no=line_no,
            )
            result.fix_patterns.append(fp)
            result.by_cwe.setdefault(cwe_id, []).append(fp)
            # 每个 pattern 在同文件只记录第一次命中（避免重复计数）
            break

    return result


def format_for_prompt(result: PatchDetectionResult) -> str:
    """将检测结果格式化为 Jinja2 prompt 可注入的文本块。

    Returns:
        可直接嵌入 prompt 的中文 Markdown 段落
    """
    if not result.fix_patterns:
        return "（未检测到安全修复模式）"

    lines = [
        "【确定性安全修复模式检测（需结合数据流复核）】",
        "以下安全防御措施已在代码中确认存在：",
    ]
    for cwe_id, patterns in result.by_cwe.items():
        for fp in patterns[:2]:  # 每 CWE 最多展示 2 条
            lines.append(
                f"  ✅ [{cwe_id}] {fp.pattern_name}  行 {fp.line_no}：`{fp.matched_text}`"
            )

    lines += [
        "",
        "**使用规则**：",
        "- 修复模式是可验证证据；仅当其覆盖同一 source-to-sink 路径且邻近风险位置时，才能 REJECTED",
        "- GENERIC 类型的输入验证仅用于降低置信度，不能单独否定漏洞",
    ]
    return "\n".join(lines)
