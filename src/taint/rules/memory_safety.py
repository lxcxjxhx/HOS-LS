"""内存安全漏洞检测规则（C/C++）

覆盖 CWE:
  - CWE-119: 缓冲区溢出（通用）
  - CWE-120: 经典缓冲区溢出（strcpy/gets 等）
  - CWE-122: 堆缓冲区溢出
  - CWE-125: 越界读取
  - CWE-134: 未控制的格式化字符串
  - CWE-190: 整数溢出/环绕
  - CWE-416: 释放后使用（Use-After-Free）
  - CWE-476: 空指针解引用
  - CWE-787: 越界写入

每个规则包含：
  - 模式匹配条件
  - 源/汇/传播规则
  - 修复建议
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MemorySafetyRule:
    """内存安全规则"""
    cwe_id: str
    name: str
    description: str
    severity: str
    source_patterns: List[str]       # 污点源匹配模式
    sink_patterns: List[str]         # 污点汇匹配模式
    propagation_patterns: List[str]  # 传播模式
    sanitizer_hints: List[str]       # 消毒器/防护提示
    fix_advice: str
    cvss_score: float = 7.5


# ---- 规则库 ----

_BUILTIN_RULES: List[MemorySafetyRule] = [
    # ── CWE-120: 经典缓冲区溢出 ──
    MemorySafetyRule(
        cwe_id="CWE-120",
        name="Buffer Overflow - strcpy/strcat",
        description="strcpy/strcat 无边界检查的拷贝可能导致传统缓冲区溢出",
        severity="critical",
        source_patterns=[r"recv\b", r"fread\b", r"read\b", r"argv", r"getenv\b", r"scanf\b"],
        sink_patterns=[r"\bstrcpy\b", r"\bstrcat\b", r"\bsprintf\b", r"\bgets\b", r"\bscanf\b"],
        propagation_patterns=[r"\bstrlen\b", r"\bmemcpy\b", r"\bmemmove\b", r"\bstrncpy\b"],
        sanitizer_hints=[r"strncpy\b", r"strncat\b", r"snprintf\b", r"_s\b"],
        fix_advice="使用 strncpy/strncat/snprintf 等有边界限制的函数，或在使用前验证源长度 ≤ 目标缓冲区大小",
        cvss_score=9.0,
    ),
    # ── CWE-787: 越界写入 ──
    MemorySafetyRule(
        cwe_id="CWE-787",
        name="Out-of-Bounds Write",
        description="基于攻击者控制索引的数组/指针越界写入",
        severity="critical",
        source_patterns=[r"argv", r"recv\b", r"fread\b", r"getenv\b", r"user\w*"],
        sink_patterns=[r"\[.*\]\s*=", r"\*.*\s*=\s*\w", r"memcpy\b"],
        propagation_patterns=[r"\w+\s*=\s*\w+", r"\w+\s*\+\s*\w+", r"\w+\s*\-"],
        sanitizer_hints=[r"CHECK\b", r"SAFE_", r"bound", r"limit", r"max"],
        fix_advice="在数组/缓冲区写入前验证索引值和偏移量是否在合法范围内",
        cvss_score=8.9,
    ),
    # ── CWE-125: 越界读取 ──
    MemorySafetyRule(
        cwe_id="CWE-125",
        name="Out-of-Bounds Read",
        description="数组/缓冲区越界读取可能导致信息泄露或崩溃",
        severity="high",
        source_patterns=[r"argv", r"recv\b", r"fread\b", r"getenv\b"],
        sink_patterns=[r"=\s*\w+\[", r"memcpy\b", r"memcmp\b", r"printf\b.*\["],
        propagation_patterns=[r"\w+\s*\+\s*\w+", r"\w+\s*\*\s*\w+", r"\w+\["],
        sanitizer_hints=[r"len\s*<", r"size\s*<=", r"CHECK"],
        fix_advice="在读取前验证索引/偏移量 < 缓冲区长度",
        cvss_score=7.5,
    ),
    # ── CWE-416: 释放后使用 ──
    MemorySafetyRule(
        cwe_id="CWE-416",
        name="Use-After-Free",
        description="内存释放后通过悬垂指针继续访问",
        severity="critical",
        source_patterns=[],
        sink_patterns=[r"\bfree\b", r"\bdelete\b"],
        propagation_patterns=[r"\*.*\s*=", r"->\w+", r"\w+\.\w+"],
        sanitizer_hints=[r"=\s*NULL", r"=\s*nullptr", r"reset\b"],
        fix_advice="free/delete 后立即将指针置 NULL；使用智能指针（C++）",
        cvss_score=8.5,
    ),
    # ── CWE-476: 空指针解引用 ──
    MemorySafetyRule(
        cwe_id="CWE-476",
        name="NULL Pointer Dereference",
        description="空指针解引用可能造成拒绝服务",
        severity="high",
        source_patterns=[],
        sink_patterns=[r"\bNULL\b", r"\bnullptr\b", r"\b0\b"],
        propagation_patterns=[r"\w+\s*=\s*\w+", r"\w+\s*->"],
        sanitizer_hints=[r"if\s*\(.*!=?\s*NULL", r"if\s*\(.*!=?\s*nullptr", r"assert\b"],
        fix_advice="解引用前始终检查指针是否为 NULL；使用断言或条件判断",
        cvss_score=7.0,
    ),
    # ── CWE-134: 格式化字符串 ──
    MemorySafetyRule(
        cwe_id="CWE-134",
        name="Uncontrolled Format String",
        description="攻击者控制的字符串直接作为 printf 系列格式化参数",
        severity="high",
        source_patterns=[r"argv", r"recv\b", r"fread\b", r"getenv\b", r"getchar\b"],
        sink_patterns=[r"\bprintf\b(?!.*\")", r"\bfprintf\b", r"\bsprintf\b", r"\bsyslog\b"],
        propagation_patterns=[r"\w+\s*=\s*\w+"],
        sanitizer_hints=[r'"[^"]*%[dsx]"', r'"%s"'],
        fix_advice="始终使用 printf(\"%s\", user_input) 而非 printf(user_input)",
        cvss_score=8.0,
    ),
    # ── CWE-190: 整数溢出 ──
    MemorySafetyRule(
        cwe_id="CWE-190",
        name="Integer Overflow / Wraparound",
        description="攻击者控制的输入参与整数运算，结果被用作缓冲区大小或索引",
        severity="high",
        source_patterns=[r"argv", r"recv\b", r"fread\b", r"getenv\b", r"atoi\b", r"strtol\b"],
        sink_patterns=[r"\bmalloc\b", r"\bcalloc\b", r"\brealloc\b", r"\[.*\b"],
        propagation_patterns=[r"\w+\s*\+\s*\w+", r"\w+\s*\*\s*\w+", r"\w+\s*\-\s*\w+"],
        sanitizer_hints=[r"MAX_", r"SIZE_MAX", r"INT_MAX", r"CHECK"],
        fix_advice="在整数运算前检查操作数范围；使用安全整数运算库或饱和算术",
        cvss_score=7.8,
    ),
    # ── CWE-122: 堆缓冲区溢出 ──
    MemorySafetyRule(
        cwe_id="CWE-122",
        name="Heap-based Buffer Overflow",
        description="堆分配内存的溢出（realloc 未更新指针、堆拷贝无边界）",
        severity="critical",
        source_patterns=[r"argv", r"recv\b", r"fread\b"],
        sink_patterns=[r"\brealloc\b", r"\bmalloc\b.*\[", r"\bcalloc\b"],
        propagation_patterns=[r"\w+\s*=\s*\w+", r"memcpy\b", r"strcpy\b"],
        sanitizer_hints=[r"if\s*\(\s*\w+\s*\)", r"if\s*\(.*NULL"],
        fix_advice="realloc 返回值始终赋给临时指针并检查；堆拷贝前验证目标容量；使用安全字符串函数",
        cvss_score=8.8,
    ),
]


class MemorySafetyRules:
    """内存安全规则管理器"""

    def __init__(self, rules: Optional[List[MemorySafetyRule]] = None) -> None:
        self._rules: Dict[str, MemorySafetyRule] = {}
        for r in (rules or _BUILTIN_RULES):
            self._rules[r.cwe_id] = r

    def get_rule(self, cwe_id: str) -> Optional[MemorySafetyRule]:
        return self._rules.get(cwe_id)

    def list_rules(self) -> List[MemorySafetyRule]:
        return list(self._rules.values())

    def get_cwe_ids(self) -> List[str]:
        return list(self._rules.keys())

    def get_sink_patterns(self, cwe_id: str) -> List[str]:
        rule = self._rules.get(cwe_id)
        return rule.sink_patterns if rule else []

    def get_source_patterns(self, cwe_id: str) -> List[str]:
        rule = self._rules.get(cwe_id)
        return rule.source_patterns if rule else []

    def get_fix_advice(self, cwe_id: str) -> str:
        rule = self._rules.get(cwe_id)
        return rule.fix_advice if rule else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            cwe: {
                "name": r.name,
                "severity": r.severity,
                "cvss": r.cvss_score,
                "description": r.description,
                "fix": r.fix_advice,
            }
            for cwe, r in self._rules.items()
        }


_instance: Optional[MemorySafetyRules] = None


def get_memory_safety_rules() -> MemorySafetyRules:
    """获取全局内存安全规则实例"""
    global _instance
    if _instance is None:
        _instance = MemorySafetyRules()
    return _instance
