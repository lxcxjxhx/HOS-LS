"""编码与规范化检测规则

检测代码中潜在的编码和规范化安全问题，包括同形文字攻击、Unicode规范化问题和双向文本注入。
"""

import re
from typing import Any, Dict, List, Optional, Union

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class HomoglyphAttackRule(BaseRule):
    """同形文字攻击检测规则

    检测视觉上相似的Unicode字符被用于欺骗的可能性。
    例如： Cyrillic/Latin lookalikes, Greek letters等

    AISVS: v1.0-C2.2.1
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="AI-SEC-010",
            name="Homoglyph Attack Detection",
            description="检测视觉上相似的Unicode字符（ Cyrillic/Latin lookalikes, Greek letters等）被用于欺骗的风险",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            references=[
                "https://unicode.org/reports/tr39/#Homoglyph_Detection",
                "https://cwe.mitre.org/data/definitions/176.html",
                "AISVS-v1.0-C2.2.1",
            ],
            tags=["unicode", "homoglyph", "confusable", "deception", "ai-security"],
        )
        super().__init__(metadata, config)

        self._homoglyph_ranges = [
            (0x0041, 0x005A),  # Latin uppercase A-Z
            (0x0410, 0x042F),  # Cyrillic uppercase А-Я
            (0x0391, 0x03A9),  # Greek uppercase Α-Ω
            (0x0061, 0x007A),  # Latin lowercase a-z
            (0x0430, 0x044F),  # Cyrillic lowercase а-я
            (0x03B1, 0x03C9),  # Greek lowercase α-ω
            (0x0030, 0x0039),  # Digits 0-9
            (0x004F, 0x004F),  # Latin O (confusable with Cyrillic О)
            (0x041E, 0x041E),  # Cyrillic О (confusable with Latin O)
            (0x0043, 0x0043),  # Latin C (confusable with Cyrillic С)
            (0x0421, 0x0421),  # Cyrillic С (confusable with Latin C)
            (0x0050, 0x0050),  # Latin P (confusable with Cyrillic Р)
            (0x0420, 0x0420),  # Cyrillic Р (confusable with Latin P)
            (0x0056, 0x0056),  # Latin V (confusable with Cyrillic В)
            (0x0412, 0x0412),  # Cyrillic В (confusable with Latin V)
            (0x0045, 0x0045),  # Latin E (confusable with Cyrillic Е)
            (0x0415, 0x0415),  # Cyrillic Е (confusable with Latin E)
            (0x0054, 0x0054),  # Latin T (confusable with Cyrillic Т)
            (0x0422, 0x0422),  # Cyrillic Т (confusable with Latin T)
        ]

        self._confusable_patterns = [
            r"[\u0410-\u042F][\u0430-\u044F]+",  # Cyrillic words that could mimic Latin
            r"[\u0391-\u03A9][\u03B1-\u03C9]+",  # Greek words
            r"[a-zA-Z][\u0430-\u044F\u0410-\u042F]+",  # Mixed Latin-Cyrillic
            r"[\u0430-\u044F\u0410-\u042F][a-zA-Z]+",  # Mixed Cyrillic-Latin
        ]

        self._compiled_patterns = [re.compile(p) for p in self._confusable_patterns]

        self._dangerous_strings = [
            "admin", "login", "password", "signin", "account",
            "user", "root", "administrator", "system",
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行同形文字攻击检测

        Args:
            target: 检查目标（文件路径、代码内容或 AST 节点）

        Returns:
            规则执行结果列表
        """
        from pathlib import Path
        results = []

        if isinstance(target, Path):
            try:
                content = target.read_text(encoding="utf-8")
            except Exception:
                return results
            file_path = str(target)
        elif isinstance(target, str):
            content = target
            file_path = "<string>"
        elif isinstance(target, dict):
            content = target.get("content", "")
            file_path = target.get("file_path", "<unknown>")
        else:
            return results

        lines = content.split("\n")

        for pattern in self._compiled_patterns:
            for match in pattern.finditer(content):
                matched_text = match.group()
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")

                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = matched_text

                if self._is_dangerous_homoglyph(matched_text):
                    result = RuleResult(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        passed=False,
                        message=f"检测到潜在的同形文字攻击: 可疑的Unicode字符组合 '{matched_text}' 可能用于欺骗",
                        severity=self.metadata.severity,
                        confidence=0.75,
                        location={
                            "file": file_path,
                            "line": line_num,
                            "column": col_num,
                        },
                        code_snippet=code_snippet,
                        fix_suggestion="使用 unicodedata.normalize('NFC', text) 规范化字符串，或使用明确的字符列表验证输入",
                        references=self.metadata.references,
                    )
                    results.append(result)

        return results

    def _is_dangerous_homoglyph(self, text: str) -> bool:
        """检查文本是否包含危险的同形文字

        Args:
            text: 待检查的文本

        Returns:
            是否为危险的同形文字
        """
        text_lower = text.lower()
        for dangerous in self._dangerous_strings:
            if dangerous in text_lower:
                return True
        return False


class UnicodeNormalizationRule(BaseRule):
    """Unicode规范化问题检测规则

    检测缺少NFC规范化可能导致的安全问题。
    不同的Unicode字符可能表示相同的视觉字符，但二进制表示不同。

    AISVS: v1.0-C2.2.1
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="AI-SEC-011",
            name="Unicode Normalization Issue Detection",
            description="检测字符串操作缺少 unicodedata.normalize('NFC', ...) 规范化，可能导致同一字符的不同表示被当作不同字符处理",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            references=[
                "https://unicode.org/reports/tr15/",
                "https://cwe.mitre.org/data/definitions/176.html",
                "AISVS-v1.0-C2.2.1",
            ],
            tags=["unicode", "normalization", "nfc", "ai-security"],
        )
        super().__init__(metadata, config)

        self._string_operations = [
            r"==\s*[\"']",
            r"!=\s*[\"']",
            r"\.replace\s*\(",
            r"\.split\s*\(",
            r"\.lower\s*\(",
            r"\.upper\s*\(",
            r"\.strip\s*\(",
            r"hash\s*\(",
            r"in\s+[\"']",
            r"[\"']\s+in\s+",
            r"assert\s+",
            r"if\s+",
        ]

        self._safe_normalization_patterns = [
            r"unicodedata\.normalize\s*\(\s*['\"]NFC['\"]",
            r"unicodedata\.normalize\s*\(\s*['\"]NFKC['\"]",
            r"normalize\s*\(\s*['\"]NFC['\"]",
            r"normalize\s*\(\s*['\"]NFKC['\"]",
        ]

        self._dangerous_patterns = [
            re.compile(
                r"(?:"
                + "|".join(self._string_operations)
                + r")\s*(?:f?[\"'][^\"']*[\"']|input\(|sys\.argv|\w+\[)"
            ),
            re.compile(r"(?:password|passwd|pwd|secret|token|auth)\s*(?:==|!=|\b(?:in|not in)\b)\s*"),
        ]

        self._compiled_safe_patterns = [re.compile(p) for p in self._safe_normalization_patterns]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行Unicode规范化问题检测

        Args:
            target: 检查目标（文件路径、代码内容或 AST 节点）

        Returns:
            规则执行结果列表
        """
        from pathlib import Path
        results = []

        if isinstance(target, Path):
            try:
                content = target.read_text(encoding="utf-8")
            except Exception:
                return results
            file_path = str(target)
        elif isinstance(target, str):
            content = target
            file_path = "<string>"
        elif isinstance(target, dict):
            content = target.get("content", "")
            file_path = target.get("file_path", "<unknown>")
        else:
            return results

        lines = content.split("\n")

        has_normalization = any(
            pattern.search(content) for pattern in self._compiled_safe_patterns
        )

        if has_normalization:
            return results

        for pattern in self._dangerous_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")

                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()

                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message="检测到潜在的Unicode规范化问题: 字符串比较/操作可能未进行NFC规范化",
                    severity=self.metadata.severity,
                    confidence=0.65,
                    location={
                        "file": file_path,
                        "line": line_num,
                        "column": col_num,
                    },
                    code_snippet=code_snippet,
                    fix_suggestion="使用 unicodedata.normalize('NFC', text) 对字符串进行规范化后再进行比较或操作",
                    references=self.metadata.references,
                )
                results.append(result)

        return results


class BidirectionalTextInjectionRule(BaseRule):
    """双向文本注入检测规则

    检测 U+202E (RIGHT-TO-LEFT OVERRIDE) 或类似字符，可能被用于欺骗性地改变文本方向。

    AISVS: v1.0-C2.2.1
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="AI-SEC-012",
            name="Bidirectional Text Injection Detection",
            description="检测潜在的双向文本注入（ RTL/LTR 覆盖）， U+202E 等字符可能被用于改变文本显示方向进行欺骗",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            references=[
                "https://unicode.org/reports/tr9/",
                "https://cwe.mitre.org/data/definitions/176.html",
                "AISVS-v1.0-C2.2.1",
            ],
            tags=["unicode", "bidirectional", "rtl", "ltr", "injection", "ai-security"],
        )
        super().__init__(metadata, config)

        self._bidi_characters = [
            (0x202A, "LEFT-TO-RIGHT EMBEDDING"),
            (0x202B, "RIGHT-TO-LEFT EMBEDDING"),
            (0x202C, "POP DIRECTIONAL FORMATTING"),
            (0x202D, "LEFT-TO-RIGHT OVERRIDE"),
            (0x202E, "RIGHT-TO-LEFT OVERRIDE"),
            (0x2066, "LEFT-TO-RIGHT ISOLATE"),
            (0x2067, "RIGHT-TO-LEFT ISOLATE"),
            (0x2068, "FIRST STRONG ISOLATE"),
            (0x2069, "POP DIRECTIONAL ISOLATE"),
        ]

        self._bidi_hex_patterns = [
            r"\\u202[ABCDE]",
            r"\\u206[6789]",
            r"\\x202[ABCDE]",
            r"\\x206[6789]",
        ]

        self._bidi_pattern = re.compile(
            r"[" + "".join(chr(c[0]) for c in self._bidi_characters) + r"]"
        )

        self._compiled_hex_patterns = [re.compile(p) for p in self._bidi_hex_patterns]

        self._dangerous_contexts = [
            "file",
            "path",
            "url",
            "uri",
            "link",
            "filename",
            "dir",
            "folder",
            "ext",
            "extension",
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行双向文本注入检测

        Args:
            target: 检查目标（文件路径、代码内容或 AST 节点）

        Returns:
            规则执行结果列表
        """
        from pathlib import Path
        results = []

        if isinstance(target, Path):
            try:
                content = target.read_text(encoding="utf-8")
            except Exception:
                return results
            file_path = str(target)
        elif isinstance(target, str):
            content = target
            file_path = "<string>"
        elif isinstance(target, dict):
            content = target.get("content", "")
            file_path = target.get("file_path", "<unknown>")
        else:
            return results

        lines = content.split("\n")

        for pattern in self._compiled_hex_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")

                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()

                bidi_name = self._get_bidi_name(match.group())

                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到潜在的双向文本注入: 发现 {bidi_name} (U+{ord(match.group()):04X}) 字符",
                    severity=self.metadata.severity,
                    confidence=0.85,
                    location={
                        "file": file_path,
                        "line": line_num,
                        "column": col_num,
                    },
                    code_snippet=code_snippet,
                    fix_suggestion="避免使用双向覆盖字符，使用明确的文本方向标记或内容过滤",
                    references=self.metadata.references,
                )
                results.append(result)

        for match in self._bidi_pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            col_num = match.start() - content[: match.start()].rfind("\n")

            if line_num <= len(lines):
                code_snippet = lines[line_num - 1].strip()
            else:
                code_snippet = match.group()

            bidi_name = self._get_bidi_name(match.group())

            if self._is_in_dangerous_context(code_snippet):
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到潜在的双向文本注入: 发现 {bidi_name} (U+{ord(match.group()):04X}) 字符在危险上下文中",
                    severity=self.metadata.severity,
                    confidence=0.9,
                    location={
                        "file": file_path,
                        "line": line_num,
                        "column": col_num,
                    },
                    code_snippet=code_snippet,
                    fix_suggestion="避免使用双向覆盖字符，使用明确的文本方向标记或内容过滤",
                    references=self.metadata.references,
                )
                results.append(result)

        return results

    def _get_bidi_name(self, char: str) -> str:
        """获取双向字符的名称

        Args:
            char: Unicode字符

        Returns:
            字符名称
        """
        for code, name in self._bidi_characters:
            if ord(char) == code:
                return name
        return "UNKNOWN"

    def _is_in_dangerous_context(self, code_line: str) -> bool:
        """检查代码行是否在危险上下文中

        Args:
            code_line: 代码行

        Returns:
            是否在危险上下文中
        """
        code_lower = code_line.lower()
        for context in self._dangerous_contexts:
            if context in code_lower:
                return True
        return False