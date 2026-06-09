"""提示词注入检测规则

基于 OWASP AISVS C2.1 标准，检测代码中潜在的提示词注入漏洞。
"""

import re
from typing import Any, Dict, List, Optional, Union, Set
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class DirectPromptInjectionRule(BaseRule):
    """AI-SEC-001: 直接提示词注入检测

    检测用户输入直接拼接到系统提示词或 LLM API 调用中的不安全模式。

    AISVS reference: v1.0-C2.1.1
    CWE: CWE-1361 (Type Errors)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="AI-SEC-001",
            name="Direct Prompt Injection Detection",
            description="检测用户输入直接拼接到系统提示词或 LLM API 调用中的不安全模式。攻击者可通过构造恶意输入覆盖或注入新指令。参考: OWASP AISVS v1.0-C2.1.1",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-1361",
            references=[
                "https://owasp.org/www-project/ai-security/",
                "https://aisvs.owasp.org/",
                "https://github.com/mainlex/prompt-injection",
            ],
            tags=["ai", "prompt-injection", "llm", "security"],
        )
        super().__init__(metadata, config)

        self._user_input_patterns = [
            r"request\.[a-zA-Z_]+",
            r"request\.args",
            r"request\.json",
            r"request\.form",
            r"request\.data",
            r"params\[",
            r"args\[",
            r"form\[",
            r"json\[",
            r"input\s*\(",
            r"sys\.argv",
            r"os\.environ",
            r"\b\w+_[iI]nput\b",
            r"\buser_[a-zA-Z_]+\b",
            r"body\[",
            r"headers\[",
            r"query\[",
        ]

        self._llm_api_patterns = [
            r"openai\.[a-zA-Z_]+\.create",
            r"openai\.ChatCompletion\.create",
            r"openai\.Completion\.create",
            r"openai\.chat\.completions\.create",
            r"anthropic\.messages\.create",
            r"anthropic\.completions\.create",
            r"google\.generativeai\.generate_content",
            r"google\.ai\.generativelanguage\.v1beta2\.Service\.generate_content",
            r"cohere\.generate",
            r"cohere\.chat",
            r"aws\.bedrock\.invoke_model",
            r"bedrock\.invoke_model",
            r"llm\.generate",
            r"llm\.chat",
            r"chat\.send_message",
            r"model\.generate",
            r"model\.chat",
            r"Completion\.create",
            r"ChatCompletion\.create",
        ]

        self._dangerous_patterns = [
            (
                re.compile(
                    r"(?:system\s*[:=]\s*[\"']?" +
                    r"(?:.*?)?[\"']?\s*\+?\s*(?:f?[\"'][^\"']*(?:" +
                    "|".join(self._user_input_patterns) + r")[^\"']*[\"']|" +
                    "|".join(self._user_input_patterns) +
                    r"))",
                    re.IGNORECASE | re.DOTALL
                ),
                "系统提示词拼接用户输入"
            ),
            (
                re.compile(
                    r"(?:messages\s*=\s*\[.*?\{[^}]*(?:content\s*[:=]\s*(?:f?[\"'][^\"']*(?:" +
                    "|".join(self._user_input_patterns) + r")[^\"']*[\"']|" +
                    "|".join(self._user_input_patterns) + r")",
                    re.IGNORECASE | re.DOTALL
                ),
                "消息列表包含用户输入"
            ),
            (
                re.compile(
                    r"(?:prompt\s*[:=]\s*(?:f?[\"'][^\"']*(?:" +
                    "|".join(self._user_input_patterns) + r")[^\"']*[\"']|" +
                    "|".join(self._user_input_patterns) +
                    r"))",
                    re.IGNORECASE
                ),
                "Prompt 变量直接使用用户输入"
            ),
            (
                re.compile(
                    r"(?:system\s*[:=]\s*(?:f?[\"'][^\"']*\{[^}]*(?:" +
                    "|".join(self._user_input_patterns) + r")[^}]*\}[^\"']*[\"']|" +
                    "|".join(self._user_input_patterns) +
                    r"))",
                    re.IGNORECASE
                ),
                "f-string 系统提示词包含用户输入"
            ),
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行直接提示词注入检测

        Args:
            target: 检查目标（文件路径、代码内容或 AST 节点）

        Returns:
            规则执行结果列表
        """
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

        for pattern, description in self._dangerous_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")

                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()

                if self._is_llm_api_context(content, match.start()):
                    result = RuleResult(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        passed=False,
                        message=f"检测到潜在的直接提示词注入漏洞: {description}",
                        severity=self.metadata.severity,
                        confidence=0.85,
                        location={
                            "file": file_path,
                            "line": line_num,
                            "column": col_num,
                        },
                        code_snippet=code_snippet,
                        fix_suggestion="使用参数化或结构化方式传递用户输入，避免直接拼接。考虑使用消息模板或内容过滤。",
                        references=self.metadata.references,
                    )
                    results.append(result)

        return results

    def _is_llm_api_context(self, content: str, match_pos: int) -> bool:
        """检查匹配位置附近是否有 LLM API 调用上下文

        Args:
            content: 文件内容
            match_pos: 匹配位置

        Returns:
            是否在 LLM API 上下文中
        """
        context_window = 500
        start = max(0, match_pos - context_window)
        end = min(len(content), match_pos + context_window)
        context = content[start:end]

        for llm_pattern in self._llm_api_patterns:
            if re.search(llm_pattern, context, re.IGNORECASE):
                return True

        return False


class InstructionOverrideRule(BaseRule):
    """AI-SEC-002: 指令覆盖攻击检测

    检测提示词中常见的注入/劫持模式，如 "ignore previous instructions"。

    AISVS reference: v1.0-C2.1.2
    CWE: CWE-841 (Workflow Enforcement)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="AI-SEC-002",
            name="Instruction Override Detection",
            description="检测提示词中常见的指令覆盖/劫持攻击模式，如 'ignore previous instructions'、'disregard system prompt' 等。攻击者利用此类模式试图绕过系统提示词的安全限制。参考: OWASP AISVS v1.0-C2.1.2",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-841",
            references=[
                "https://owasp.org/www-project/ai-security/",
                "https://aisvs.owasp.org/",
                "https://arxiv.org/abs/2308.12813",
            ],
            tags=["ai", "prompt-injection", "jailbreak", "security"],
        )
        super().__init__(metadata, config)

        self._injection_patterns = [
            r"ignore\s+(?:all\s+)?previous\s+(?:instructions?|commands?|orders?)",
            r"disregard\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)",
            r"(?:forget|ignore)\s+(?:everything|all)\s+(?:you|I've|I)\s+(?:were|told|learned|said)",
            r"ignore\s+(?:your\s+)?(?:programming|constraints|guidelines)",
            r"new\s+instructions?:",
            r"(?:you\s+)?(?:are now|will now|should now)\s+(?:act as|be|follow)\s+[^.]{10,}",
            r"(?:for the purpose of|to)\s+(?:this|that)\s+(?:challenge|test|experiment)",
            r"(?:bypass|break|circumvent)\s+(?:your|these|the)\s+(?:safety|security|content)",
            r"(?:roleplay|pretend)\s+as\s+(?:a\s+)?(?:different|new|unrestricted)",
            r"\\boxed\{",
            r"\\[a-z]+\{[^}]+\}",
            r"<(?:script|style|iframe)[^>]*>",
            r"<\?xml[^>]*>",
            r"\[\[INST\]\][^\]]+\[\[/INST\]\]",
            r"<<SYS>>[^<]*<</SYS>>",
            r"<\|system\|>",
            r"<\|user\|>",
            r"#{3,}\s*(?:system|user|assistant)",
            r"---{3,}",
            r"END{2,}",
            r"={3,}",
            r"\^\\^",
            r"░" * 10,
            r"█" * 10,
            r"▓" * 10,
        ]

        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in self._injection_patterns
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行指令覆盖攻击检测

        Args:
            target: 检查目标（文件路径、代码内容或 AST 节点）

        Returns:
            规则执行结果列表
        """
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
                    message=f"检测到潜在的指令覆盖攻击模式: {match.group()[:50]}...",
                    severity=self.metadata.severity,
                    confidence=0.9,
                    location={
                        "file": file_path,
                        "line": line_num,
                        "column": col_num,
                    },
                    code_snippet=code_snippet,
                    fix_suggestion="实施输入过滤和上下文化隔离，使用提示词安全框架或 LLM 对话管理平台提供的能力。",
                    references=self.metadata.references,
                )
                results.append(result)

        return results


class ContextOverflowRule(BaseRule):
    """AI-SEC-003: 上下文窗口溢出检测

    检测缺少输入长度控制的 LLM API 调用，可能导致上下文窗口溢出或资源耗尽。

    AISVS reference: v1.0-C2.1.3
    CWE: CWE-400 (Resource Exhaustion)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="AI-SEC-003",
            name="Context Window Overflow Detection",
            description="检测缺少输入长度验证的 LLM API 调用，可能导致上下文窗口溢出、资源耗尽或服务中断。参考: OWASP AISVS v1.0-C2.1.3",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-400",
            references=[
                "https://owasp.org/www-project/ai-security/",
                "https://aisvs.owasp.org/",
                "https://platform.openai.com/docs/api-reference/introduction",
            ],
            tags=["ai", "prompt-injection", "resource-exhaustion", "security"],
        )
        super().__init__(metadata, config)

        self._llm_api_patterns = [
            r"openai\.[a-zA-Z_]+\.create",
            r"openai\.ChatCompletion\.create",
            r"openai\.Completion\.create",
            r"openai\.chat\.completions\.create",
            r"anthropic\.messages\.create",
            r"anthropic\.completions\.create",
            r"google\.generativeai\.generate_content",
            r"google\.ai\.generativelanguage\.v1beta2\.Service\.generate_content",
            r"cohere\.generate",
            r"cohere\.chat",
            r"aws\.bedrock\.invoke_model",
            r"bedrock\.invoke_model",
            r"llm\.generate",
            r"llm\.chat",
            r"chat\.send_message",
            r"model\.generate",
            r"model\.chat",
            r"Completion\.create",
            r"ChatCompletion\.create",
        ]

        self._user_input_patterns = [
            r"request\.[a-zA-Z_]+",
            r"request\.args",
            r"request\.json",
            r"request\.form",
            r"request\.data",
            r"params\[",
            r"args\[",
            r"form\[",
            r"json\[",
            r"input\s*\(",
            r"sys\.argv",
            r"os\.environ",
            r"\b\w+_[iI]nput\b",
            r"\buser_[a-zA-Z_]+\b",
            r"body\[",
            r"headers\[",
            r"query\[",
        ]

        self._length_check_patterns = [
            r"len\s*\(",
            r"max_length",
            r"truncate",
            r"slice\s*\(",
            r"\[:\s*\d+\]",
            r"\.split\s*\(\s*[\"'][^\"']*[\"']\s*,\s*\d+",
            r"if\s+len\(",
            r"assert\s+len\(",
        ]

        self._dangerous_patterns = [
            (
                re.compile(
                    r"(?:" + "|".join(self._llm_api_patterns) + r")" +
                    r"\s*\(" +
                    r"(?:[^)]*(?:" + "|".join(self._user_input_patterns) + r")[^)]*)?" +
                    r"\)",
                    re.IGNORECASE
                ),
                "LLM API 调用包含用户输入但无长度检查"
            ),
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行上下文窗口溢出检测

        Args:
            target: 检查目标（文件路径、代码内容或 AST 节点）

        Returns:
            规则执行结果列表
        """
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

        for pattern, description in self._dangerous_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")

                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()

                if not self._has_length_validation(content, match.start(), match.end()):
                    result = RuleResult(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        passed=False,
                        message=f"检测到潜在的上下文窗口溢出风险: {description}",
                        severity=self.metadata.severity,
                        confidence=0.75,
                        location={
                            "file": file_path,
                            "line": line_num,
                            "column": col_num,
                        },
                        code_snippet=code_snippet,
                        fix_suggestion="在调用 LLM API 前验证输入长度，使用截断、分块或拒绝过长输入的策略。",
                        references=self.metadata.references,
                    )
                    results.append(result)

        return results

    def _has_length_validation(self, content: str, start: int, end: int) -> bool:
        """检查是否有长度验证

        Args:
            content: 文件内容
            start: 匹配开始位置
            end: 匹配结束位置

        Returns:
            是否有长度验证
        """
        context_window = 800
        search_start = max(0, start - context_window)
        search_end = min(len(content), end + context_window)
        context = content[search_start:search_end]

        for length_pattern in self._length_check_patterns:
            if re.search(length_pattern, context, re.IGNORECASE):
                return True

        return False


__all__ = [
    "DirectPromptInjectionRule",
    "InstructionOverrideRule",
    "ContextOverflowRule",
]
