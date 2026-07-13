"""AI 模型输出控制检测规则

基于 AISVS C7 标准的 AI 模型输出安全检测规则。
检测模型输出相关的安全问题，包括未验证输出、Schema验证缺失、幻觉风险和安全过滤器缺失。
"""

import re
from typing import Any, Dict, List, Optional, Union

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class UnvalidatedModelOutputRule(BaseRule):
    """AI-SEC-020: 未验证的模型输出

    检测模型输出直接用于危险操作而未进行验证的模式。
    例如：模型输出用于 SQL 查询、命令执行、文件操作等。

    AISVS: v1.0-C7.1.3
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="AI-SEC-020",
            name="Unvalidated Model Output",
            description="检测模型输出直接用于危险操作而未进行验证的问题，可能导致注入攻击",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-94",
            references=[
                "AISVS-v1.0-C7.1.3",
                "https://owasp.org/www-project-ai-security/",
                "https://cwe.mitre.org/data/definitions/94.html",
            ],
            tags=["ai", "model-output", "injection", "unvalidated", "AISVS-C7"],
        )
        super().__init__(metadata, config)

        self._model_output_patterns = [
            r"response\.text",
            r"response\.content",
            r"output\.text",
            r"message\.content",
            r"completion\.text",
            r"result\.text",
            r"llm\.response",
            r"model\.output",
            r"chat_completion",
            r"create_completion",
            r"generate\(",
        ]

        self._dangerous_sinks = [
            r"execute\s*\(",
            r"exec\s*\(",
            r"eval\s*\(",
            r"system\s*\(",
            r"os\.system",
            r"os\.popen",
            r"subprocess",
            r"cursor\.execute",
            r"db\.execute",
            r"conn\.execute",
            r"\.query\s*\(",
            r"raw\s*\(",
            r"sql\s*=",
            r"open\s*\(",
            r"file\s*\(",
            r"__import__",
            r"compile\s*\(",
            r"eval\s*\(",
            r"child_process\.exec",
            r"child_process\.spawn",
            r"new\s+Function",
            r"setTimeout",
            r"setInterval",
        ]

        self._validation_patterns = [
            r"validate\s*\(",
            r"sanitize\s*\(",
            r"escape\s*\(",
            r"check\s*\(",
            r"verify\s*\(",
            r"schema\.validate",
            r"jsonschema\.validate",
            r"pydantic",
            r"marshmallow",
            r"ajv\.validate",
            r"zod\.parse",
        ]

        self._compiled_model_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._model_output_patterns
        ]
        self._compiled_dangerous_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._dangerous_sinks
        ]
        self._compiled_validation_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._validation_patterns
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
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

        for line_num, line in enumerate(lines, 1):
            has_model_output = any(
                pattern.search(line) for pattern in self._compiled_model_patterns
            )
            has_dangerous_sink = any(
                pattern.search(line) for pattern in self._compiled_dangerous_patterns
            )

            if has_model_output and has_dangerous_sink:
                has_validation = any(
                    pattern.search(line) for pattern in self._compiled_validation_patterns
                )

                if not has_validation:
                    result = RuleResult(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        passed=False,
                        message=f"检测到未验证的模型输出用于危险操作: {line.strip()[:80]}",
                        severity=self.metadata.severity,
                        confidence=0.85,
                        location={"file": file_path, "line": line_num, "column": 1},
                        code_snippet=line.strip(),
                        fix_suggestion="在使用模型输出前进行验证，使用 schema 验证输入或 sanitize 函数清理内容",
                        references=self.metadata.references,
                    )
                    results.append(result)

        return results


class SchemaValidationMissingRule(BaseRule):
    """AI-SEC-021: Schema 验证缺失

    检测 LLM API 调用时缺少响应格式验证的问题。
    例如：OpenAI 调用缺少 response_format 参数。

    AISVS: v1.0-C7.1.1
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="AI-SEC-021",
            name="Schema Validation Missing",
            description="检测 LLM API 调用时缺少响应格式验证，可能导致模型输出解析错误或安全问题",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-20",
            references=[
                "AISVS-v1.0-C7.1.1",
                "https://platform.openai.com/docs/api-reference/chat/create",
                "https://cwe.mitre.org/data/definitions/20.html",
            ],
            tags=["ai", "schema", "validation", "response-format", "AISVS-C7"],
        )
        super().__init__(metadata, config)

        self._llm_api_patterns = [
            r"openai\.(ChatCompletion|Completion)\.create",
            r"OpenAI\(.*\)\.chat\.completions\.create",
            r"openai\.create_chat_completion",
            r"client\.chat\.completions\.create",
            r"anthropic\.messages\.create",
            r"model\.invoke",
            r"llm\.invoke",
            r"chat\.send_message",
            r"chat\.create",
            r"completion\.create",
            r"generate_content",
        ]

        self._schema_validation_patterns = [
            r"response_format\s*=",
            r"response_schema\s*=",
            r"schema\s*=",
            r"json_schema\s*=",
            r"output_schema\s*=",
            r"structure\s*=",
            r"response\.format",
            r"StructuredOutput",
            r"JsonSchema",
            r"output_parser",
            r"pydantic",
            r"function_call\s*=",
            r"tools\s*=",
        ]

        self._compiled_llm_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._llm_api_patterns
        ]
        self._compiled_schema_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._schema_validation_patterns
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
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

        llm_call_lines = []
        for line_num, line in enumerate(lines, 1):
            if any(pattern.search(line) for pattern in self._compiled_llm_patterns):
                llm_call_lines.append((line_num, line))

        for line_num, line in llm_call_lines:
            context_lines = max(0, line_num - 5), min(len(lines), line_num + 5)
            context = "\n".join(lines[context_lines[0]:context_lines[1]])

            has_schema_validation = any(
                pattern.search(context) for pattern in self._compiled_schema_patterns
            )

            if not has_schema_validation:
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到 LLM API 调用缺少 Schema 验证",
                    severity=self.metadata.severity,
                    confidence=0.75,
                    location={"file": file_path, "line": line_num, "column": 1},
                    code_snippet=line.strip(),
                    fix_suggestion="使用 response_format 或 json_schema 参数指定输出格式，使用 OpenAI 的 response_format 参数或 Pydantic 模型",
                    references=self.metadata.references,
                )
                results.append(result)

        return results


class HallucinationRiskRule(BaseRule):
    """AI-SEC-022: 幻觉风险

    检测模型输出包含事实性断言但缺少检索增强(RAG)或验证的问题。
    模型可能在不知道答案时编造信息。

    AISVS: v1.0-C7.2.1
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="AI-SEC-022",
            name="Hallucination Risk",
            description="检测模型输出包含事实性断言但缺少外部知识检索增强，可能导致幻觉内容",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-1105",
            references=[
                "AISVS-v1.0-C7.2.1",
                "https://arxiv.org/abs/2207.13251",
                "https://cwe.mitre.org/data/definitions/1105.html",
            ],
            tags=["ai", "hallucination", "grounding", "RAG", "factual", "AISVS-C7"],
        )
        super().__init__(metadata, config)

        self._factual_claim_patterns = [
            r"according to\s+\w+",
            r"it is (a )?fact that",
            r"it is (well )?known that",
            r"the (latest |current )?\w+ (data|information|study|research) shows",
            r"studies (show|indicate|suggest)",
            r"research (shows|indicates|suggests)",
            r"data (shows|indicates|suggests)",
            r"statistics show",
            r"this is (a )?common (fact|belief|understanding)",
            r"as (stated|mentioned|noted) in\s+\w+",
            r"the (official|authoritative|verified) (source|report|data)",
            r"confirmed (by|that)",
            r"(definitely|certainly|obviously|clearly) (is|are|was|were)",
            r"always (is|are|was|were)",
            r"never (is|are|was|were)",
            r"it is (impossible|guaranteed|certain) that",
            r"is (guaranteed|certain|definite) to",
        ]

        self._rag_patterns = [
            r"retrieve?\s*\(",
            r"search\s*\(",
            r"query\s*\(",
            r"vector.*search",
            r"similarity.*search",
            r"embedding.*search",
            r"knowledge.*base",
            r"rag",
            r"retrieval.*augmented",
            r"grounding",
            r"citation",
            r"reference\s*\(",
            r"sources\s*=",
            r"context\s*=",
            r"document.*search",
            r"database.*query",
            r"fetch.*knowledge",
            r"retrieve.*context",
        ]

        self._safe_output_patterns = [
            r"i am not sure",
            r"i don'?t know",
            r"i cannot (verify|confirm|guarantee)",
            r"uncertain",
            r"may vary",
            r"it depends",
            r"not (certain|sure)",
            r"might (be|have)",
            r"could be",
            r"possibly",
            r"probably",
            r"typically",
            r"usually",
            r"in general",
            r"on average",
            r"according to (our|this|the) (database|knowledge base)",
            r"based on (the |our )?(provided |given )?(context|data|information)",
        ]

        self._compiled_factual_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._factual_claim_patterns
        ]
        self._compiled_rag_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._rag_patterns
        ]
        self._compiled_safe_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._safe_output_patterns
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
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

        has_rag = any(pattern.search(content) for pattern in self._compiled_rag_patterns)

        for line_num, line in enumerate(lines, 1):
            has_factual_claim = any(
                pattern.search(line) for pattern in self._compiled_factual_patterns
            )
            has_safe_output = any(
                pattern.search(line) for pattern in self._compiled_safe_patterns
            )

            if has_factual_claim and not has_safe_output:
                context_start = max(0, line_num - 3)
                context_end = min(len(lines), line_num + 3)
                context = "\n".join(lines[context_start:context_end])

                if not has_rag:
                    result = RuleResult(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        passed=False,
                        message=f"检测到高风险事实性断言，可能存在幻觉风险: {line.strip()[:80]}",
                        severity=self.metadata.severity,
                        confidence=0.7,
                        location={"file": file_path, "line": line_num, "column": 1},
                        code_snippet=line.strip(),
                        fix_suggestion="使用 RAG (检索增强生成) 或外部知识库验证事实性断言，或添加不确定性表达",
                        references=self.metadata.references,
                    )
                    results.append(result)

        return results


class OutputSafetyFilterMissingRule(BaseRule):
    """AI-SEC-023: 输出安全过滤器缺失

    检测模型输出在展示给用户前缺少内容安全过滤的问题。
    例如：直接显示模型输出而没有经过 moderation API 或内容分类。

    AISVS: v1.0-C7.3.1
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="AI-SEC-023",
            name="Output Safety Filter Missing",
            description="检测模型输出展示给用户前缺少内容安全过滤，可能导致有害内容暴露",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-1391",
            references=[
                "AISVS-v1.0-C7.3.1",
                "https://platform.openai.com/docs/guides/moderation",
                "https://cwe.mitre.org/data/definitions/1391.html",
            ],
            tags=["ai", "safety", "moderation", "filter", "content-classification", "AISVS-C7"],
        )
        super().__init__(metadata, config)

        self._model_output_patterns = [
            r"response\.text",
            r"response\.content",
            r"output\.text",
            r"message\.content",
            r"completion\.text",
            r"result\.text",
            r"llm\.response",
            r"model\.output",
            r"chat_completion",
            r"create_completion",
            r"generate\(",
        ]

        self._user_display_patterns = [
            r"print\s*\(",
            r"console\.log",
            r"document\.write",
            r"innerHTML\s*=",
            r"outerHTML\s*=",
            r"render\s*\(",
            r"display\s*\(",
            r"show\s*\(",
            r"return\s+",
            r"res\.send",
            r"res\.json",
            r"render_template",
            r"Response\.json",
            r"send_message",
            r"send_text",
            r"reply\s*\(",
            r"post\s*\(",
            r"message\.reply",
            r"\.text\s*=",
        ]

        self._safety_filter_patterns = [
            r"moderation",
            r"content.*(filter|classification|check)",
            r"safety.*(check|filter|classify)",
            r"filter.*(content|harmful|toxic)",
            r"classify.*(content|text)",
            r"is_safe",
            r"is_valid",
            r"check_(harmful|toxic|unsafe)",
            r"safe_(check|validate)",
            r"harmful.*(content|detect)",
            r"toxicity",
            r"profanity",
            r"nsfw",
            r"content.*(policy|guideline)",
            r"OpenAI\.Moderation",
            r"AzureContentSafety",
            r"TextAnalyticsClient",
            r"comprehend.*(toxicity|moderation)",
        ]

        self._compiled_model_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._model_output_patterns
        ]
        self._compiled_display_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._user_display_patterns
        ]
        self._compiled_safety_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._safety_filter_patterns
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
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

        has_safety_filter = any(
            pattern.search(content) for pattern in self._compiled_safety_patterns
        )

        for line_num, line in enumerate(lines, 1):
            has_model_output = any(
                pattern.search(line) for pattern in self._compiled_model_patterns
            )
            has_user_display = any(
                pattern.search(line) for pattern in self._compiled_display_patterns
            )

            if has_model_output and has_user_display and not has_safety_filter:
                context_start = max(0, line_num - 5)
                context_end = min(len(lines), line_num + 5)
                context = "\n".join(lines[context_start:context_end])

                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到模型输出直接展示给用户，缺少内容安全过滤",
                    severity=self.metadata.severity,
                    confidence=0.75,
                    location={"file": file_path, "line": line_num, "column": 1},
                    code_snippet=line.strip(),
                    fix_suggestion="在展示模型输出前使用 moderation API 或内容分类服务进行安全过滤",
                    references=self.metadata.references,
                )
                results.append(result)

        return results
