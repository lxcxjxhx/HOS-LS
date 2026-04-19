"""XSS 检测规则

检测代码中潜在的跨站脚本攻击漏洞。
"""

import re
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class XSSRule(BaseRule):
    """XSS 检测规则
    
    检测以下模式:
    - 直接输出用户输入到 HTML
    - 不安全的 HTML 渲染
    - innerHTML 赋值用户输入
    - document.write 调用用户输入
    
    改进:
    - 使用上下文感知检测，区分安全输出和危险输出
    - 减少过于宽泛的正则匹配
    - 识别自动转义的模板系统
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="HOS003",
            name="Cross-Site Scripting (XSS) Detection",
            description="检测代码中潜在的 XSS 漏洞，包括不安全的 HTML 输出和用户输入直接渲染",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            language="*",
            version="2.0.0",
            author="HOS-LS Team",
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            tags=["xss", "injection", "html", "javascript", "security"],
        )
        super().__init__(metadata, config)
        
        # 用户输入源模式
        self._user_input_patterns = [
            r"request\.[a-zA-Z_]+",
            r"req\.[a-zA-Z_]+",
            r"params\[",
            r"args\[",
            r"form\[",
            r"json\[",
            r"input\s*\(",
            r"user_[a-zA-Z_]+",
            r"\w+_[iI]nput\b",
        ]
        
        # 危险模式 - 必须同时满足：1) 危险操作 2) 包含用户输入
        self._patterns = [
            # JavaScript - innerHTML 赋值用户输入
            (re.compile(
                r"innerHTML\s*=\s*(?:.*\+\s*)?(?:" + "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "innerHTML 赋值用户输入"),
            
            # JavaScript - document.write 用户输入
            (re.compile(
                r"document\.write\s*\(\s*(?:.*\+\s*)?(?:" + "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "document.write 用户输入"),
            
            # jQuery - html() 用户输入
            (re.compile(
                r"\.html\s*\(\s*(?:.*\+\s*)?(?:" + "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "jQuery html() 用户输入"),
            
            # Flask - render_template_string 用户输入
            (re.compile(
                r"render_template_string\s*\(\s*(?:f[\"'].*\{|.*\+\s*)(?:" + 
                "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "Flask render_template_string 用户输入"),
            
            # Django - mark_safe 用户输入
            (re.compile(
                r"mark_safe\s*\(\s*(?:" + "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "Django mark_safe 用户输入"),
            
            # Jinja2 - |safe 过滤器用户输入
            (re.compile(
                r"\{\s*\{\s*(?:" + "|".join(self._user_input_patterns) + r")[^}]*\|\s*safe",
                re.IGNORECASE
            ), "Jinja2 safe 过滤器用户输入"),
        ]
        
        # Python Web 框架模式
        self._python_patterns = [
            # 直接返回请求内容
            (re.compile(
                r"return\s+(?:" + "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "直接返回用户输入"),
            
            # Response 直接使用用户输入
            (re.compile(
                r"(?:Response|HttpResponse|make_response)\s*\(\s*(?:" + 
                "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "Response 直接使用用户输入"),
        ]
        
        # 安全的上下文模式 - 用于排除误报
        self._safe_context_patterns = [
            r"escape\s*\(",           # 使用了 escape 函数
            r"html\.escape",          # Python html.escape
            r"bleach\.clean",         # bleach 库
            r"sanitize",              # 自定义清理函数
            r"\.text\s*\(",           # jQuery text() 方法
            r"textContent\s*=",       # textContent 赋值
            r"autoescape\s+true",     # Jinja2 自动转义
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行 XSS 检测
        
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
        
        # 检查是否有安全上下文（全局检查）
        has_safe_context = any(
            re.search(pattern, content, re.IGNORECASE)
            for pattern in self._safe_context_patterns
        )
        
        all_patterns = self._patterns + self._python_patterns
        
        for pattern, description in all_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")
                
                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()
                
                # 检查该行是否有安全上下文
                if self._has_safe_context(code_snippet):
                    continue
                
                # 检查是否是硬编码字符串（误报）
                if self._is_hardcoded_string(code_snippet):
                    continue
                
                # 检查是否是模板中的自动转义
                if self._is_auto_escaped_template(content, code_snippet):
                    continue
                
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到潜在的 XSS 漏洞: {description}",
                    severity=self.metadata.severity,
                    confidence=0.80 if not has_safe_context else 0.60,
                    location={
                        "file": file_path,
                        "line": line_num,
                        "column": col_num,
                    },
                    code_snippet=code_snippet,
                    fix_suggestion=self._get_fix_suggestion(description),
                    references=self.metadata.references,
                )
                results.append(result)
        
        return results
    
    def _has_safe_context(self, code_line: str) -> bool:
        """检查代码行是否有安全上下文
        
        Args:
            code_line: 代码行
            
        Returns:
            是否有安全上下文
        """
        for pattern in self._safe_context_patterns:
            if re.search(pattern, code_line, re.IGNORECASE):
                return True
        return False
    
    def _is_hardcoded_string(self, code_line: str) -> bool:
        """检查是否是硬编码字符串（非用户输入）
        
        Args:
            code_line: 代码行
            
        Returns:
            是否是硬编码字符串
        """
        # 如果行中包含明显的硬编码 HTML 但没有用户输入变量
        hardcoded_html_patterns = [
            r"['\"]<\w+",           # HTML 标签开始
            r"['\"].*</\w+>['\"]",   # HTML 标签结束
        ]
        
        has_hardcoded_html = any(
            re.search(p, code_line) for p in hardcoded_html_patterns
        )
        
        # 检查是否真的没有用户输入
        has_user_input = any(
            re.search(pattern, code_line, re.IGNORECASE)
            for pattern in self._user_input_patterns
        )
        
        # 如果有硬编码 HTML 但没有用户输入，可能是误报
        if has_hardcoded_html and not has_user_input:
            return True
        
        return False
    
    def _is_auto_escaped_template(self, content: str, code_line: str) -> bool:
        """检查是否在使用自动转义的模板系统
        
        Args:
            content: 文件内容
            code_line: 代码行
            
        Returns:
            是否使用自动转义模板
        """
        # 检查是否是 Django 模板且没有 mark_safe
        if "{% extends" in content or "{% block" in content:
            # Django 模板默认自动转义
            if "mark_safe" not in code_line and "|safe" not in code_line:
                return True
        
        # 检查是否是 Jinja2 模板且启用了自动转义
        if "{% extends" in content or "{{ " in content:
            if "autoescape" in content and "|safe" not in code_line:
                return True
        
        # 检查是否是 React/Vue/Angular（自动转义）
        framework_indicators = [
            r"import\s+React",
            r"from\s+['\"]react['\"]",
            r"import\s+Vue",
            r"from\s+['\"]vue['\"]",
            r"import\s+\{\s*Component\s*\}",
            r"@Component",
        ]
        
        for indicator in framework_indicators:
            if re.search(indicator, content):
                # 现代前端框架默认自动转义
                return True
        
        return False
    
    def _get_fix_suggestion(self, issue_type: str) -> str:
        """获取修复建议"""
        suggestions = {
            "innerHTML 赋值请求内容": "使用 textContent 替代 innerHTML，或对内容进行 HTML 转义",
            "innerHTML 字符串拼接": "使用 textContent 或创建 DOM 元素，避免直接拼接 HTML",
            "innerHTML 模板字符串": "使用 textContent 或模板引擎进行安全渲染",
            "document.write 请求内容": "避免使用 document.write，使用 DOM 操作方法",
            "document.write 拼接": "使用 document.createElement 和 textContent",
            "jQuery html() 请求内容": "使用 text() 方法替代 html()，或对内容进行转义",
            "jQuery html() 拼接": "使用 text() 方法或 $.text() 函数",
            "Flask 模板字符串拼接": "使用 render_template 并在模板中使用自动转义",
            "Flask f-string 模板": "使用 render_template 替代 render_template_string",
            "Django mark_safe 请求内容": "避免对用户输入使用 mark_safe，使用 escape 过滤器",
            "Django safe 请求内容": "避免对用户输入使用 safe 过滤器",
            "Jinja2 safe 过滤器请求内容": "避免对用户输入使用 safe 过滤器",
            "直接返回请求内容": "对用户输入进行转义后再返回",
            "Response 直接使用请求内容": "使用模板引擎或对内容进行 HTML 转义",
            "HttpResponse 直接使用请求内容": "使用 Django 模板或 escape() 函数",
        }
        return suggestions.get(issue_type, "对用户输入进行 HTML 转义后再输出")
