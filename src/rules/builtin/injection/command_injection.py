"""命令注入检测规则

检测代码中潜在的命令注入漏洞。
"""

import re
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class CommandInjectionRule(BaseRule):
    """命令注入检测规则
    
    检测以下模式:
    - os.system 调用用户输入
    - subprocess 调用 with shell=True 且包含用户输入
    - eval/exec 执行用户输入
    - 不安全的命令拼接（包含用户输入变量）
    
    改进:
    - 使用上下文感知检测，区分硬编码命令和动态命令
    - 追踪用户输入源，减少误报
    - 识别安全的参数列表传递方式
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="HOS002",
            name="Command Injection Detection",
            description="检测代码中潜在的命令注入漏洞，包括不安全的系统命令执行和用户输入拼接",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            language="*",
            version="2.0.0",
            author="HOS-LS Team",
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
            ],
            tags=["command", "injection", "os", "subprocess", "security"],
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
            r"sys\.argv",
            r"os\.environ",
            r"\b\w+_[iI]nput\b",
            r"\buser_[a-zA-Z_]+\b",
            r"\bcmd\b",
            r"\bcommand\b",
        ]
        
        # 安全的模式 - 使用参数列表而非 shell 字符串
        self._safe_patterns = [
            r"subprocess\.(?:call|run|Popen)\s*\(\s*\[",  # 参数列表
            r"subprocess\.(?:call|run|Popen)\s*\(\s*args\s*=\s*\[",  # args 参数
        ]
        
        # 危险模式 - 必须同时满足：1) 危险操作 2) 包含用户输入变量
        self._patterns = [
            # os.system 包含用户输入
            (re.compile(
                r"os\.system\s*\(\s*(?:f[\"']|.*\+\s*)(?:" +
                "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "os.system 包含用户输入"),
            
            # os.popen 包含用户输入
            (re.compile(
                r"os\.popen\s*\(\s*(?:f[\"']|.*\+\s*)(?:" +
                "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "os.popen 包含用户输入"),
            
            # subprocess with shell=True 且包含用户输入
            (re.compile(
                r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*(?:" +
                "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "subprocess shell=True 包含用户输入"),
            
            # subprocess 字符串拼接用户输入
            (re.compile(
                r"subprocess\.(?:call|run|Popen)\s*\(\s*(?:f[\"']|.*\+\s*)(?:" +
                "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "subprocess 字符串拼接用户输入"),
            
            # eval 执行用户输入
            (re.compile(
                r"eval\s*\(\s*(?:" + "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "eval 执行用户输入"),
            
            # exec 执行用户输入
            (re.compile(
                r"exec\s*\(\s*(?:" + "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "exec 执行用户输入"),
        ]
        
        # 编译安全模式
        self._compiled_safe_patterns = [re.compile(p, re.IGNORECASE) for p in self._safe_patterns]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行命令注入检测
        
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
        
        for pattern, description in self._patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")
                
                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()
                
                # 检查是否是安全的参数列表调用
                if self._is_safe_parameter_list(code_snippet):
                    continue
                
                # 检查是否是硬编码命令（非用户输入）
                if self._is_hardcoded_command(code_snippet):
                    continue
                
                # 检查是否使用了 shlex.quote 等安全措施
                if self._has_security_measure(code_snippet):
                    continue
                
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到潜在的命令注入漏洞: {description}",
                    severity=self.metadata.severity,
                    confidence=0.90,
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
    
    def _is_safe_parameter_list(self, code_line: str) -> bool:
        """检查是否使用安全的参数列表调用
        
        Args:
            code_line: 代码行
            
        Returns:
            是否使用参数列表
        """
        for pattern in self._compiled_safe_patterns:
            if pattern.search(code_line):
                return True
        return False
    
    def _is_hardcoded_command(self, code_line: str) -> bool:
        """检查是否是硬编码命令（非用户输入）
        
        Args:
            code_line: 代码行
            
        Returns:
            是否是硬编码命令
        """
        # 检查是否包含用户输入模式
        has_user_input = any(
            re.search(pattern, code_line, re.IGNORECASE)
            for pattern in self._user_input_patterns
        )
        
        # 如果没有用户输入，可能是硬编码命令
        if not has_user_input:
            # 检查是否是纯字符串拼接（如 "echo " + "hello"）
            if re.search(r"['\"].*['\"]\s*\+\s*['\"].*['\"]", code_line):
                return True
            
            # 检查是否是纯 f-string 硬编码
            if re.search(r"f['\"][^'{]*['\"]", code_line):
                return True
        
        return False
    
    def _has_security_measure(self, code_line: str) -> bool:
        """检查是否有安全措施
        
        Args:
            code_line: 代码行
            
        Returns:
            是否有安全措施
        """
        security_patterns = [
            r"shlex\.quote",           # shlex.quote 转义
            r"pipes\.quote",           # pipes.quote 转义
            r"re\.escape",             # re.escape 转义
            r"validate",               # 自定义验证
            r"sanitize",               # 自定义清理
            r"escape",                 # 转义函数
        ]
        
        for pattern in security_patterns:
            if re.search(pattern, code_line, re.IGNORECASE):
                return True
        
        return False
    
    def _get_fix_suggestion(self, issue_type: str) -> str:
        """获取修复建议"""
        suggestions = {
            "os.system 字符串拼接": "使用 subprocess 模块并传递参数列表，避免 shell=True",
            "os.system f-string": "使用 subprocess.run(['cmd', arg1, arg2]) 替代 os.system",
            "os.system % 格式化": "使用 subprocess 模块，将参数作为列表传递",
            "subprocess shell=True": "避免使用 shell=True，将命令和参数作为列表传递: subprocess.run(['cmd', arg])",
            "subprocess 字符串拼接": "使用参数列表: subprocess.run(['cmd', arg1, arg2])",
            "subprocess f-string": "使用参数列表替代 f-string 构建命令",
            "os.popen 字符串拼接": "使用 subprocess.Popen 并传递参数列表",
            "os.popen f-string": "使用 subprocess.Popen 替代 os.popen",
            "commands 模块拼接": "使用 subprocess 模块替代已弃用的 commands 模块",
            "eval 字符串拼接": "避免使用 eval，使用更安全的替代方案如 ast.literal_eval",
            "exec 字符串拼接": "避免使用 exec 执行动态代码",
            "eval 执行请求内容": "永远不要执行来自用户请求的代码，使用白名单验证",
            "exec 执行请求内容": "永远不要执行来自用户请求的代码，使用白名单验证",
        }
        return suggestions.get(issue_type, "使用 subprocess 模块并传递参数列表，避免 shell=True")
