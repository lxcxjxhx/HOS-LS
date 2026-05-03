"""SQL 注入检测规则

检测代码中潜在的 SQL 注入漏洞。
"""

import re
from typing import Any, Dict, List, Optional, Union, Set
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class SQLInjectionRule(BaseRule):
    """SQL 注入检测规则
    
    检测以下模式:
    - 字符串拼接 SQL 语句（包含用户输入变量）
    - 格式化字符串构建 SQL（包含用户输入变量）
    - 不安全的参数化查询
    - 原始 SQL 执行
    
    改进:
    - 使用上下文感知检测，区分硬编码 SQL 和动态 SQL
    - 追踪用户输入源，减少误报
    - 识别安全的参数化查询模式
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="HOS001",
            name="SQL Injection Detection",
            description="检测代码中潜在的 SQL 注入漏洞，包括字符串拼接、格式化字符串构建 SQL 语句等不安全模式",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            language="*",
            version="2.0.0",
            author="HOS-LS Team",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
            tags=["sql", "injection", "database", "security"],
        )
        super().__init__(metadata, config)
        
        # 用户输入源模式 - 用于确认变量是否来自用户输入
        self._user_input_patterns = [
            r"request\.[a-zA-Z_]+",  # Flask/Django request
            r"req\.[a-zA-Z_]+",      # Express req
            r"params\[",              # URL参数
            r"args\[",                # 参数
            r"form\[",                # 表单数据
            r"json\[",                # JSON数据
            r"input\s*\(",            # input() 函数
            r"sys\.argv",             # 命令行参数
            r"os\.environ",           # 环境变量
            r"\b\w+_[iI]nput\b",      # 以 input 结尾的变量
            r"\buser_[a-zA-Z_]+\b",   # user_ 开头的变量
        ]
        
        # 安全的参数化查询模式 - 用于排除误报
        self._safe_patterns = [
            r"execute\s*\(\s*[\"'][^\"']*%s[^\"']*[\"']\s*,\s*\(?\s*\w+",  # %s 参数化
            r"execute\s*\(\s*[\"'][^\"']*\?[^\"']*[\"']\s*,\s*\(?\s*\w+",  # ? 参数化
            r"execute\s*\(\s*[\"'][^\"']*\$\d+[^\"']*[\"']\s*,\s*\(?\s*\w+",  # $1 参数化
            r"execute\s*\(\s*[\"'][^\"']*:[a-zA-Z_]+[^\"']*[\"']\s*,\s*\{?\s*[\"']?:[a-zA-Z_]+",  # :name 参数化
        ]
        
        # 危险模式 - 必须同时满足：1) SQL操作 2) 包含用户输入变量
        self._dangerous_patterns = [
            # cursor.execute(f"...{user_input}...")
            (re.compile(
                r"(?:cursor|db|conn|connection)\.execute\s*\(\s*f[\"'][^\"']*\{[^}]*(?:" + 
                "|".join(self._user_input_patterns) + r")[^}]*\}[^\"']*[\"']",
                re.IGNORECASE
            ), "f-string SQL 包含用户输入"),
            
            # cursor.execute("..." + user_input + "...")
            (re.compile(
                r"(?:cursor|db|conn|connection)\.execute\s*\(\s*[\"'][^\"']*(?:" +
                "|".join(self._user_input_patterns) + r")[^\"']*[\"']\s*\+",
                re.IGNORECASE
            ), "字符串拼接 SQL 包含用户输入"),
            
            # execute("... %s ..." % user_input) - 非参数化使用
            (re.compile(
                r"(?:cursor|db|conn|connection)?\.?execute\s*\(\s*[\"'][^\"']*%[sdfe][^\"']*[\"']\s*%\s*(?:" +
                "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "% 格式化 SQL 包含用户输入"),
            
            # execute("... {} ...".format(user_input))
            (re.compile(
                r"(?:cursor|db|conn|connection)?\.?execute\s*\(\s*[\"'][^\"']*\{[^}]*\}[^\"']*[\"']\s*\.format\s*\(\s*(?:" +
                "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), ".format() SQL 包含用户输入"),
            
            # ORM raw() 方法使用用户输入
            (re.compile(
                r"\.raw\s*\(\s*(?:f[\"']|.*\+|.*\.format).*" +
                "(?:" + "|".join(self._user_input_patterns) + r")",
                re.IGNORECASE
            ), "ORM raw() 包含用户输入"),
        ]
        
        # 编译安全模式
        self._compiled_safe_patterns = [re.compile(p, re.IGNORECASE) for p in self._safe_patterns]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行 SQL 注入检测
        
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
        
        # 首先检查是否是安全的参数化查询
        for safe_pattern in self._compiled_safe_patterns:
            # 如果匹配到安全模式，跳过该行的检测
            for match in safe_pattern.finditer(content):
                return []  # 整个文件使用参数化查询，跳过
        
        # 检测危险模式
        for pattern, description in self._dangerous_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")
                
                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()
                
                # 再次检查该行是否是安全的参数化查询
                if self._is_safe_parameterized_query(code_snippet):
                    continue
                
                # 检查是否是硬编码的测试数据（减少误报）
                if self._is_hardcoded_test_data(code_snippet):
                    continue
                
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到潜在的 SQL 注入漏洞: {description}",
                    severity=self.metadata.severity,
                    confidence=0.85,
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
    
    def _is_safe_parameterized_query(self, code_line: str) -> bool:
        """检查是否是安全的参数化查询
        
        Args:
            code_line: 代码行
            
        Returns:
            是否是安全的参数化查询
        """
        # 检查是否有参数元组/列表作为第二个参数
        safe_indicators = [
            r",\s*\(\s*\w+",      # , (variable
            r",\s*\[\s*\w+",      # , [variable
            r",\s*\w+\s*\)",      # , variable)
            r"execute\s*\(\s*\w+\s*,\s*\w+",  # execute(sql, params)
        ]
        
        for indicator in safe_indicators:
            if re.search(indicator, code_line, re.IGNORECASE):
                return True
        
        return False
    
    def _is_hardcoded_test_data(self, code_line: str) -> bool:
        """检查是否是硬编码的测试数据
        
        Args:
            code_line: 代码行
            
        Returns:
            是否是硬编码的测试数据
        """
        # 如果整行都是硬编码字符串，可能是误报
        hardcoded_patterns = [
            r"execute\s*\(\s*['\"]SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['\"]\s*\+",
            r"execute\s*\(\s*f['\"]\s*SELECT\s+\*\s+FROM\s+\w+",
        ]
        
        # 检查是否包含明显的测试数据
        test_data_indicators = [
            r"['\"]test['\"]",
            r"['\"]example['\"]",
            r"['\"]demo['\"]",
            r"['\"]sample['\"]",
        ]
        
        for indicator in test_data_indicators:
            if re.search(indicator, code_line, re.IGNORECASE):
                # 检查是否同时包含用户输入模式
                has_user_input = any(
                    re.search(pattern, code_line, re.IGNORECASE)
                    for pattern in self._user_input_patterns
                )
                if not has_user_input:
                    return True
        
        return False
    
    def _get_fix_suggestion(self, issue_type: str) -> str:
        """获取修复建议"""
        suggestions = {
            "字符串拼接 SQL": "使用参数化查询，例如: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "f-string 格式化 SQL": "使用参数化查询替代 f-string，例如: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "% 格式化 SQL": "使用参数化查询，例如: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            ".format() 格式化 SQL": "使用参数化查询替代 .format()，例如: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "原始 SQL 拼接": "避免使用 raw() 方法拼接 SQL，使用 ORM 提供的安全方法",
            "游标执行拼接 SQL": "使用参数化查询，将用户输入作为参数传递",
            "批量执行拼接 SQL": "使用参数化查询进行批量操作",
            "脚本执行拼接 SQL": "避免动态构建 SQL 脚本，使用预定义的 SQL 语句",
        }
        return suggestions.get(issue_type, "使用参数化查询替代动态 SQL 构建")
