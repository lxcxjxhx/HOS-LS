"""不安全随机数检测规则

检测代码中使用的不安全随机数生成器。
"""

import re
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class InsecureRandomRule(BaseRule):
    """不安全随机数检测规则
    
    检测以下模式:
    - random 模块用于安全场景
    - Math.random 用于安全场景
    - 时间戳作为随机种子
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="HOS008",
            name="Insecure Random Number Detection",
            description="检测代码中用于安全场景的不安全随机数生成器",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CRYPTOGRAPHY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            references=[
                "https://owasp.org/www-community/vulnerabilities/Insecure_Randomness",
                "https://cwe.mitre.org/data/definitions/338.html",
            ],
            tags=["random", "cryptography", "security", "insecure"],
        )
        super().__init__(metadata, config)
        
        self._patterns = [
            (re.compile(r"random\.random\s*\(\s*\)"), "random.random() 不安全随机数"),
            (re.compile(r"random\.randint\s*\("), "random.randint() 不安全随机数"),
            (re.compile(r"random\.choice\s*\("), "random.choice() 不安全随机数"),
            (re.compile(r"random\.randrange\s*\("), "random.randrange() 不安全随机数"),
            (re.compile(r"Math\.random\s*\(\s*\)"), "Math.random() 不安全随机数"),
            (re.compile(r"Math\.floor\s*\(\s*Math\.random"), "Math.random() 不安全随机数"),
            (re.compile(r"new\s+Random\s*\("), "Java Random 类不安全"),
            (re.compile(r"Random\.Next\s*\("), ".NET Random 不安全"),
        ]
        
        self._security_context_patterns = [
            re.compile(r"password|passwd|pwd|secret|token|key|auth|session|csrf|nonce|salt|iv", re.IGNORECASE),
        ]
        
        self._safe_patterns = [
            re.compile(r"secrets\."),
            re.compile(r"crypto\.random"),
            re.compile(r"secrets\.token_hex"),
            re.compile(r"secrets\.randbelow"),
            re.compile(r"SystemRandom"),
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行不安全随机数检测
        
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
                
                context = self._analyze_context(content, line_num)
                severity = self._determine_severity(context)
                
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到{description}，用于安全敏感场景",
                    severity=severity,
                    confidence=0.75,
                    location={
                        "file": file_path,
                        "line": line_num,
                        "column": col_num,
                    },
                    code_snippet=code_snippet,
                    fix_suggestion=self._get_fix_suggestion(),
                    references=self.metadata.references,
                    metadata={"context": context},
                )
                results.append(result)
        
        return results
    
    def _analyze_context(self, content: str, line_num: int) -> str:
        """分析代码上下文判断是否用于安全场景"""
        lines = content.split("\n")
        start = max(0, line_num - 10)
        end = min(len(lines), line_num + 5)
        context_code = "\n".join(lines[start:end])
        
        for pattern in self._security_context_patterns:
            if pattern.search(context_code):
                return "security"
        
        for pattern in self._safe_patterns:
            if pattern.search(context_code):
                return "safe"
        
        return "general"
    
    def _determine_severity(self, context: str) -> RuleSeverity:
        """根据上下文确定严重级别"""
        if context == "security":
            return RuleSeverity.HIGH
        elif context == "safe":
            return RuleSeverity.INFO
        else:
            return RuleSeverity.MEDIUM
    
    def _get_fix_suggestion(self) -> str:
        """获取修复建议"""
        return (
            "使用 secrets 模块生成安全随机数:\n"
            "- secrets.token_hex(16)  # 生成安全的十六进制令牌\n"
            "- secrets.randbelow(n)   # 生成安全随机整数\n"
            "- secrets.choice(sequence)  # 从序列中安全选择\n"
            "或使用 SystemRandom: random.SystemRandom()"
        )
