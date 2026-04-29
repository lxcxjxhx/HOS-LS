"""弱加密算法检测规则

检测代码中使用的不安全加密算法。
"""

import re
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class WeakCryptoRule(BaseRule):
    """弱加密算法检测规则
    
    检测以下模式:
    - MD5 用于密码或签名
    - SHA1 用于安全敏感场景
    - DES/3DES 加密
    - ECB 模式
    - 弱哈希算法
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="HOS005",
            name="Weak Cryptography Detection",
            description="检测代码中使用的不安全加密算法，包括 MD5、SHA1、DES 等",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.CRYPTOGRAPHY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            references=[
                "https://owasp.org/www-community/vulnerabilities/Use_of_a_Broken_or_Risky_Cryptographic_Algorithm",
                "https://cwe.mitre.org/data/definitions/327.html",
            ],
            tags=["cryptography", "encryption", "hash", "weak", "security"],
        )
        super().__init__(metadata, config)
        
        self._patterns = [
            (re.compile(r"hashlib\.md5\s*\(", re.IGNORECASE), "MD5 哈希算法"),
            (re.compile(r"MD5\s*\(", re.IGNORECASE), "MD5 哈希算法"),
            (re.compile(r"hashlib\.sha1\s*\(", re.IGNORECASE), "SHA1 哈希算法"),
            (re.compile(r"SHA1\s*\(", re.IGNORECASE), "SHA1 哈希算法"),
            (re.compile(r"from\s+Crypto\.Cipher\s+import\s+DES", re.IGNORECASE), "DES 加密算法"),
            (re.compile(r"DES\.new\s*\(", re.IGNORECASE), "DES 加密算法"),
            (re.compile(r"DES3\.new\s*\(", re.IGNORECASE), "3DES 加密算法"),
            (re.compile(r"AES\.new\s*\([^)]*,\s*AES\.MODE_ECB", re.IGNORECASE), "ECB 加密模式"),
            (re.compile(r"MODE_ECB", re.IGNORECASE), "ECB 加密模式"),
            (re.compile(r"Random\.random\s*\(\s*\)", re.IGNORECASE), "不安全的随机数"),
            (re.compile(r"math\.random\s*\(\s*\)", re.IGNORECASE), "不安全的随机数"),
            (re.compile(r"random\.random\s*\(\s*\)", re.IGNORECASE), "不安全的随机数"),
            (re.compile(r"random\.randint\s*\(", re.IGNORECASE), "不安全的随机数"),
            (re.compile(r"random\.choice\s*\(", re.IGNORECASE), "不安全的随机数"),
        ]
        
        self._context_patterns = {
            "password": re.compile(r"password|passwd|pwd|secret|key", re.IGNORECASE),
            "token": re.compile(r"token|auth|session|jwt", re.IGNORECASE),
            "sensitive": re.compile(r"encrypt|decrypt|sign|verify|hash", re.IGNORECASE),
        }

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行弱加密算法检测
        
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
                severity = self._determine_severity(description, context)
                
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到弱加密算法: {description}",
                    severity=severity,
                    confidence=0.85,
                    location={
                        "file": file_path,
                        "line": line_num,
                        "column": col_num,
                    },
                    code_snippet=code_snippet,
                    fix_suggestion=self._get_fix_suggestion(description),
                    references=self.metadata.references,
                    metadata={"context": context},
                )
                results.append(result)
        
        return results
    
    def _analyze_context(self, content: str, line_num: int) -> str:
        """分析代码上下文"""
        lines = content.split("\n")
        start = max(0, line_num - 5)
        end = min(len(lines), line_num + 5)
        context_code = "\n".join(lines[start:end])
        
        for context_type, pattern in self._context_patterns.items():
            if pattern.search(context_code):
                return context_type
        return "general"
    
    def _determine_severity(self, description: str, context: str) -> RuleSeverity:
        """根据上下文确定严重级别"""
        if context in ["password", "token"]:
            return RuleSeverity.CRITICAL
        elif context == "sensitive":
            return RuleSeverity.HIGH
        elif "ECB" in description:
            return RuleSeverity.HIGH
        else:
            return RuleSeverity.MEDIUM
    
    def _get_fix_suggestion(self, issue_type: str) -> str:
        """获取修复建议"""
        suggestions = {
            "MD5 哈希算法": "使用 SHA-256 或更强的哈希算法: hashlib.sha256()，对于密码使用 bcrypt 或 Argon2",
            "SHA1 哈希算法": "使用 SHA-256 或 SHA-3: hashlib.sha256() 或 hashlib.sha3_256()",
            "DES 加密算法": "使用 AES-256 加密: from Crypto.Cipher import AES",
            "3DES 加密算法": "使用 AES-256 替代 3DES",
            "ECB 加密模式": "使用 CBC、GCM 或 CTR 模式: AES.new(key, AES.MODE_GCM)",
            "不安全的随机数": "使用 secrets 模块生成安全随机数: secrets.token_hex(16)",
        }
        return suggestions.get(issue_type, "使用现代、安全的加密算法替代")
