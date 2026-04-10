"""硬编码密钥检测规则

检测代码中硬编码的加密密钥。
"""

import re
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class HardcodedKeysRule(BaseRule):
    """硬编码密钥检测规则
    
    检测以下模式:
    - 硬编码 AES 密钥
    - 硬编码 RSA 私钥
    - 硬编码签名密钥
    - 硬编码 JWT 密钥
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="HOS006",
            name="Hardcoded Cryptographic Keys Detection",
            description="检测代码中硬编码的加密密钥，包括 AES 密钥、RSA 私钥、JWT 密钥等",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.CRYPTOGRAPHY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            references=[
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key",
                "https://cwe.mitre.org/data/definitions/321.html",
            ],
            tags=["cryptography", "key", "hardcoded", "secret", "security"],
        )
        super().__init__(metadata, config)
        
        self._patterns = [
            (re.compile(r"SECRET_KEY\s*=\s*[\"'][^\"']{8,}[\"']", re.IGNORECASE), "硬编码 SECRET_KEY"),
            (re.compile(r"JWT_SECRET\s*=\s*[\"'][^\"']{8,}[\"']", re.IGNORECASE), "硬编码 JWT 密钥"),
            (re.compile(r"JWT_KEY\s*=\s*[\"'][^\"']{8,}[\"']", re.IGNORECASE), "硬编码 JWT 密钥"),
            (re.compile(r"AES_KEY\s*=\s*[\"'][^\"']{16,}[\"']", re.IGNORECASE), "硬编码 AES 密钥"),
            (re.compile(r"ENCRYPTION_KEY\s*=\s*[\"'][^\"']{8,}[\"']", re.IGNORECASE), "硬编码加密密钥"),
            (re.compile(r"SIGNING_KEY\s*=\s*[\"'][^\"']{8,}[\"']", re.IGNORECASE), "硬编码签名密钥"),
            (re.compile(r"PRIVATE_KEY\s*=\s*[\"']-----BEGIN", re.IGNORECASE), "硬编码 RSA 私钥"),
            (re.compile(r"key\s*=\s*[\"'][a-zA-Z0-9]{16,}[\"']", re.IGNORECASE), "硬编码密钥"),
        ]
        
        self._base64_pattern = re.compile(r"[\"']([A-Za-z0-9+/]{16,}={0,2})[\"']")
        
        self._whitelist_patterns = [
            re.compile(r"SECRET_KEY\s*=\s*os\.environ", re.IGNORECASE),
            re.compile(r"SECRET_KEY\s*=\s*os\.getenv", re.IGNORECASE),
            re.compile(r"SECRET_KEY\s*=\s*[\"']\$\{", re.IGNORECASE),
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行硬编码密钥检测
        
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
                
                if self._is_whitelisted(code_snippet):
                    continue
                
                masked_snippet = self._mask_key(code_snippet)
                
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到{description}",
                    severity=self.metadata.severity,
                    confidence=0.90,
                    location={
                        "file": file_path,
                        "line": line_num,
                        "column": col_num,
                    },
                    code_snippet=masked_snippet,
                    fix_suggestion=self._get_fix_suggestion(description),
                    references=self.metadata.references,
                )
                results.append(result)
        
        return results
    
    def _is_whitelisted(self, code: str) -> bool:
        """检查是否在白名单中"""
        for pattern in self._whitelist_patterns:
            if pattern.search(code):
                return True
        return False
    
    def _mask_key(self, code: str) -> str:
        """遮蔽密钥"""
        masked = code
        patterns = [
            (re.compile(r"(SECRET_KEY\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
            (re.compile(r"(JWT_SECRET\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
            (re.compile(r"(AES_KEY\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
            (re.compile(r"(ENCRYPTION_KEY\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
        ]
        for pattern, replacement in patterns:
            masked = pattern.sub(replacement, masked)
        return masked
    
    def _get_fix_suggestion(self, issue_type: str) -> str:
        """获取修复建议"""
        suggestions = {
            "硬编码 SECRET_KEY": "使用环境变量: SECRET_KEY = os.environ.get('SECRET_KEY') 或使用 secrets 模块生成",
            "硬编码 JWT 密钥": "使用环境变量存储 JWT 密钥，或使用密钥管理服务",
            "硬编码 AES 密钥": "使用密钥管理服务 (KMS) 管理加密密钥",
            "硬编码加密密钥": "使用环境变量或密钥管理服务存储加密密钥",
            "硬编码签名密钥": "使用安全的密钥存储方案，如 HashiCorp Vault",
            "硬编码 RSA 私钥": "将私钥存储在安全的密钥管理服务中，不要硬编码",
            "硬编码密钥": "使用环境变量或密钥管理服务存储密钥",
        }
        return suggestions.get(issue_type, "使用环境变量或密钥管理服务存储加密密钥")
