"""硬编码凭证检测规则

检测代码中硬编码的用户名、密码、API密钥等敏感凭证。
"""

import re
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class HardcodedCredentialsRule(BaseRule):
    """硬编码凭证检测规则
    
    检测以下模式:
    - 硬编码密码
    - 硬编码用户名和密码组合
    - 硬编码 API 密钥
    - 硬编码数据库连接字符串
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="HOS004",
            name="Hardcoded Credentials Detection",
            description="检测代码中硬编码的敏感凭证，包括密码、API密钥、数据库连接字符串等",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.AUTHENTICATION,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            references=[
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
            tags=["credentials", "password", "hardcoded", "secret", "security"],
        )
        super().__init__(metadata, config)
        
        self._password_patterns = [
            (re.compile(r"password\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE), "硬编码密码"),
            (re.compile(r"passwd\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE), "硬编码密码"),
            (re.compile(r"pwd\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE), "硬编码密码"),
            (re.compile(r"secret\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE), "硬编码密钥"),
            (re.compile(r"api_key\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE), "硬编码 API 密钥"),
            (re.compile(r"apikey\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE), "硬编码 API 密钥"),
            (re.compile(r"access_key\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE), "硬编码访问密钥"),
            (re.compile(r"access_token\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE), "硬编码访问令牌"),
            (re.compile(r"auth_token\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE), "硬编码认证令牌"),
            (re.compile(r"private_key\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE), "硬编码私钥"),
        ]
        
        self._connection_patterns = [
            (re.compile(r"mysql://[^:]+:[^@]+@[^\"'\s]+", re.IGNORECASE), "MySQL 连接字符串含密码"),
            (re.compile(r"postgresql://[^:]+:[^@]+@[^\"'\s]+", re.IGNORECASE), "PostgreSQL 连接字符串含密码"),
            (re.compile(r"mongodb://[^:]+:[^@]+@[^\"'\s]+", re.IGNORECASE), "MongoDB 连接字符串含密码"),
            (re.compile(r"redis://[^:]*:[^@]+@[^\"'\s]+", re.IGNORECASE), "Redis 连接字符串含密码"),
        ]
        
        self._env_patterns = [
            re.compile(r"os\.environ\[", re.IGNORECASE),
            re.compile(r"os\.getenv\s*\(", re.IGNORECASE),
            re.compile(r"process\.env\.", re.IGNORECASE),
        ]
        
        self._whitelist_patterns = [
            re.compile(r"password\s*=\s*[\"']\$\{", re.IGNORECASE),
            re.compile(r"password\s*=\s*os\.environ", re.IGNORECASE),
            re.compile(r"password\s*=\s*os\.getenv", re.IGNORECASE),
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行硬编码凭证检测
        
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
        
        all_patterns = self._password_patterns + self._connection_patterns
        
        for pattern, description in all_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")
                
                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()
                
                if self._is_whitelisted(code_snippet):
                    continue
                
                masked_snippet = self._mask_sensitive_data(code_snippet)
                
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到{description}",
                    severity=self.metadata.severity,
                    confidence=0.95,
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
        """检查是否在白名单中（使用了环境变量等安全方式）"""
        for pattern in self._whitelist_patterns:
            if pattern.search(code):
                return True
        return False
    
    def _mask_sensitive_data(self, code: str) -> str:
        """遮蔽敏感数据"""
        masked = code
        patterns = [
            (re.compile(r"(password\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
            (re.compile(r"(secret\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
            (re.compile(r"(api_key\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
            (re.compile(r"(access_token\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
        ]
        for pattern, replacement in patterns:
            masked = pattern.sub(replacement, masked)
        return masked
    
    def _get_fix_suggestion(self, issue_type: str) -> str:
        """获取修复建议"""
        suggestions = {
            "硬编码密码": "使用环境变量存储密码: os.environ.get('PASSWORD') 或使用 secrets 管理工具",
            "硬编码密钥": "使用环境变量或配置文件存储密钥，不要将密钥提交到代码仓库",
            "硬编码 API 密钥": "使用环境变量存储 API 密钥: os.environ.get('API_KEY')",
            "硬编码访问密钥": "使用 AWS Secrets Manager 或类似服务管理访问密钥",
            "硬编码访问令牌": "使用 OAuth 流程动态获取令牌，或使用安全的令牌存储",
            "硬编码认证令牌": "使用安全的令牌管理方案，避免硬编码",
            "硬编码私钥": "使用密钥管理服务 (KMS) 或安全的密钥存储",
            "MySQL 连接字符串含密码": "使用环境变量构建连接字符串，或使用配置管理工具",
            "PostgreSQL 连接字符串含密码": "使用环境变量存储数据库凭据",
            "MongoDB 连接字符串含密码": "使用环境变量或配置服务存储连接信息",
            "Redis 连接字符串含密码": "使用环境变量存储 Redis 密码",
        }
        return suggestions.get(issue_type, "使用环境变量或密钥管理服务存储敏感凭证")
