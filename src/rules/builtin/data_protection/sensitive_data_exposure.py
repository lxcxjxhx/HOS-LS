"""敏感数据暴露检测规则

检测代码中潜在的敏感数据暴露问题。
"""

import re
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class SensitiveDataExposureRule(BaseRule):
    """敏感数据暴露检测规则
    
    检测以下模式:
    - 敏感数据记录到日志
    - 敏感数据在响应中返回
    - 敏感数据在错误消息中暴露
    - PII 数据未加密存储
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="HOS007",
            name="Sensitive Data Exposure Detection",
            description="检测代码中潜在的敏感数据暴露，包括日志记录、响应返回、错误消息等",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.DATA_PROTECTION,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            references=[
                "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_GET_request",
                "https://cwe.mitre.org/data/definitions/200.html",
            ],
            tags=["data-protection", "pii", "sensitive", "exposure", "security"],
        )
        super().__init__(metadata, config)
        
        self._log_patterns = [
            (re.compile(r"log(?:ger)?\.(?:debug|info|warning|error|critical)\s*\([^)]*password", re.IGNORECASE), "密码记录到日志"),
            (re.compile(r"log(?:ger)?\.(?:debug|info|warning|error|critical)\s*\([^)]*token", re.IGNORECASE), "令牌记录到日志"),
            (re.compile(r"log(?:ger)?\.(?:debug|info|warning|error|critical)\s*\([^)]*secret", re.IGNORECASE), "密钥记录到日志"),
            (re.compile(r"log(?:ger)?\.(?:debug|info|warning|error|critical)\s*\([^)]*credit", re.IGNORECASE), "信用卡信息记录到日志"),
            (re.compile(r"print\s*\([^)]*password", re.IGNORECASE), "密码打印输出"),
            (re.compile(r"print\s*\([^)]*token", re.IGNORECASE), "令牌打印输出"),
            (re.compile(r"console\.log\s*\([^)]*password", re.IGNORECASE), "密码记录到控制台"),
            (re.compile(r"console\.log\s*\([^)]*token", re.IGNORECASE), "令牌记录到控制台"),
        ]
        
        self._response_patterns = [
            (re.compile(r"return\s+.*password", re.IGNORECASE), "密码在响应中返回"),
            (re.compile(r"return\s+.*token", re.IGNORECASE), "令牌在响应中返回"),
            (re.compile(r"json\.dumps\s*\([^)]*password", re.IGNORECASE), "密码序列化到 JSON"),
            (re.compile(r"response\[.*password", re.IGNORECASE), "密码放入响应"),
            (re.compile(r"res\.json\s*\([^)]*password", re.IGNORECASE), "密码放入 JSON 响应"),
            (re.compile(r"res\.send\s*\([^)]*password", re.IGNORECASE), "密码发送到客户端"),
        ]
        
        self._error_patterns = [
            (re.compile(r"raise\s+Exception\s*\([^)]*password", re.IGNORECASE), "密码在异常消息中"),
            (re.compile(r"raise\s+.*Error\s*\([^)]*password", re.IGNORECASE), "密码在错误消息中"),
            (re.compile(r"flash\s*\([^)]*password", re.IGNORECASE), "密码在 flash 消息中"),
        ]
        
        self._pii_patterns = [
            (re.compile(r"ssn\s*=\s*[\"']\d{3}-\d{2}-\d{4}[\"']", re.IGNORECASE), "硬编码 SSN"),
            (re.compile(r"credit_card\s*=\s*[\"']\d{16}[\"']", re.IGNORECASE), "硬编码信用卡号"),
            (re.compile(r"email\s*=\s*[\"'][^\"']+@[^\"']+\.[^\"']+[\"']", re.IGNORECASE), "硬编码邮箱"),
            (re.compile(r"phone\s*=\s*[\"']\d{10,}[\"']", re.IGNORECASE), "硬编码电话号码"),
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行敏感数据暴露检测
        
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
        
        all_patterns = self._log_patterns + self._response_patterns + self._error_patterns + self._pii_patterns
        
        for pattern, description in all_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")
                
                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()
                
                masked_snippet = self._mask_sensitive_data(code_snippet)
                
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到{description}",
                    severity=self.metadata.severity,
                    confidence=0.80,
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
    
    def _mask_sensitive_data(self, code: str) -> str:
        """遮蔽敏感数据"""
        masked = code
        patterns = [
            (re.compile(r"(password\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
            (re.compile(r"(token\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
            (re.compile(r"(secret\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****\2"),
            (re.compile(r"(ssn\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1***-**-****\2"),
            (re.compile(r"(credit_card\s*=\s*[\"'])[^\"']+([\"'])", re.IGNORECASE), r"\1****************\2"),
        ]
        for pattern, replacement in patterns:
            masked = pattern.sub(replacement, masked)
        return masked
    
    def _get_fix_suggestion(self, issue_type: str) -> str:
        """获取修复建议"""
        suggestions = {
            "密码记录到日志": "不要将密码记录到日志中，使用脱敏处理或完全移除",
            "令牌记录到日志": "不要将令牌记录到日志中，只记录令牌的部分信息（如前4位）",
            "密钥记录到日志": "不要将密钥记录到日志中",
            "信用卡信息记录到日志": "不要将信用卡信息记录到日志，如需记录请脱敏处理",
            "密码打印输出": "移除打印密码的代码，使用安全的调试方式",
            "令牌打印输出": "移除打印令牌的代码",
            "密码记录到控制台": "移除 console.log 中的敏感信息",
            "令牌记录到控制台": "移除 console.log 中的敏感信息",
            "密码在响应中返回": "不要在 API 响应中返回密码字段",
            "令牌在响应中返回": "谨慎处理令牌返回，确保只返回必要信息",
            "密码序列化到 JSON": "在序列化前排除密码字段",
            "密码放入响应": "从响应对象中移除密码字段",
            "密码放入 JSON 响应": "从 JSON 响应中排除密码字段",
            "密码发送到客户端": "不要将密码发送到客户端",
            "密码在异常消息中": "不要在异常消息中包含密码",
            "密码在错误消息中": "使用通用错误消息，不要暴露敏感信息",
            "密码在 flash 消息中": "不要在 flash 消息中包含密码",
            "硬编码 SSN": "不要硬编码社会安全号，使用测试数据",
            "硬编码信用卡号": "不要硬编码信用卡号，使用测试卡号",
            "硬编码邮箱": "使用环境变量或配置文件存储邮箱",
            "硬编码电话号码": "使用环境变量或配置文件存储电话号码",
        }
        return suggestions.get(issue_type, "避免暴露敏感数据，使用脱敏处理或移除相关代码")
