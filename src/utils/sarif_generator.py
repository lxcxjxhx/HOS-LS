#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SARIF 生成器模块

功能：
1. 将安全扫描结果转换为 SARIF 格式
2. 支持 GitHub 安全选项卡集成
3. 提供详细的漏洞信息和位置
"""

import json
from typing import Dict, Any, List


class SARIFGenerator:
    """SARIF 格式生成器"""
    
    def __init__(self):
        """初始化 SARIF 生成器"""
        self._rules = {
            "sql_injection": {
                "id": "SQL_INJECTION",
                "name": "SQL 注入",
                "description": "检测到可能的 SQL 注入漏洞",
                "severity": "high"
            },
            "xss": {
                "id": "XSS",
                "name": "跨站脚本",
                "description": "检测到可能的跨站脚本漏洞",
                "severity": "high"
            },
            "command_injection": {
                "id": "COMMAND_INJECTION",
                "name": "命令注入",
                "description": "检测到可能的命令注入漏洞",
                "severity": "high"
            },
            "hardcoded_secret": {
                "id": "HARDCODED_SECRET",
                "name": "硬编码密钥",
                "description": "检测到硬编码的密钥或凭据",
                "severity": "high"
            },
            "path_traversal": {
                "id": "PATH_TRAVERSAL",
                "name": "路径遍历",
                "description": "检测到可能的路径遍历漏洞",
                "severity": "medium"
            },
            "insecure_deserialization": {
                "id": "INSECURE_DESERIALIZATION",
                "name": "不安全的反序列化",
                "description": "检测到不安全的反序列化操作",
                "severity": "high"
            },
            "csrf": {
                "id": "CSRF",
                "name": "跨站请求伪造",
                "description": "检测到可能的跨站请求伪造漏洞",
                "severity": "medium"
            },
            "auth_bypass": {
                "id": "AUTH_BYPASS",
                "name": "认证绕过",
                "description": "检测到可能的认证绕过漏洞",
                "severity": "high"
            },
            "sensitive_data_exposure": {
                "id": "SENSITIVE_DATA_EXPOSURE",
                "name": "敏感数据泄露",
                "description": "检测到可能的敏感数据泄露",
                "severity": "medium"
            },
            "ai_security_issue": {
                "id": "AI_SECURITY_ISSUE",
                "name": "AI 检测的安全问题",
                "description": "AI 检测到的安全问题",
                "severity": "medium"
            }
        }
    
    def generate_sarif(self, scan_results: Dict[str, Any]) -> str:
        """生成 SARIF 格式的扫描结果
        
        Args:
            scan_results: 扫描结果
            
        Returns:
            SARIF 格式的 JSON 字符串
        """
        sarif_template = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "HOS-LS",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/hos-ls/hos-ls",
                            "rules": []
                        }
                    },
                    "results": [],
                    "artifacts": []
                }
            ]
        }
        
        # 提取所有规则
        rules = []
        for rule_id, rule_info in self._rules.items():
            rule = {
                "id": rule_info["id"],
                "name": rule_info["name"],
                "shortDescription": {
                    "text": rule_info["description"]
                },
                "fullDescription": {
                    "text": rule_info["description"]
                },
                "defaultConfiguration": {
                    "level": self._map_severity(rule_info["severity"])
                },
                "properties": {
                    "security-severity": rule_info["severity"]
                }
            }
            rules.append(rule)
        
        sarif_template["runs"][0]["tool"]["driver"]["rules"] = rules
        
        # 处理扫描结果
        results = []
        artifacts = set()
        
        for category, issues in scan_results.items():
            if isinstance(issues, list):
                for issue in issues:
                    result = self._create_sarif_result(issue, category)
                    if result:
                        results.append(result)
                        # 添加文件到 artifacts
                        file_path = issue.get('file')
                        if file_path:
                            artifacts.add(file_path)
        
        sarif_template["runs"][0]["results"] = results
        
        # 添加 artifacts
        artifact_list = []
        for file_path in artifacts:
            artifact = {
                "location": {
                    "uri": file_path
                }
            }
            artifact_list.append(artifact)
        
        sarif_template["runs"][0]["artifacts"] = artifact_list
        
        return json.dumps(sarif_template, indent=2, ensure_ascii=False)
    
    def _create_sarif_result(self, issue: Dict[str, Any], category: str) -> Dict[str, Any]:
        """创建单个 SARIF 结果
        
        Args:
            issue: 安全问题
            category: 问题类别
            
        Returns:
            SARIF 结果对象
        """
        file_path = issue.get('file')
        line_number = issue.get('line_number')
        
        if not file_path or not line_number:
            return None
        
        # 映射类别到规则 ID
        rule_id = self._map_category_to_rule_id(category)
        
        # 获取规则信息
        rule_info = self._rules.get(rule_id, {
            "id": "GENERAL_SECURITY_ISSUE",
            "name": "安全问题",
            "description": "检测到安全问题",
            "severity": "medium"
        })
        
        # 构建结果
        result = {
            "ruleId": rule_info["id"],
            "message": {
                "text": issue.get('issue', '未指定问题')
            },
            "level": self._map_severity(issue.get('severity', 'medium')),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path
                        },
                        "region": {
                            "startLine": line_number,
                            "startColumn": 1
                        }
                    }
                }
            ],
            "properties": {
                "security-severity": issue.get('severity', 'medium'),
                "description": issue.get('details', ''),
                "code_snippet": issue.get('code_snippet', ''),
                "detection_method": issue.get('detection_method', 'unknown'),
                "confidence": issue.get('confidence', 0.0)
            }
        }
        
        # 添加攻击场景（如果有）
        exploit_scenario = issue.get('exploit_scenario')
        if exploit_scenario:
            result["properties"]["exploit_scenario"] = exploit_scenario
        
        # 添加修复建议（如果有）
        recommendation = issue.get('recommendation')
        if recommendation:
            result["properties"]["recommendation"] = recommendation
        
        return result
    
    def _map_category_to_rule_id(self, category: str) -> str:
        """映射类别到规则 ID
        
        Args:
            category: 问题类别
            
        Returns:
            规则 ID
        """
        category_map = {
            "sql_injection": "sql_injection",
            "xss": "xss",
            "command_injection": "command_injection",
            "hardcoded_secret": "hardcoded_secret",
            "path_traversal": "path_traversal",
            "insecure_deserialization": "insecure_deserialization",
            "csrf": "csrf",
            "auth_bypass": "auth_bypass",
            "sensitive_data_exposure": "sensitive_data_exposure",
            "ai_security_issues": "ai_security_issue"
        }
        
        return category_map.get(category, "ai_security_issue")
    
    def _map_severity(self, severity: str) -> str:
        """映射严重程度到 SARIF 级别
        
        Args:
            severity: 严重程度
            
        Returns:
            SARIF 级别
        """
        severity_map = {
            "high": "error",
            "medium": "warning",
            "low": "note"
        }
        
        return severity_map.get(severity, "warning")


if __name__ == '__main__':
    # 测试 SARIF 生成
    test_results = {
        "ai_security_issues": [
            {
                "file": "test.py",
                "line_number": 10,
                "issue": "SQL 注入风险",
                "severity": "high",
                "details": "检测到可能的 SQL 注入风险",
                "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
                "detection_method": "ai_analysis",
                "confidence": 0.95
            }
        ]
    }
    
    generator = SARIFGenerator()
    sarif_output = generator.generate_sarif(test_results)
    
    # 保存到文件
    with open('security-results.sarif', 'w', encoding='utf-8') as f:
        f.write(sarif_output)
    
    print("SARIF 文件已生成: security-results.sarif")
