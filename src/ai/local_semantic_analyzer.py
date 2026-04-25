"""本地语义分析器

提供轻量级的本地语义分析，无需调用外部 AI API。
用于在不启用 --ai 参数时提供基本的语义判断能力。
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SemanticAnalysisResult:
    """语义分析结果"""
    is_vulnerable: bool
    risk_level: RiskLevel
    confidence: float
    reason: str
    attack_chain: List[str]
    recommendations: List[str]


class LocalSemanticAnalyzer:
    """本地语义分析器
    
    基于代码模式和上下文进行轻量级语义分析，
    无需调用外部 AI API。
    """
    
    def __init__(self):
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
            r"os\.environ\[",
            r"\b\w+_[iI]nput\b",
            r"\buser_[a-zA-Z_]+\b",
        ]
        
        # 安全处理模式
        self._safe_patterns = [
            r"escape\s*\(",
            r"sanitize",
            r"validate",
            r"clean",
            r"shlex\.quote",
            r"html\.escape",
            r"bleach\.",
            r"paramiko",
        ]
        
        # 漏洞模式及其风险等级
        self._vulnerability_patterns = {
            "sql_injection": {
                "patterns": [
                    r"execute\s*\(\s*f['\"].*\{.*\}",
                    r"execute\s*\(\s*['\"].*\+",
                    r"\.raw\s*\(",
                ],
                "risk_level": RiskLevel.CRITICAL,
                "description": "SQL 注入漏洞",
            },
            "command_injection": {
                "patterns": [
                    r"os\.system\s*\(",
                    r"os\.popen\s*\(",
                    r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True",
                    r"eval\s*\(",
                    r"exec\s*\(",
                ],
                "risk_level": RiskLevel.CRITICAL,
                "description": "命令注入漏洞",
            },
            "xss": {
                "patterns": [
                    r"innerHTML\s*=",
                    r"document\.write\s*\(",
                    r"\.html\s*\(",
                    r"mark_safe\s*\(",
                    r"\|\s*safe",
                ],
                "risk_level": RiskLevel.HIGH,
                "description": "XSS 漏洞",
            },
            "hardcoded_credentials": {
                "patterns": [
                    r"password\s*=\s*['\"][^'\"]+['\"]",
                    r"api_key\s*=\s*['\"][^'\"]+['\"]",
                    r"secret\s*=\s*['\"][^'\"]+['\"]",
                    r"token\s*=\s*['\"][^'\"]+['\"]",
                ],
                "risk_level": RiskLevel.HIGH,
                "description": "硬编码凭证",
            },
            "weak_crypto": {
                "patterns": [
                    r"hashlib\.md5",
                    r"hashlib\.sha1",
                    r"random\.random",
                    r"random\.randint",
                ],
                "risk_level": RiskLevel.MEDIUM,
                "description": "弱加密/随机数",
            },
        }
    
    def analyze(self, code: str, file_path: str = "") -> SemanticAnalysisResult:
        """分析代码语义
        
        Args:
            code: 代码内容
            file_path: 文件路径
            
        Returns:
            语义分析结果
        """
        # 检查是否包含用户输入
        has_user_input = self._has_user_input(code)
        
        # 检查是否有安全措施
        has_security_measure = self._has_security_measure(code)
        
        # 检测漏洞类型
        vulnerabilities = self._detect_vulnerabilities(code)
        
        # 构建攻击链路
        attack_chain = self._build_attack_chain(code, vulnerabilities, has_user_input)
        
        # 评估风险
        is_vulnerable, risk_level, confidence = self._assess_risk(
            vulnerabilities, has_user_input, has_security_measure
        )
        
        # 生成建议
        recommendations = self._generate_recommendations(vulnerabilities, has_security_measure)
        
        return SemanticAnalysisResult(
            is_vulnerable=is_vulnerable,
            risk_level=risk_level,
            confidence=confidence,
            reason=self._generate_reason(vulnerabilities, has_user_input, has_security_measure),
            attack_chain=attack_chain,
            recommendations=recommendations,
        )
    
    def _has_user_input(self, code: str) -> bool:
        """检查代码是否包含用户输入"""
        for pattern in self._user_input_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False
    
    def _has_security_measure(self, code: str) -> bool:
        """检查代码是否包含安全措施"""
        for pattern in self._safe_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False
    
    def _detect_vulnerabilities(self, code: str) -> List[Dict[str, Any]]:
        """检测漏洞类型"""
        vulnerabilities = []
        
        for vuln_type, vuln_info in self._vulnerability_patterns.items():
            for pattern in vuln_info["patterns"]:
                if re.search(pattern, code, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": vuln_type,
                        "risk_level": vuln_info["risk_level"],
                        "description": vuln_info["description"],
                    })
                    break  # 每种漏洞类型只记录一次
        
        return vulnerabilities
    
    def _build_attack_chain(self, code: str, vulnerabilities: List[Dict], has_user_input: bool) -> List[str]:
        """构建攻击链路"""
        chain = []
        
        if not vulnerabilities:
            return chain
        
        # 攻击入口
        if has_user_input:
            chain.append("1. 攻击者通过用户输入点注入恶意数据")
        else:
            chain.append("1. 存在潜在的安全弱点")
        
        # 攻击路径
        for i, vuln in enumerate(vulnerabilities[:3], 2):  # 最多显示3个路径
            chain.append(f"{i}. {vuln['description']}")
        
        # 攻击影响
        if vulnerabilities:
            priority_order = {
                RiskLevel.CRITICAL: 0,
                RiskLevel.HIGH: 1,
                RiskLevel.MEDIUM: 2,
                RiskLevel.LOW: 3,
                RiskLevel.INFO: 4,
            }
            highest_risk = min(vulnerabilities, key=lambda x: priority_order[x["risk_level"]])["risk_level"]
            if highest_risk == RiskLevel.CRITICAL:
                chain.append(f"{len(vulnerabilities) + 2}. 可能导致系统完全 compromised")
            elif highest_risk == RiskLevel.HIGH:
                chain.append(f"{len(vulnerabilities) + 2}. 可能导致敏感数据泄露")
            else:
                chain.append(f"{len(vulnerabilities) + 2}. 可能导致安全风险")
        
        return chain
    
    def _assess_risk(self, vulnerabilities: List[Dict], has_user_input: bool, 
                     has_security_measure: bool) -> Tuple[bool, RiskLevel, float]:
        """评估风险等级"""
        if not vulnerabilities:
            return False, RiskLevel.INFO, 0.0
        
        # 获取最高风险等级
        risk_levels = [v["risk_level"] for v in vulnerabilities]
        # 按优先级排序：CRITICAL > HIGH > MEDIUM > LOW > INFO
        priority_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4,
        }
        highest_risk = min(risk_levels, key=lambda x: priority_order[x])
        
        # 计算置信度
        confidence = 0.7  # 基础置信度
        
        if has_user_input:
            confidence += 0.2  # 有用户输入，置信度更高
        
        if has_security_measure:
            confidence -= 0.3  # 有安全措施，降低置信度
        
        # 根据漏洞数量调整
        confidence += min(len(vulnerabilities) * 0.05, 0.1)
        
        # 确保置信度在合理范围内
        confidence = max(0.3, min(confidence, 0.95))
        
        # 如果有安全措施且没有用户输入，可能不是漏洞
        if has_security_measure and not has_user_input:
            return False, highest_risk, confidence * 0.5
        
        return True, highest_risk, confidence
    
    def _generate_reason(self, vulnerabilities: List[Dict], has_user_input: bool, 
                         has_security_measure: bool) -> str:
        """生成分析原因"""
        if not vulnerabilities:
            return "未发现明显的安全漏洞"
        
        reasons = []
        
        # 漏洞描述
        vuln_descriptions = [v["description"] for v in vulnerabilities]
        reasons.append(f"检测到: {', '.join(vuln_descriptions)}")
        
        # 用户输入
        if has_user_input:
            reasons.append("代码包含用户输入，存在被利用的风险")
        else:
            reasons.append("代码可能包含硬编码的安全问题")
        
        # 安全措施
        if has_security_measure:
            reasons.append("但检测到安全措施，可能已缓解风险")
        
        return "; ".join(reasons)
    
    def _generate_recommendations(self, vulnerabilities: List[Dict], 
                                  has_security_measure: bool) -> List[str]:
        """生成修复建议"""
        recommendations = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln["type"]
            
            if vuln_type == "sql_injection":
                recommendations.append("使用参数化查询替代字符串拼接")
                recommendations.append("考虑使用 ORM 框架")
            elif vuln_type == "command_injection":
                recommendations.append("使用参数列表传递命令参数")
                recommendations.append("避免使用 shell=True")
                recommendations.append("考虑使用 shlex.quote 转义用户输入")
            elif vuln_type == "xss":
                recommendations.append("使用模板引擎的自动转义功能")
                recommendations.append("对用户输入进行 HTML 转义")
                recommendations.append("使用 textContent 替代 innerHTML")
            elif vuln_type == "hardcoded_credentials":
                recommendations.append("将凭证存储在环境变量或配置文件中")
                recommendations.append("使用密钥管理服务")
            elif vuln_type == "weak_crypto":
                recommendations.append("使用 hashlib.sha256 或更强的哈希算法")
                recommendations.append("使用 secrets 模块生成安全随机数")
        
        if not has_security_measure and vulnerabilities:
            recommendations.append("添加输入验证和清理")
        
        # 去重
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:5]  # 最多返回5条建议


# 全局分析器实例
_local_analyzer: Optional[LocalSemanticAnalyzer] = None


def get_local_analyzer() -> LocalSemanticAnalyzer:
    """获取本地语义分析器实例"""
    global _local_analyzer
    if _local_analyzer is None:
        _local_analyzer = LocalSemanticAnalyzer()
    return _local_analyzer
