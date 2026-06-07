from typing import Dict, Any, List
import re


class SecurityChecker:
    """安全检查器"""
    
    def __init__(self):
        """初始化安全检查器"""
        # OWASP LLM 2025 安全风险模式
        self.owasp_patterns = {
            "prompt_injection": [
                r"ignore previous instructions",
                r"system prompt",
                r"prompt injection",
                r"bypass security",
                r"override instructions"
            ],
            "data_exfiltration": [
                r"send data to",
                r"exfiltrate",
                r"steal data",
                r"access sensitive",
                r"download file"
            ],
            "malicious_code": [
                r"execute command",
                r"run code",
                r"eval\(",
                r"exec\(",
                r"system\("
            ],
            "privilege_escalation": [
                r"sudo",
                r"root",
                r"admin",
                r"privilege",
                r"escalate"
            ]
        }
    
    def check_prompt_injection(self, prompt: str) -> Dict[str, Any]:
        """检查提示注入风险"""
        score = 0
        matched_patterns = []
        
        for pattern in self.owasp_patterns["prompt_injection"]:
            if re.search(pattern, prompt, re.IGNORECASE):
                score += 1
                matched_patterns.append(pattern)
        
        risk_level = "low"
        if score >= 3:
            risk_level = "high"
        elif score >= 1:
            risk_level = "medium"
        
        return {
            "risk": risk_level,
            "score": score,
            "matched_patterns": matched_patterns,
            "recommendation": "避免使用可能导致提示注入的语言"
        }
    
    def check_data_exfiltration(self, prompt: str) -> Dict[str, Any]:
        """检查数据泄露风险"""
        score = 0
        matched_patterns = []
        
        for pattern in self.owasp_patterns["data_exfiltration"]:
            if re.search(pattern, prompt, re.IGNORECASE):
                score += 1
                matched_patterns.append(pattern)
        
        risk_level = "low"
        if score >= 3:
            risk_level = "high"
        elif score >= 1:
            risk_level = "medium"
        
        return {
            "risk": risk_level,
            "score": score,
            "matched_patterns": matched_patterns,
            "recommendation": "避免请求数据泄露或传输"
        }
    
    def check_malicious_code(self, prompt: str) -> Dict[str, Any]:
        """检查恶意代码风险"""
        score = 0
        matched_patterns = []
        
        for pattern in self.owasp_patterns["malicious_code"]:
            if re.search(pattern, prompt, re.IGNORECASE):
                score += 1
                matched_patterns.append(pattern)
        
        risk_level = "low"
        if score >= 3:
            risk_level = "high"
        elif score >= 1:
            risk_level = "medium"
        
        return {
            "risk": risk_level,
            "score": score,
            "matched_patterns": matched_patterns,
            "recommendation": "避免请求执行代码或命令"
        }
    
    def check_privilege_escalation(self, prompt: str) -> Dict[str, Any]:
        """检查权限提升风险"""
        score = 0
        matched_patterns = []
        
        for pattern in self.owasp_patterns["privilege_escalation"]:
            if re.search(pattern, prompt, re.IGNORECASE):
                score += 1
                matched_patterns.append(pattern)
        
        risk_level = "low"
        if score >= 3:
            risk_level = "high"
        elif score >= 1:
            risk_level = "medium"
        
        return {
            "risk": risk_level,
            "score": score,
            "matched_patterns": matched_patterns,
            "recommendation": "避免请求提升权限的操作"
        }
    
    def run_all_checks(self, prompt: str) -> Dict[str, Any]:
        """运行所有安全检查"""
        checks = {
            "prompt_injection": self.check_prompt_injection(prompt),
            "data_exfiltration": self.check_data_exfiltration(prompt),
            "malicious_code": self.check_malicious_code(prompt),
            "privilege_escalation": self.check_privilege_escalation(prompt)
        }
        
        # 计算总体风险
        total_score = sum(check["score"] for check in checks.values())
        high_risks = sum(1 for check in checks.values() if check["risk"] == "high")
        
        overall_risk = "low"
        if high_risks >= 2 or total_score >= 8:
            overall_risk = "high"
        elif high_risks >= 1 or total_score >= 4:
            overall_risk = "medium"
        
        return {
            "overall_risk": overall_risk,
            "total_score": total_score,
            "checks": checks,
            "timestamp": "2024-01-01T00:00:00Z"  # 实际应用中应该使用真实的时间戳
        }
    
    def generate_security_report(self, prompt: str) -> str:
        """生成安全报告"""
        result = self.run_all_checks(prompt)
        
        report = f"# 安全检查报告\n\n"
        report += f"## 总体风险评估\n"
        report += f"- 总体风险: {result['overall_risk']}\n"
        report += f"- 总得分: {result['total_score']}\n\n"
        
        report += f"## 详细检查结果\n"
        for check_name, check_result in result['checks'].items():
            report += f"### {check_name.replace('_', ' ').title()}\n"
            report += f"- 风险等级: {check_result['risk']}\n"
            report += f"- 得分: {check_result['score']}\n"
            if check_result['matched_patterns']:
                report += f"- 匹配模式: {', '.join(check_result['matched_patterns'])}\n"
            report += f"- 建议: {check_result['recommendation']}\n\n"
        
        return report


def get_security_checker() -> SecurityChecker:
    """获取安全检查器实例"""
    return SecurityChecker()
