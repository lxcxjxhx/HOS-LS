"""漏洞分类器模块

为漏洞发现添加分类标签：security_vuln / sdl_issue / code_quality / informational
"""

from enum import Enum
from typing import Dict, Any, List, Optional


class VulnType(Enum):
    """漏洞类型枚举"""
    SECURITY_VULN = "security_vuln"
    SDL_ISSUE = "sdl_issue"
    CODE_QUALITY = "code_quality"
    INFORMATIONAL = "informational"


class VulnerabilityClassifier:
    """漏洞分类器

    根据漏洞特征自动分类漏洞类型
    """

    SECURITY_VULN_PATTERNS = [
        "sql", "sql injection", "sql注入",
        "xss", "cross-site script", "跨站脚本",
        "command injection", "命令注入", "os command",
        "path traversal", "路径遍历",
        "ldap injection", "ldap注入",
        "xml injection", "xml注入",
        "xxe", "xml external entity",
        "deserialization", "反序列化",
        "ssrf", "server side request forgery",
        "csrf", "cross-site request forgery",
        "idOR", "insecure direct object reference",
        "broken authentication", "认证绕过",
        "buffer overflow", "缓冲区溢出",
        "race condition", "竞态条件",
        "type confusion", "类型混淆",
        "use after free", "释放后使用",
        "heap overflow", "堆溢出",
        "stack overflow", "栈溢出",
        "format string", "格式化字符串",
        "integer overflow", "整数溢出",
        "remote code execution", "rce", "远程代码执行",
        "code injection", "代码注入",
        "expression injection", "表达式注入",
        "template injection", "模板注入",
        "script injection", "脚本注入",
    ]

    SDL_ISSUE_PATTERNS = [
        "hardcoded", "硬编码",
        "hard-coded", "hard coded",
        "credentials", "凭据", "密码", "password",
        "api key", "api密钥", "密钥",
        "secret", "密钥", "token", "令牌",
        "weak crypto", "弱加密",
        "md5", "sha1", "des", "rc4",
        "insecure random", "不安全的随机数",
        "deprecated", "废弃", "过时的",
        "insecure", "不安全的",
        "tls version", "ssl version",
        "certificate", "证书",
        "self-signed", "自签名",
        "no encryption", "未加密",
        "encryption", "加密",
        "sensitive data", "敏感数据",
        "data exposure", "数据泄露",
        "information disclosure", "信息泄露",
        "debug enabled", "调试开启",
        "banner", "banner信息",
        "http headers", "http头",
    ]

    CODE_QUALITY_PATTERNS = [
        "unused", "未使用",
        "dead code", "死代码",
        "unused import", "未使用的导入",
        "unused variable", "未使用的变量",
        "convention", "规范",
        "naming", "命名",
        "style", "风格",
        "complexity", "复杂度",
        "cyclo", "圈复杂度",
        "cognitive", "认知复杂度",
        "long method", "长方法",
        "too many parameters", "参数过多",
        "code smell", "代码味道",
        "refactor", "重构",
        "duplicate code", "重复代码",
        "magic number", "魔法数字",
    ]

    INFORMATIONAL_PATTERNS = [
        "info", "信息",
        "note", "注意",
        "todo", "待办",
        "fixme", "修复我",
        "hack", "hack",
        "temporary", "临时",
        "placeholder", "占位符",
        "example", "示例",
        "test", "测试",
        "debug", "调试",
        "log", "日志",
        "print", "打印",
    ]

    def __init__(self):
        """初始化漏洞分类器"""
        self._security_patterns = [p.lower() for p in self.SECURITY_VULN_PATTERNS]
        self._sdl_patterns = [p.lower() for p in self.SDL_ISSUE_PATTERNS]
        self._quality_patterns = [p.lower() for p in self.CODE_QUALITY_PATTERNS]
        self._info_patterns = [p.lower() for p in self.INFORMATIONAL_PATTERNS]

    def classify(self, finding: Dict[str, Any]) -> VulnType:
        """分类漏洞类型

        Args:
            finding: 漏洞发现字典

        Returns:
            VulnType: 漏洞类型
        """
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        risk_type = finding.get("risk_type", "").lower()

        combined_text = f"{title} {description} {risk_type}"

        security_score = sum(1 for p in self._security_patterns if p in combined_text)
        sdl_score = sum(1 for p in self._sdl_patterns if p in combined_text)
        quality_score = sum(1 for p in self._quality_patterns if p in combined_text)
        info_score = sum(1 for p in self._info_patterns if p in combined_text)

        scores = {
            VulnType.SECURITY_VULN: security_score,
            VulnType.SDL_ISSUE: sdl_score,
            VulnType.CODE_QUALITY: quality_score,
            VulnType.INFORMATIONAL: info_score,
        }

        max_score = max(scores.values())
        if max_score == 0:
            return VulnType.INFORMATIONAL

        for vuln_type, score in scores.items():
            if score == max_score:
                return vuln_type

        return VulnType.INFORMATIONAL

    def classify_and_update(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """分类漏洞并更新 finding 字典

        Args:
            finding: 漏洞发现字典

        Returns:
            更新后的漏洞发现字典
        """
        vuln_type = self.classify(finding)
        finding["vuln_type"] = vuln_type.value
        finding["vuln_type_label"] = self.get_type_label(vuln_type)
        return finding

    def classify_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量分类漏洞

        Args:
            findings: 漏洞发现列表

        Returns:
            更新后的漏洞发现列表
        """
        return [self.classify_and_update(f) for f in findings]

    @staticmethod
    def get_type_label(vuln_type: VulnType) -> str:
        """获取漏洞类型标签

        Args:
            vuln_type: 漏洞类型

        Returns:
            中文标签
        """
        labels = {
            VulnType.SECURITY_VULN: "安全漏洞",
            VulnType.SDL_ISSUE: "SDL规范问题",
            VulnType.CODE_QUALITY: "代码质量问题",
            VulnType.INFORMATIONAL: "信息性发现",
        }
        return labels.get(vuln_type, "未知")

    @staticmethod
    def get_type_color(vuln_type: VulnType) -> str:
        """获取漏洞类型对应的颜色

        Args:
            vuln_type: 漏洞类型

        Returns:
            颜色代码
        """
        colors = {
            VulnType.SECURITY_VULN: "red",
            VulnType.SDL_ISSUE: "yellow",
            VulnType.CODE_QUALITY: "blue",
            VulnType.INFORMATIONAL: "gray",
        }
        return colors.get(vuln_type, "white")

    def filter_by_type(
        self,
        findings: List[Dict[str, Any]],
        vuln_types: List[VulnType]
    ) -> List[Dict[str, Any]]:
        """按漏洞类型过滤

        Args:
            findings: 漏洞发现列表
            vuln_types: 要保留的漏洞类型列表

        Returns:
            过滤后的漏洞发现列表
        """
        type_values = [vt.value for vt in vuln_types]
        return [
            f for f in findings
            if f.get("vuln_type") in type_values
        ]

    def separate_by_type(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[VulnType, List[Dict[str, Any]]]:
        """按漏洞类型分组

        Args:
            findings: 漏洞发现列表

        Returns:
            按类型分组的漏洞发现字典
        """
        result = {
            VulnType.SECURITY_VULN: [],
            VulnType.SDL_ISSUE: [],
            VulnType.CODE_QUALITY: [],
            VulnType.INFORMATIONAL: [],
        }

        for finding in findings:
            vuln_type = VulnType(finding.get("vuln_type", "informational"))
            result[vuln_type].append(finding)

        return result

    def get_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """获取漏洞分类统计

        Args:
            findings: 漏洞发现列表

        Returns:
            各类别数量统计
        """
        stats = {
            "security_vuln": 0,
            "sdl_issue": 0,
            "code_quality": 0,
            "informational": 0,
            "total": len(findings),
        }

        for finding in findings:
            vuln_type = finding.get("vuln_type", "informational")
            if vuln_type in stats:
                stats[vuln_type] += 1

        return stats


_classifier: Optional[VulnerabilityClassifier] = None


def get_classifier() -> VulnerabilityClassifier:
    """获取漏洞分类器单例"""
    global _classifier
    if _classifier is None:
        _classifier = VulnerabilityClassifier()
    return _classifier


def classify_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """便捷函数：分类单个漏洞"""
    return get_classifier().classify_and_update(finding)


def classify_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """便捷函数：批量分类漏洞"""
    return get_classifier().classify_batch(findings)
