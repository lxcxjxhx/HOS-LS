"""安全文件过滤器 - 仿人类专家思维

根据文件路径/名称预判可疑程度，实现智能分层扫描
"""
import fnmatch
import re
from pathlib import Path
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class SuspiciousFile:
    """可疑文件信息"""
    file_path: str
    risk_level: RiskLevel
    reasons: List[str]
    expected_vulnerabilities: List[str]


class SecurityFileFilter:
    """安全文件过滤器 - 仿人类专家思维"""

    CRITICAL_RISK_PATTERNS = {
        "UserMapper.xml": {
            "vulnerabilities": ["SQL注入（CWE-89）- ${} 动态拼接"],
            "check_patterns": ["${", "#{", "sqlSegment", "queryWrapper", "ew.sqlSegment"]
        },
        "BrandMapper.xml": {
            "vulnerabilities": ["SQL注入（CWE-89）- ${queryWrapper.sqlSegment}"],
            "check_patterns": ["${queryWrapper.sqlSegment", "${ew.sqlSegment"]
        },
        "GoodsCategoryMapper.xml": {
            "vulnerabilities": ["SQL注入（CWE-89）- ${ew.sqlSegment}"],
            "check_patterns": ["${ew.sqlSegment", "${queryWrapper"]
        },
        "*Mapper.xml": {
            "vulnerabilities": ["SQL注入（CWE-89）- MyBatis ${} 拼接"],
            "check_patterns": ["${", "#{", "sqlSegment"]
        },
        "UploadFileController.java": {
            "vulnerabilities": [
                "文件上传漏洞（CWE-434）- 缺少适当验证",
                "路径遍历漏洞（CWE-22）- 用户控制路径"
            ],
            "check_patterns": ["MultipartFile", "fileName", "upload", "download", "new File("]
        },
        "WebSecurityConfigurer.java": {
            "vulnerabilities": ["CSRF防护禁用（CWE-352）"],
            "check_patterns": [".csrf().disable()", "csrf().disable"]
        },
        "SecurityEnum.java": {
            "vulnerabilities": ["不安全密码存储（CWE-259）- {noop}前缀"],
            "check_patterns": ["{noop}", "CLIENT_FIELDS", "client_secret"]
        },
        "CommonEnum.java": {
            "vulnerabilities": ["硬编码默认密码（CWE-259）"],
            "check_patterns": ["DEFAULT_PASSWORD", "123456", "password"]
        },
        "SecurityUtils.java": {
            "vulnerabilities": ["敏感信息泄露（CWE-200）- 敏感请求头"],
            "check_patterns": ["getHeader", "userName", "UserId", "getHeader(\"userName\")"]
        },
    }

    HIGH_RISK_PATTERNS = {
        "*Controller.java": {
            "vulnerabilities": ["敏感数据处理不当", "输入验证缺失"],
            "check_patterns": ["request", "response", "getParameter", "getHeader"]
        },
        "*Service.java": {
            "vulnerabilities": ["业务逻辑漏洞", "敏感数据泄露"],
            "check_patterns": ["password", "secret", "token", "credential", "private"]
        },
        "*Dao.java": {
            "vulnerabilities": ["SQL注入", "数据访问漏洞"],
            "check_patterns": [" jdbc", "Statement", "executeQuery", "${"]
        },
        "*Util.java": {
            "vulnerabilities": ["敏感信息处理"],
            "check_patterns": ["password", "secret", "key", "encrypt", "decrypt"]
        },
    }

    CONFIG_FILE_PATTERNS = {
        "*.yml": ["password", "secret", "key", "accessKey", "accessKeySecret", "jasypt"],
        "*.yaml": ["password", "secret", "key", "accessKey", "accessKeySecret", "jasypt"],
        "*.properties": ["password", "secret", "key", "driver", "url"],
        "*.xml": ["password", "driver", "url", "username", "jdbc"],
    }

    def __init__(self):
        self.critical_patterns = self.CRITICAL_RISK_PATTERNS
        self.high_patterns = self.HIGH_RISK_PATTERNS
        self.config_patterns = self.CONFIG_FILE_PATTERNS

    def classify_file(self, file_path: str, content: str = None) -> SuspiciousFile:
        """分类单个文件

        Args:
            file_path: 文件路径
            content: 文件内容（可选）

        Returns:
            SuspiciousFile 对象
        """
        file_name = Path(file_path).name
        file_path_str = str(file_path)
        file_path_lower = file_path_str.lower()

        reasons = []
        expected_vulns = []
        risk_level = RiskLevel.SAFE

        for pattern, info in self.critical_patterns.items():
            if self._match_pattern(pattern, file_name, file_path):
                reasons.append(f"匹配关键风险模式: {pattern}")
                expected_vulns.extend(info["vulnerabilities"])
                risk_level = RiskLevel.CRITICAL
                break

        if risk_level == RiskLevel.SAFE:
            for pattern, info in self.high_patterns.items():
                if self._match_pattern(pattern, file_name, file_path):
                    reasons.append(f"匹配高风险模式: {pattern}")
                    expected_vulns.extend(info["vulnerabilities"])
                    risk_level = RiskLevel.HIGH
                    break

        if content and risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            actual_patterns = self._detect_patterns_in_content(
                content,
                self.critical_patterns.get(file_name, {}).get("check_patterns", []) +
                self.high_patterns.get(file_name, {}).get("check_patterns", [])
            )
            if actual_patterns:
                reasons.append(f"内容检测到风险模式: {', '.join(actual_patterns[:3])}")

        if self._is_config_file(file_path):
            reasons.append("配置文件 - 检查敏感信息硬编码")
            if risk_level.value < RiskLevel.MEDIUM.value:
                risk_level = RiskLevel.MEDIUM

        return SuspiciousFile(
            file_path=file_path,
            risk_level=risk_level,
            reasons=reasons,
            expected_vulnerabilities=expected_vulns
        )

    def filter_files(self, files: List[str], content_map: Dict[str, str] = None) -> Dict[str, List[SuspiciousFile]]:
        """过滤文件

        Args:
            files: 文件路径列表
            content_map: 文件路径到内容的映射（可选）

        Returns:
            {
                "critical": [...],
                "high": [...],
                "medium": [...],
                "low": [...],
                "safe": [...]  # 被忽略的文件
            }
        """
        result = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "safe": []
        }

        for file_path in files:
            content = content_map.get(file_path) if content_map else None
            classified = self.classify_file(file_path, content)

            if classified.risk_level == RiskLevel.CRITICAL:
                result["critical"].append(classified)
            elif classified.risk_level == RiskLevel.HIGH:
                result["high"].append(classified)
            elif classified.risk_level == RiskLevel.MEDIUM:
                result["medium"].append(classified)
            elif classified.risk_level == RiskLevel.LOW:
                result["low"].append(classified)
            else:
                result["safe"].append(classified)

        return result

    def get_files_by_risk(self, files: List[str], min_risk: RiskLevel = RiskLevel.LOW) -> List[str]:
        """根据风险等级获取文件列表

        Args:
            files: 文件路径列表
            min_risk: 最低风险等级

        Returns:
            符合风险等级的文件路径列表
        """
        content_map = {}
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content_map[file_path] = f.read()
            except:
                pass

        filtered = self.filter_files(files, content_map)

        result = []
        risk_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]
        min_idx = risk_order.index(min_risk) if min_risk in risk_order else 0

        for i in range(min_idx, len(risk_order)):
            level = risk_order[i]
            level_name = level.value
            if level_name in filtered:
                result.extend([f.file_path for f in filtered[level_name]])

        return result

    def get_target_files_for_scan(self, files: List[str], limit: int = None) -> Tuple[List[str], Dict[str, SuspiciousFile]]:
        """获取扫描目标文件

        仿人类专家：优先扫描高危文件，控制扫描数量

        Args:
            files: 文件路径列表
            limit: 限制返回数量

        Returns:
            (目标文件列表, 文件分类信息)
        """
        content_map = {}
        for file_path in files:
            if self._is_config_file(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content_map[file_path] = f.read()
                except:
                    pass

        filtered = self.filter_files(files, content_map)

        target_files = []

        for level_name in ["critical", "high", "medium", "low"]:
            for sf in filtered.get(level_name, []):
                target_files.append(sf.file_path)

        if limit:
            target_files = target_files[:limit]

        all_classified = {}
        for level_name in filtered:
            for sf in filtered[level_name]:
                all_classified[sf.file_path] = sf

        return target_files, all_classified

    def _match_pattern(self, pattern: str, file_name: str, file_path: str) -> bool:
        """匹配模式"""
        if "*" in pattern:
            return fnmatch.fnmatch(file_name, pattern) or fnmatch.fnmatch(file_path, pattern)
        else:
            return pattern in file_name or pattern in file_path

    def _is_config_file(self, file_path: str) -> bool:
        """判断是否为配置文件"""
        file_path_str = str(file_path)
        for ext_patterns in self.config_patterns.values():
            for ext_pattern in ext_patterns:
                if ext_pattern.startswith("*."):
                    ext = ext_pattern[1:]
                    if file_path_str.lower().endswith(ext):
                        return True
        return False

    def _detect_patterns_in_content(self, content: str, patterns: List[str]) -> List[str]:
        """检测内容中的模式"""
        found = []
        for pattern in patterns:
            if pattern in content:
                found.append(pattern)
        return found

    def get_risk_summary(self, files: List[str]) -> Dict[str, int]:
        """获取风险摘要

        Args:
            files: 文件路径列表

        Returns:
            各风险等级的文件数量
        """
        content_map = {}
        for file_path in files:
            if self._is_config_file(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content_map[file_path] = f.read()
                except:
                    pass

        filtered = self.filter_files(files, content_map)

        return {
            "critical": len(filtered.get("critical", [])),
            "high": len(filtered.get("high", [])),
            "medium": len(filtered.get("medium", [])),
            "low": len(filtered.get("low", [])),
            "safe": len(filtered.get("safe", [])),
            "total": len(files)
        }


def create_file_filter() -> SecurityFileFilter:
    """创建文件过滤器实例"""
    return SecurityFileFilter()
