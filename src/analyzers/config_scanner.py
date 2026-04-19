"""配置文件的敏感信息扫描模块

专门用于快速扫描配置文件中的硬编码凭证、密钥、密码等敏感信息。
不需要 AI 分析，使用正则模式匹配，速度快。

支持的文件类型:
- YAML (.yml, .yaml)
- Properties (.properties)
- XML (.xml)
- JSON (.json)
- ENV (.env)
- TOML (.toml)
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from src.utils.logger import get_logger

logger = get_logger(__name__)


class SensitivityLevel(Enum):
    """敏感级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ConfigFinding:
    """配置扫描发现"""
    file_path: str
    line_number: int
    key: str
    value: str
    pattern_name: str
    sensitivity: SensitivityLevel
    description: str
    remediation: str
    is_secret: bool = True


@dataclass
class ConfigScanResult:
    """配置扫描结果"""
    total_files: int = 0
    files_with_findings: int = 0
    findings: List[ConfigFinding] = field(default_factory=list)

    def get_critical_findings(self) -> List[ConfigFinding]:
        return [f for f in self.findings if f.sensitivity == SensitivityLevel.CRITICAL]

    def get_high_findings(self) -> List[ConfigFinding]:
        return [f for f in self.findings if f.sensitivity == SensitivityLevel.HIGH]


class ConfigPatterns:
    """配置敏感信息检测模式"""

    CRITICAL_PATTERNS = [
        (r'password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'hardcoded_password', '硬编码密码'),
        (r'passwd\s*[:=]\s*["\']?([^"\'\s,}]+)', 'hardcoded_passwd', '硬编码密码'),
        (r'secret\s*[:=]\s*["\']?([^"\'\s,}]+)', 'hardcoded_secret', '硬编码密钥'),
        (r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s,}]+)', 'hardcoded_api_key', '硬编码API密钥'),
        (r'access[_-]?key[_-]?id\s*[:=]\s*["\']?([^"\'\s,}]+)', 'hardcoded_access_key_id', '硬编码访问密钥ID'),
        (r'access[_-]?key[_-]?secret\s*[:=]\s*["\']?([^"\'\s,}]+)', 'hardcoded_access_key_secret', '硬编码访问密钥'),
        (r'private[_-]?key\s*[:=]\s*["\']?([^"\'\s,}]+)', 'hardcoded_private_key', '硬编码私钥'),
        (r'jasypt\s*:\s*.*\s*password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'jasypt_password', 'Jasypt加密密钥'),
    ]

    HIGH_PATTERNS = [
        (r'db[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'database_password', '数据库密码'),
        (r'db[_-]?pass\s*[:=]\s*["\']?([^"\'\s,}]+)', 'database_password', '数据库密码'),
        (r'database[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'database_password', '数据库密码'),
        (r'username\s*[:=]\s*["\']?([^"\'\s,}]+)', 'hardcoded_username', '硬编码用户名'),
        (r'user[_-]?name\s*[:=]\s*["\']?([^"\'\s,}]+)', 'hardcoded_username', '硬编码用户名'),
        (r'redis[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'redis_password', 'Redis密码'),
        (r'mail[_-]?smtp[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'smtp_password', '邮箱密码'),
        (r'smtp[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'smtp_password', 'SMTP密码'),
        (r'client[_-]?secret\s*[:=]\s*["\']?([^"\'\s,}]+)', 'client_secret', '客户端密钥'),
        (r'jwt[_-]?secret\s*[:=]\s*["\']?([^"\'\s,}]+)', 'jwt_secret', 'JWT密钥'),
        (r'encrypt[_-]?key\s*[:=]\s*["\']?([^"\'\s,}]+)', 'encryption_key', '加密密钥'),
        (r'crypto[_-]?key\s*[:=]\s*["\']?([^"\'\s,}]+)', 'crypto_key', '加密密钥'),
    ]

    MEDIUM_PATTERNS = [
        (r'login[_-]?username\s*[:=]\s*["\']?([^"\'\s,}]+)', 'login_username', '登录用户名'),
        (r'login[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'login_password', '登录密码'),
        (r'druid[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'druid_password', 'Druid密码'),
        (r'elastic[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'elastic_password', 'Elasticsearch密码'),
        (r'kafka[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'kafka_password', 'Kafka密码'),
        (r'mongo[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'mongodb_password', 'MongoDB密码'),
    ]

    LOW_PATTERNS = [
        (r'default[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'default_password', '默认密码'),
        (r'admin[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'admin_password', '管理员密码'),
        (r'guest[_-]?password\s*[:=]\s*["\']?([^"\'\s,}]+)', 'guest_password', '访客密码'),
    ]

    INSECURE_PATTERNS = [
        (r'\{noop\}', 'insecure_password_prefix', '不安全的密码前缀(noop)'),
        (r'\{noop\s+', 'insecure_password_prefix', '不安全的密码前缀(noop)'),
    ]

    SENSITIVE_PATHS = [
        r'/actuator/',
        r'/druid/',
        r'/admin/',
        r'/debug/',
        r'/env',
        r'/heapdump',
        r'/threaddump',
    ]

    @classmethod
    def get_all_patterns(cls) -> List[Tuple[re.Pattern, str, str, SensitivityLevel]]:
        """获取所有模式"""
        patterns = []
        for pattern_str, name, desc in cls.CRITICAL_PATTERNS:
            patterns.append((re.compile(pattern_str, re.IGNORECASE), name, desc, SensitivityLevel.CRITICAL))
        for pattern_str, name, desc in cls.HIGH_PATTERNS:
            patterns.append((re.compile(pattern_str, re.IGNORECASE), name, desc, SensitivityLevel.HIGH))
        for pattern_str, name, desc in cls.MEDIUM_PATTERNS:
            patterns.append((re.compile(pattern_str, re.IGNORECASE), name, desc, SensitivityLevel.MEDIUM))
        for pattern_str, name, desc in cls.LOW_PATTERNS:
            patterns.append((re.compile(pattern_str, re.IGNORECASE), name, desc, SensitivityLevel.LOW))
        return patterns

    @classmethod
    def get_insecure_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        """获取不安全模式"""
        patterns = []
        for pattern_str, name, desc in cls.INSECURE_PATTERNS:
            patterns.append((re.compile(pattern_str, re.IGNORECASE), name, desc))
        return patterns


class ConfigScanner:
    """配置文件敏感信息扫描器"""

    CONFIG_EXTENSIONS = {
        '.yml', '.yaml', '.properties', '.xml', '.json', '.env', '.toml', '.ini', '.conf'
    }

    CONFIG_DIR_PATTERNS = {
        'config', 'conf', 'configuration', 'settings', 'data', 'resources'
    }

    def __init__(self, include_sensitive_paths: bool = True):
        """初始化配置扫描器

        Args:
            include_sensitive_paths: 是否扫描敏感路径暴露
        """
        self.include_sensitive_paths = include_sensitive_paths
        self.patterns = ConfigPatterns.get_all_patterns()
        self.insecure_patterns = ConfigPatterns.get_insecure_patterns()
        self._findings: List[ConfigFinding] = []

    def is_config_file(self, file_path: str) -> bool:
        """判断是否为配置文件

        Args:
            file_path: 文件路径

        Returns:
            是否为配置文件
        """
        path = Path(file_path)

        if path.suffix.lower() in self.CONFIG_EXTENSIONS:
            return True

        path_str = str(path).lower()
        for pattern in self.CONFIG_DIR_PATTERNS:
            if pattern in path_str:
                return True

        return False

    def scan_file(self, file_path: str, content: Optional[str] = None) -> List[ConfigFinding]:
        """扫描单个配置文件

        Args:
            file_path: 文件路径
            content: 文件内容（如果为None则读取文件）

        Returns:
            发现列表
        """
        findings = []

        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                logger.debug(f"无法读取文件 {file_path}: {e}")
                return findings

        lines = content.split('\n')

        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            for pattern, name, desc, sensitivity in self.patterns:
                match = pattern.search(line)
                if match:
                    value = match.group(1) if match.groups() else ''

                    if self._is_likely_placeholder(value):
                        continue

                    finding = ConfigFinding(
                        file_path=file_path,
                        line_number=line_num,
                        key=name,
                        value=value,
                        pattern_name=name,
                        sensitivity=sensitivity,
                        description=f"{desc}: {self._mask_value(value)}",
                        remediation=self._get_remediation(name)
                    )
                    findings.append(finding)

            for pattern, name, desc in self.insecure_patterns:
                if pattern.search(line):
                    finding = ConfigFinding(
                        file_path=file_path,
                        line_number=line_num,
                        key=name,
                        value=line,
                        pattern_name=name,
                        sensitivity=SensitivityLevel.MEDIUM,
                        description=f"发现{desc}",
                        remediation="使用强密码或移除不安全的密码前缀"
                    )
                    findings.append(finding)

        if self.include_sensitive_paths:
            for line_num, line in enumerate(lines, start=1):
                for path_pattern in ConfigPatterns.SENSITIVE_PATHS:
                    if path_pattern in line and ('/**' in line or 'release-urls' in line.lower()):
                        finding = ConfigFinding(
                            file_path=file_path,
                            line_number=line_num,
                            key='sensitive_path_exposure',
                            value=line.strip(),
                            pattern_name='sensitive_path_exposure',
                            sensitivity=SensitivityLevel.MEDIUM,
                            description=f"敏感路径暴露: {path_pattern}",
                            remediation=f"限制对 {path_pattern} 的访问"
                        )
                        findings.append(finding)

        return findings

    def scan_directory(self, directory: str, recursive: bool = True) -> ConfigScanResult:
        """扫描目录中的所有配置文件

        Args:
            directory: 目录路径
            recursive: 是否递归扫描子目录

        Returns:
            扫描结果
        """
        result = ConfigScanResult()
        dir_path = Path(directory)

        if not dir_path.exists():
            logger.warning(f"目录不存在: {directory}")
            return result

        for file_path in dir_path.rglob('*') if recursive else dir_path.glob('*'):
            if not file_path.is_file():
                continue

            if not self.is_config_file(str(file_path)):
                continue

            result.total_files += 1

            findings = self.scan_file(str(file_path))
            if findings:
                result.files_with_findings += 1
                result.findings.extend(findings)

        return result

    def scan_files(self, file_paths: List[str]) -> ConfigScanResult:
        """扫描多个文件

        Args:
            file_paths: 文件路径列表

        Returns:
            扫描结果
        """
        result = ConfigScanResult()

        for file_path in file_paths:
            if not self.is_config_file(file_path):
                continue

            result.total_files += 1

            findings = self.scan_file(file_path)
            if findings:
                result.files_with_findings += 1
                result.findings.extend(findings)

        return result

    def _is_likely_placeholder(self, value: str) -> bool:
        """判断值是否为占位符

        Args:
            value: 值

        Returns:
            是否为占位符
        """
        placeholders = {
            'xxx', 'xxx...', 'your_password', 'your_secret',
            '***', '****', '*****', '<secret>', '<password>',
            '${', '${}', '{{', '}}', '${password}', '${secret}',
            'changeme', 'changepassword', 'your-key-here',
            'xxxxxxxx', 'xxxxxxxxxxxxxxxx', 'xxxxxxxxxxxxx',
            'example', 'test', 'null', 'none', 'undefined'
        }

        value_lower = value.lower().strip()
        return value_lower in placeholders or value_lower.startswith('${') or value_lower.startswith('{{')

    def _mask_value(self, value: str, visible_chars: int = 4) -> str:
        """遮蔽敏感值

        Args:
            value: 原始值
            visible_chars: 保留可见字符数

        Returns:
            遮蔽后的值
        """
        if len(value) <= visible_chars:
            return '*' * len(value)

        return value[:visible_chars] + '*' * (len(value) - visible_chars)

    def _get_remediation(self, key: str) -> str:
        """获取修复建议

        Args:
            key: 问题类型

        Returns:
            修复建议
        """
        remediations = {
            'hardcoded_password': '使用环境变量或密钥管理服务存储密码',
            'hardcoded_secret': '使用密钥管理服务存储密钥',
            'hardcoded_api_key': '使用环境变量存储API密钥，不要硬编码',
            'hardcoded_access_key_id': '使用IAM角色或密钥管理服务',
            'hardcoded_access_key_secret': '使用IAM角色或密钥管理服务',
            'hardcoded_private_key': '使用密钥管理服务存储私钥',
            'jasypt_password': '使用外部密钥管理或环境变量',
            'database_password': '使用环境变量 ${DB_PASSWORD} 替代',
            'redis_password': '使用环境变量 ${REDIS_PASSWORD} 替代',
            'smtp_password': '使用环境变量 ${SMTP_PASSWORD} 替代',
            'client_secret': '使用OAuth客户端凭证管理',
            'jwt_secret': '使用强随机密钥并通过安全方式分发',
            'encryption_key': '使用密钥管理服务(KMS)管理加密密钥',
            'login_password': '使用强密码策略和安全的密码存储',
            'default_password': '强制用户首次登录时更改密码',
            'insecure_password_prefix': '移除 {noop} 前缀，使用 bcrypt 或其他安全算法',
            'sensitive_path_exposure': '限制对敏感端点的访问，使用认证和授权'
        }

        return remediations.get(key, '使用环境变量或密钥管理服务存储敏感信息')


def scan_config_directory(directory: str, include_sensitive_paths: bool = True) -> ConfigScanResult:
    """快速扫描配置目录

    Args:
        directory: 目录路径
        include_sensitive_paths: 是否扫描敏感路径暴露

    Returns:
        扫描结果
    """
    scanner = ConfigScanner(include_sensitive_paths=include_sensitive_paths)
    return scanner.scan_directory(directory)


def scan_config_files(file_paths: List[str]) -> ConfigScanResult:
    """快速扫描多个配置文件

    Args:
        file_paths: 文件路径列表

    Returns:
        扫描结果
    """
    scanner = ConfigScanner()
    return scanner.scan_files(file_paths)
