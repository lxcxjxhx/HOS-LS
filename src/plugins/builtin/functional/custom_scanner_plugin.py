"""自定义扫描器插件

演示如何创建自定义扫描插件，支持文件模式检测和敏感数据扫描。
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.plugins.base import ScanPlugin, PluginMetadata, PluginPriority


class CustomScannerPlugin(ScanPlugin):
    """自定义扫描器插件基类

    提供通用的扫描框架，支持自定义规则和模式配置。
    """

    DEFAULT_CONFIG = {
        "enabled_rules": ["sensitive_data", "filename_pattern"],
        "exclude_extensions": [".md", ".txt", ".log"],
        "max_file_size_kb": 1024,
        "case_sensitive": False,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        metadata = PluginMetadata(
            name="custom_scanner",
            version="1.0.0",
            description="自定义文件扫描器，支持模式匹配和敏感数据检测",
            author="HOS-LS Team",
            priority=PluginPriority.NORMAL,
            enabled=True,
        )
        super().__init__(metadata, config)
        self._config = {**self.DEFAULT_CONFIG, **(config or {})}
        self._initialize_rules()

    def _initialize_rules(self) -> None:
        """初始化扫描规则"""
        self._rules: List[Dict[str, Any]] = []

        if "sensitive_data" in self._config["enabled_rules"]:
            self._rules.append({
                "name": "sensitive_data",
                "pattern": self._build_sensitive_pattern(),
                "severity": "HIGH",
                "message": "检测到敏感数据模式",
            })

        if "filename_pattern" in self._config["enabled_rules"]:
            self._rules.append({
                "name": "filename_pattern",
                "pattern": self._build_filename_pattern(),
                "severity": "MEDIUM",
                "message": "检测到可疑文件名模式",
            })

    def _build_sensitive_pattern(self) -> re.Pattern:
        """构建敏感数据检测正则"""
        sensitive_patterns = [
            r'password\s*=\s*["\'][^"\']{3,}["\']',
            r'api[_-]?key\s*=\s*["\'][^"\']{10,}["\']',
            r'secret\s*=\s*["\'][^"\']{3,}["\']',
            r'token\s*=\s*["\'][^"\']{10,}["\']',
            r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
            r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
            r'AKIA[0-9A-Z]{16}',
            r'sk_live_[0-9a-zA-Z]{24,}',
        ]
        pattern = "|".join(sensitive_patterns)
        flags = 0 if self._config.get("case_sensitive") else re.IGNORECASE
        return re.compile(pattern, flags)

    def _build_filename_pattern(self) -> re.Pattern:
        """构建文件名检测正则"""
        suspicious_names = [
            r'\.env\.',
            r'\.gitignore',
            r'config\.',
            r'secret',
            r'credentials',
            r'\.pem$',
            r'\.key$',
            r'\.p12$',
            r'\.jks$',
        ]
        pattern = "|".join(suspicious_names)
        return re.compile(pattern, re.IGNORECASE)

    async def scan(
        self, file_path: Path, content: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """扫描文件

        Args:
            file_path: 文件路径
            content: 文件内容
            context: 扫描上下文

        Returns:
            发现的安全问题列表
        """
        findings = []

        if self._should_skip_file(file_path):
            return findings

        for rule in self._rules:
            matches = rule["pattern"].finditer(content)
            for match in matches:
                findings.append({
                    "rule_id": f"custom_{rule['name']}",
                    "rule_name": rule["name"],
                    "message": rule["message"],
                    "severity": rule["severity"],
                    "confidence": "MEDIUM",
                    "location": {
                        "file": str(file_path),
                        "line": content[:match.start()].count("\n") + 1,
                        "column": self._get_column(content, match.start()),
                    },
                    "matched_content": match.group()[:100],
                    "plugin": self.name,
                })

        return findings

    def _should_skip_file(self, file_path: Path) -> bool:
        """检查是否应跳过文件"""
        if file_path.suffix in self._config["exclude_extensions"]:
            return True

        try:
            size_kb = file_path.stat().st_size / 1024
            if size_kb > self._config["max_file_size_kb"]:
                return True
        except OSError:
            pass

        return False

    def _get_column(self, content: str, position: int) -> int:
        """获取匹配位置的列号"""
        line_start = content.rfind("\n", 0, position) + 1
        return position - line_start + 1


class SensitiveDataDetector(ScanPlugin):
    """敏感数据检测插件

    专门用于检测代码中的敏感信息，如密码、密钥、令牌等。
    """

    SENSITIVE_PATTERNS = {
        "password": {
            "pattern": r'(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{3,})["\']',
            "severity": "HIGH",
            "rule_id": "硬编码密码",
        },
        "api_key": {
            "pattern": r'(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{10,})["\']',
            "severity": "HIGH",
            "rule_id": "硬编码API密钥",
        },
        "secret_key": {
            "pattern": r'(secret[_-]?key|client[_-]?secret)\s*[=:]\s*["\']([^"\']{10,})["\']',
            "severity": "HIGH",
            "rule_id": "硬编码密钥",
        },
        "bearer_token": {
            "pattern": r'Bearer\s+[0-9a-zA-Z_\-]{20,}',
            "severity": "HIGH",
            "rule_id": "暴露的Bearer令牌",
        },
        "aws_key": {
            "pattern": r'AKIA[0-9A-Z]{16}',
            "severity": "CRITICAL",
            "rule_id": "AWS访问密钥",
        },
        "private_key": {
            "pattern": r'-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----',
            "severity": "CRITICAL",
            "rule_id": "私钥文件",
        },
        "jwt_token": {
            "pattern": r'eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+',
            "severity": "MEDIUM",
            "rule_id": "JWT令牌",
        },
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        metadata = PluginMetadata(
            name="sensitive_data_detector",
            version="1.0.0",
            description="检测代码中的敏感数据泄露",
            author="HOS-LS Team",
            priority=PluginPriority.HIGH,
            enabled=True,
        )
        super().__init__(metadata, config)
        self._patterns = {
            name: re.compile(data["pattern"], re.IGNORECASE)
            for name, data in self.SENSITIVE_PATTERNS.items()
        }
        self._exclude_paths = config.get("exclude_paths", []) if config else []

    async def scan(
        self, file_path: Path, content: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """扫描敏感数据

        Args:
            file_path: 文件路径
            content: 文件内容
            context: 扫描上下文

        Returns:
            发现的安全问题列表
        """
        findings = []

        if any(str(file_path).startswith(excl) for excl in self._exclude_paths):
            return findings

        for name, pattern in self._patterns.items():
            rule_data = self.SENSITIVE_PATTERNS[name]
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "rule_id": rule_data["rule_id"],
                    "rule_name": name,
                    "message": f"检测到敏感数据: {rule_data['rule_id']}",
                    "severity": rule_data["severity"],
                    "confidence": "HIGH",
                    "location": {
                        "file": str(file_path),
                        "line": line_num,
                        "column": self._get_column(content, match.start()),
                    },
                    "matched_content": match.group()[:100],
                    "plugin": self.name,
                })

        return findings

    def _get_column(self, content: str, position: int) -> int:
        """获取列号"""
        line_start = content.rfind("\n", 0, position) + 1
        return position - line_start + 1


class FilenamePatternScanner(ScanPlugin):
    """文件名模式扫描器

    根据文件名模式检测潜在的安全风险文件。
    """

    DEFAULT_PATTERNS = [
        (r"\.env$", "MEDIUM", "环境配置文件"),
        (r"\.env\.", "MEDIUM", "环境配置备份文件"),
        (r"\.gitignore$", "LOW", "Git忽略配置"),
        (r"config\.py$", "MEDIUM", "配置文件"),
        (r"secret", "HIGH", "包含secret的文件"),
        (r"credentials", "HIGH", "包含credentials的文件"),
        (r"\.pem$", "CRITICAL", "PEM证书文件"),
        (r"\.key$", "CRITICAL", "密钥文件"),
        (r"\.p12$", "CRITICAL", "PKCS12证书文件"),
        (r"\.jks$", "CRITICAL", "Java密钥库文件"),
        (r"id_rsa", "CRITICAL", "SSH私钥文件"),
        (r"\.sqlite$", "MEDIUM", "SQLite数据库文件"),
        (r"\.db$", "MEDIUM", "数据库文件"),
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        metadata = PluginMetadata(
            name="filename_pattern_scanner",
            version="1.0.0",
            description="根据文件名模式检测风险文件",
            author="HOS-LS Team",
            priority=PluginPriority.NORMAL,
            enabled=True,
        )
        super().__init__(metadata, config)
        self._config = config or {}
        self._patterns = self._compile_patterns()

    def _compile_patterns(self) -> List[tuple]:
        """编译文件名模式"""
        patterns = self._config.get("patterns", self.DEFAULT_PATTERNS)
        compiled = []
        for pattern_str, severity, description in patterns:
            try:
                compiled.append((
                    re.compile(pattern_str, re.IGNORECASE),
                    severity,
                    description
                ))
            except re.error:
                continue
        return compiled

    async def scan(
        self, file_path: Path, content: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """扫描文件名模式

        Args:
            file_path: 文件路径
            content: 文件内容
            context: 扫描上下文

        Returns:
            发现的安全问题列表
        """
        findings = []
        filename = file_path.name

        for pattern, severity, description in self._patterns:
            if pattern.search(filename):
                findings.append({
                    "rule_id": f"filename_{description}",
                    "rule_name": "filename_pattern",
                    "message": f"检测到风险文件: {description}",
                    "severity": severity,
                    "confidence": "HIGH",
                    "location": {
                        "file": str(file_path),
                        "line": 0,
                        "column": 0,
                    },
                    "matched_content": filename,
                    "plugin": self.name,
                })
                break

        return findings