"""SARIF 输入标准化模块

基于 ZeroFalse 论文中对多 SAST 工具输出进行归一化的方法，本模块实现了通过 SARIF
（Static Analysis Results Interchange Format）格式对不同静态分析工具的输出进行解析、
标准化、去重和合并的功能。

支持的 SAST 工具：
  - Semgrep（规则 ID 形如 ``java.sql-injection``）
  - CodeQL（规则 ID 形如 ``java/SqlInjection``）
  - SonarQube（规则 ID 形如 ``java:S3649``）
  - Bandit（Python 安全检测）
  - ESLint 安全插件（如 eslint-plugin-security）

核心能力：
  1. 解析 SARIF JSON 文件 / 字典为结构化数据
  2. 将多工具结果统一为 ``NormalizedFinding`` 格式
  3. 基于文件路径、行号容差、CWE 映射与描述相似度进行跨工具去重
  4. 将工具特有规则 ID 映射到通用 CWE 分类体系
  5. 将 HOS-LS 内部发现导出为 SARIF 格式
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class SarifLocation:
    """SARIF 结果中的位置信息。

    Attributes:
        file_path: 文件路径（已标准化为正向斜杠形式）。
        start_line: 起始行号（1-based），0 表示未知。
        end_line: 结束行号（1-based），0 表示未知。
        start_column: 起始列号（1-based），0 表示未知。
        end_column: 结束列号（1-based），0 表示未知。
    """

    file_path: str = ""
    start_line: int = 0
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典。"""
        return {
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "end_column": self.end_column,
        }

    @classmethod
    def from_sarif(cls, location_data: Dict[str, Any]) -> "SarifLocation":
        """从 SARIF location 字典构造实例。

        Args:
            location_data: SARIF 规范中 ``locations[].physicalLocation`` 对象。

        Returns:
            SarifLocation 实例。
        """
        artifact = location_data.get("physicalLocation", {})
        artifact_uri = (
            artifact
            .get("artifactLocation", {})
            .get("uri", "")
        )
        region = artifact.get("region", {})

        # 标准化路径：使用正斜杠，去除前导 ./
        normalized_path = artifact_uri.replace("\\", "/")
        if normalized_path.startswith("./"):
            normalized_path = normalized_path[2:]

        return cls(
            file_path=normalized_path,
            start_line=region.get("startLine", 0),
            end_line=region.get("endLine", region.get("startLine", 0)),
            start_column=region.get("startColumn", 0),
            end_column=region.get("endColumn", 0),
        )


@dataclass
class SarifResult:
    """单条 SARIF 结果。

    Attributes:
        rule_id: 工具规则标识符。
        message: 人类可读的描述信息。
        locations: 关联的代码位置列表。
        severity: 严重级别（error / warning / note / none）。
        properties: 扩展属性（含工具自定义字段）。
    """

    rule_id: str = ""
    message: str = ""
    locations: List[SarifLocation] = field(default_factory=list)
    severity: str = "warning"
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典。"""
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "locations": [loc.to_dict() for loc in self.locations],
            "severity": self.severity,
            "properties": self.properties,
        }

    @classmethod
    def from_sarif(
        cls,
        result_data: Dict[str, Any],
        rule_severity_map: Dict[str, str],
    ) -> "SarifResult":
        """从 SARIF result 字典构造实例。

        Args:
            result_data: SARIF ``results`` 数组中的一个元素。
            rule_severity_map: 规则 ID → 严重级别 的映射表，用于回退查找。

        Returns:
            SarifResult 实例。
        """
        rule_id = result_data.get("ruleId", "")

        # 提取消息
        message_obj = result_data.get("message", {})
        message = message_obj.get("text", "")
        if not message:
            message = message_obj.get("markdown", "")

        # 提取位置列表
        locations: List[SarifLocation] = []
        for loc in result_data.get("locations", []):
            locations.append(SarifLocation.from_sarif(loc))

        # 严重级别：优先 result 自身 → 规则映射表 → 默认 warning
        level = result_data.get("level", "")
        if not level:
            level = rule_severity_map.get(rule_id, "warning")

        # 扩展属性
        properties = result_data.get("properties", {})
        # 将 fingerprints / partialFingerprints 一并保留
        fp = result_data.get("fingerprints", {})
        if fp:
            properties["fingerprints"] = fp
        pfp = result_data.get("partialFingerprints", {})
        if pfp:
            properties["partialFingerprints"] = pfp

        # 关联的 code flow / related locations 也保留
        code_flows = result_data.get("codeFlows", [])
        if code_flows:
            properties["codeFlows"] = code_flows

        return cls(
            rule_id=rule_id,
            message=message,
            locations=locations,
            severity=level,
            properties=properties,
        )


@dataclass
class SarifRun:
    """SARIF 中的一次工具运行。

    Attributes:
        tool_name: 工具名称。
        tool_version: 工具版本。
        results: 本次运行产出的结果列表。
        artifacts: 引用的制品（文件）列表。
        rules: 规则定义列表（含 ID、严重级别、CWE 等元数据）。
    """

    tool_name: str = ""
    tool_version: str = ""
    results: List[SarifResult] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    rules: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典。"""
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "results": [r.to_dict() for r in self.results],
            "artifacts": self.artifacts,
            "rules": self.rules,
        }


@dataclass
class NormalizedFinding:
    """标准化后的统一发现格式，用于映射到 HOS-LS 内部数据结构。

    Attributes:
        rule_id: 原始工具规则 ID。
        message: 描述信息。
        file_path: 标准化后的文件路径。
        start_line: 起始行号。
        end_line: 结束行号。
        start_column: 起始列号。
        end_column: 结束列号。
        severity: 标准化严重级别（critical / high / medium / low / info）。
        cwe_id: CWE 编号（如 ``CWE-89``）。
        tool_name: 产出该结果的工具名称。
        confidence: 置信度（0.0 ~ 1.0）。
        source_tool_rule: 工具特有规则标识（保留原始值用于溯源）。
        properties: 额外扩展字段。
    """

    rule_id: str = ""
    message: str = ""
    file_path: str = ""
    start_line: int = 0
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0
    severity: str = "medium"
    cwe_id: str = ""
    tool_name: str = ""
    confidence: float = 1.0
    source_tool_rule: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典，可直接对接 HOS-LS 内部 ``AnalysisIssue``。"""
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "end_column": self.end_column,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "tool_name": self.tool_name,
            "confidence": self.confidence,
            "source_tool_rule": self.source_tool_rule,
            "properties": self.properties,
        }

    def to_analysis_issue_dict(self) -> Dict[str, Any]:
        """转换为与 ``AnalysisIssue.to_dict()`` 兼容的字典格式。

        可直接传入 HOS-LS 的分析结果管道。
        """
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "line": self.start_line,
            "column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "severity": self.severity,
            "confidence": self.confidence,
            "code_snippet": self.properties.get("code_snippet", ""),
            "fix_suggestion": self.properties.get("fix_suggestion", ""),
            "cwe_id": self.cwe_id if self.cwe_id else None,
            "owasp_category": self.properties.get("owasp_category", None),
            "metadata": {
                "tool_name": self.tool_name,
                "source_tool_rule": self.source_tool_rule,
                "file_path": self.file_path,
                **self.properties,
            },
        }


# ---------------------------------------------------------------------------
# CWE 映射表
# ---------------------------------------------------------------------------

# Semgrep 规则前缀 → CWE 映射
_SEMGREP_CWE_MAP: Dict[str, str] = {
    "sql-injection": "CWE-89",
    "sqli": "CWE-89",
    "command-injection": "CWE-78",
    "cmdi": "CWE-78",
    "os-command": "CWE-78",
    "path-traversal": "CWE-22",
    "lfi": "CWE-22",
    "directory-traversal": "CWE-22",
    "xss": "CWE-79",
    "cross-site-scripting": "CWE-79",
    "xxe": "CWE-611",
    "xml-external-entity": "CWE-611",
    "ssrf": "CWE-918",
    "server-side-request-forgery": "CWE-918",
    "hardcoded-secret": "CWE-798",
    "hardcoded-password": "CWE-259",
    "hardcoded-credential": "CWE-798",
    "weak-crypto": "CWE-327",
    "insecure-hash": "CWE-328",
    "deserialization": "CWE-502",
    "insecure-deserialization": "CWE-502",
    "open-redirect": "CWE-601",
    "ldap-injection": "CWE-90",
    "xpath-injection": "CWE-643",
    "regex-dos": "CWE-1333",
    "redos": "CWE-1333",
    "missing-auth": "CWE-306",
    "authentication-bypass": "CWE-287",
    "csrf": "CWE-352",
    "insecure-cookie": "CWE-614",
    "missing-encryption": "CWE-311",
    "null-dereference": "CWE-476",
    "use-after-free": "CWE-416",
    "buffer-overflow": "CWE-120",
    "integer-overflow": "CWE-190",
    "race-condition": "CWE-362",
    "unsafe-reflection": "CWE-470",
    "log-injection": "CWE-117",
    "header-injection": "CWE-113",
    "template-injection": "CWE-1336",
    "ssti": "CWE-1336",
    "jwt": "CWE-345",
    "cors": "CWE-942",
    "missing-cors": "CWE-942",
}

# CodeQL 查询名 → CWE 映射
_CODEQL_CWE_MAP: Dict[str, str] = {
    "SqlInjection": "CWE-89",
    "CommandInjection": "CWE-78",
    "PathInjection": "CWE-22",
    "Xss": "CWE-79",
    "CrossSiteScripting": "CWE-79",
    "Xxe": "CWE-611",
    "ServerSideRequestForgery": "CWE-918",
    "Ssrf": "CWE-918",
    "HardcodedCredentials": "CWE-798",
    "WeakCrypto": "CWE-327",
    "InsecureDeserialization": "CWE-502",
    "OpenRedirect": "CWE-601",
    "LdapInjection": "CWE-90",
    "XpathInjection": "CWE-643",
    "MissingEncryption": "CWE-311",
    "InsecureCookie": "CWE-614",
    "Csrf": "CWE-352",
    "MissingAuth": "CWE-306",
    "NullDereference": "CWE-476",
    "BufferOverflow": "CWE-120",
    "IntegerOverflow": "CWE-190",
    "UseAfterFree": "CWE-416",
    "RaceCondition": "CWE-362",
    "LogInjection": "CWE-117",
    "HeaderInjection": "CWE-113",
    "TemplateInjection": "CWE-1336",
    "ReDoS": "CWE-1333",
    "UnsafeDeserialization": "CWE-502",
    "BadTagFilter": "CWE-116",
    "MissingRateLimiting": "CWE-770",
    "ClearTextStorage": "CWE-312",
    "WeakRandom": "CWE-330",
}

# SonarQube 规则 ID → CWE 映射（常见安全规则）
_SONARQUBE_CWE_MAP: Dict[str, str] = {
    "S3649": "CWE-89",     # SQL injection
    "S2077": "CWE-89",     # SQL formatting
    "S2076": "CWE-78",     # OS command injection
    "S2078": "CWE-78",     # OS command injection
    "S2083": "CWE-22",     # Path traversal
    "S5131": "CWE-79",     # XSS
    "S5135": "CWE-502",    # Deserialization
    "S2092": "CWE-614",    # Secure flag cookie
    "S2255": "CWE-259",    # Hardcoded password
    "S2068": "CWE-798",    # Hardcoded credentials
    "S2095": "CWE-459",    # Resource not closed
    "S2245": "CWE-330",    # Pseudo-random
    "S2755": "CWE-611",    # XXE
    "S5332": "CWE-918",    # SSRF
    "S5144": "CWE-918",    # SSRF
    "S2087": "CWE-200",    # Information leak
    "S2094": "CWE-200",    # Information leak
    "S2074": "CWE-117",    # Log injection
    "S5122": "CWE-942",    # CORS
    "S4502": "CWE-345",    # JWT
    "S2252": "CWE-601",    # Open redirect
    "S2631": "CWE-1333",   # ReDoS
    "S2079": "CWE-416",    # Use after free
    "S1313": "CWE-200",    # IP address hard-coded
    "S5547": "CWE-327",    # Cipher algorithm
    "S2069": "CWE-352",    # CSRF
    "S2072": "CWE-502",    # Deserialization
    "S2089": "CWE-918",    # SSRF (injection)
    "S2091": "CWE-90",     # LDAP injection
    "S5145": "CWE-208",    # Information exposure
    "S4434": "CWE-295",    # SSL certificate
    "S4790": "CWE-328",    # Hash algorithm
    "S6350": "CWE-20",     # Input validation
}

# Bandit 测试 ID → CWE 映射
_BANDIT_CWE_MAP: Dict[str, str] = {
    "B101": "CWE-705",     # assert used
    "B102": "CWE-78",      # exec usage
    "B103": "CWE-273",     # set_bad_file_permissions
    "B104": "CWE-605",     # hardcoded_bind_all_interfaces
    "B105": "CWE-259",     # hardcoded_password_string
    "B106": "CWE-259",     # hardcoded_password_funcarg
    "B107": "CWE-259",     # hardcoded_password_default
    "B108": "CWE-377",     # hardcoded_tmp_directory
    "B110": "CWE-390",     # try_except_pass
    "B112": "CWE-390",     # try_except_continue
    "B201": "CWE-1336",    # flask_debug_true
    "B301": "CWE-502",     # pickle usage
    "B302": "CWE-502",     # marshal usage
    "B303": "CWE-328",     # MD5 usage
    "B304": "CWE-327",     # insecure cipher
    "B305": "CWE-327",     # insecure cipher mode
    "B306": "CWE-377",     # mktemp_q usage
    "B307": "CWE-78",      # eval usage
    "B308": "CWE-79",      # mark_safe usage
    "B309": "CWE-327",     # HTTPSConnection without TLS
    "B310": "CWE-22",      # urllib_urlopen
    "B311": "CWE-330",     # random usage
    "B312": "CWE-327",     # telnetlib
    "B313": "CWE-611",     # xml_bad_cElementTree
    "B314": "CWE-611",     # xml_bad_ElementTree
    "B315": "CWE-611",     # xml_bad_expatreader
    "B316": "CWE-611",     # xml_bad_expatbuilder
    "B317": "CWE-611",     # xml_bad_sax
    "B318": "CWE-611",     # xml_bad_minidom
    "B319": "CWE-611",     # xml_bad_pulldom
    "B320": "CWE-611",     # xml_bad_etree
    "B321": "CWE-614",     # ftplib
    "B323": "CWE-295",     # unverified context
    "B324": "CWE-328",     # hashlib insecure
    "B325": "CWE-78",      # subprocess
    "B401": "CWE-200",     # import telnetlib
    "B402": "CWE-200",     # import ftplib
    "B403": "CWE-502",     # import pickle
    "B404": "CWE-78",      # import subprocess
    "B405": "CWE-611",     # import xml.etree
    "B406": "CWE-611",     # import xml.sax
    "B407": "CWE-611",     # import expat
    "B408": "CWE-611",     # import minidom
    "B409": "CWE-611",     # import pulldom
    "B410": "CWE-611",     # import etree
    "B411": "CWE-200",     # xmlrpc
    "B412": "CWE-200",     # import twisted.web.xmlrpc
    "B413": "CWE-327",     # import py_CRYPTO
    "B501": "CWE-295",     # request_with_no_cert_validation
    "B502": "CWE-327",     # ssl_with_bad_version
    "B503": "CWE-327",     # ssl_with_bad_defaults
    "B504": "CWE-327",     # ssl_with_no_version
    "B505": "CWE-327",     # weak_cryptographic_key
    "B506": "CWE-502",     # yaml_load
    "B507": "CWE-295",     # ssh_no_host_key_verification
    "B601": "CWE-78",      # paramiko_calls
    "B602": "CWE-78",      # subprocess_shell_true
    "B603": "CWE-78",      # subprocess_without_shell_equals_true
    "B604": "CWE-78",      # any_other_function_with_shell_equals_true
    "B605": "CWE-78",      # start_process_with_a_shell
    "B606": "CWE-78",      # start_process_with_no_shell
    "B607": "CWE-78",      # start_process_with_partial_path
    "B608": "CWE-89",      # hardcoded_sql_expressions
    "B609": "CWE-117",     # logging_config_insecure_listen
    "B610": "CWE-89",      # extra_used
    "B611": "CWE-89",      # RawSQL_used
    "B701": "CWE-79",      # jinja2_autoescape_false
    "B702": "CWE-200",     # use_of_info
    "B703": "CWE-79",      # django_mark_safe
}

# ESLint security 规则 → CWE 映射
_ESLINT_CWE_MAP: Dict[str, str] = {
    "detect-non-literal-regexp": "CWE-1333",
    "detect-non-literal-fs-filename": "CWE-22",
    "detect-disable-mustache-escape": "CWE-116",
    "detect-eval-with-expression": "CWE-95",
    "detect-no-csrf-before-method-override": "CWE-352",
    "detect-buffer-noassert": "CWE-120",
    "detect-child-process": "CWE-78",
    "detect-sql-injection": "CWE-89",
    "detect-no-unsafe-regex": "CWE-1333",
    "detect-possible-timing-attacks": "CWE-208",
    "detect-pseudoRandomBytes": "CWE-330",
    "detect-unsafe-regex": "CWE-1333",
    "no-eval": "CWE-95",
    "no-implied-eval": "CWE-95",
    "no-new-func": "CWE-95",
    "dangerously-set-inner-html": "CWE-79",
    "no-dangerously-set-innerhtml": "CWE-79",
    "no-document-domain": "CWE-79",
    "no-inner-html": "CWE-79",
    "no-literal-jsx-dangerously-set-inner-html": "CWE-79",
}


# ---------------------------------------------------------------------------
# 严重级别标准化映射
# ---------------------------------------------------------------------------

_SARIF_SEVERITY_MAP: Dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

_BANDIT_SEVERITY_MAP: Dict[str, str] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


# ---------------------------------------------------------------------------
# SarifStandardizer 核心类
# ---------------------------------------------------------------------------

class SarifStandardizer:
    """SARIF 输入标准化器。

    参照 ZeroFalse 论文中提出的多 SAST 工具输入归一化方法，本类提供：

    * 将不同 SAST 工具（Semgrep / CodeQL / SonarQube / Bandit / ESLint）
      产生的 SARIF 输出解析为统一数据结构；
    * 将解析结果标准化为 ``NormalizedFinding`` 列表；
    * 跨工具去重（文件路径 + 行号容差 + CWE 映射 + 描述相似度）；
    * 与 HOS-LS 内部发现合并；
    * 将 HOS-LS 发现反向导出为 SARIF 格式。

    Example::

        standardizer = SarifStandardizer()
        runs = standardizer.parse_sarif_file("semgrep-results.sarif")
        findings = standardizer.normalize_results(runs)
    """

    # 行号匹配容差
    LINE_TOLERANCE: int = 3

    # Jaccard 相似度阈值
    JACCARD_THRESHOLD: float = 0.5

    def __init__(self) -> None:
        self._cwe_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # 1. SARIF 解析
    # ------------------------------------------------------------------

    def parse_sarif_file(self, file_path: str) -> List[SarifRun]:
        """解析 SARIF JSON 文件。

        Args:
            file_path: SARIF 文件的绝对或相对路径。

        Returns:
            解析后的 SarifRun 列表。

        Raises:
            FileNotFoundError: 文件不存在。
            json.JSONDecodeError: 文件内容不是合法 JSON。
        """
        path = Path(file_path)
        if not path.exists():
            logger.error("SARIF 文件不存在: %s", file_path)
            raise FileNotFoundError(f"SARIF 文件不存在: {file_path}")

        logger.info("正在解析 SARIF 文件: %s", file_path)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        return self.parse_sarif_dict(data)

    def parse_sarif_dict(self, data: Dict[str, Any]) -> List[SarifRun]:
        """从字典解析 SARIF 数据。

        兼容 SARIF v2.1.0（``$schema`` 中包含 ``2.1.0``）以及
        早期 v2.0.0 格式。

        Args:
            data: 已反序列化的 SARIF 字典。

        Returns:
            SarifRun 列表。
        """
        runs_data = data.get("runs", [])
        if not runs_data:
            logger.warning("SARIF 数据中未找到 runs 字段")
            return []

        parsed_runs: List[SarifRun] = []

        for run_data in runs_data:
            # 工具信息
            tool_info = run_data.get("tool", {})
            driver = tool_info.get("driver", {})
            tool_name = driver.get("name", "unknown")
            tool_version = driver.get("version", driver.get("semanticVersion", ""))

            # 提取规则定义 → 构建 规则ID→严重级别 映射
            rules_data = driver.get("rules", [])
            rule_severity_map: Dict[str, str] = {}
            for rule in rules_data:
                rid = rule.get("id", "")
                props = rule.get("properties", {})
                # SARIF 规范中 defaultConfiguration.level 表示默认严重级别
                default_cfg = rule.get("defaultConfiguration", {})
                level = default_cfg.get("level", "")
                if not level:
                    level = props.get("security-severity", "")
                    # security-severity 是数值（0-10），需要转换
                    if level:
                        try:
                            score = float(level)
                            if score >= 9.0:
                                level = "error"
                            elif score >= 7.0:
                                level = "error"
                            elif score >= 4.0:
                                level = "warning"
                            else:
                                level = "note"
                        except (ValueError, TypeError):
                            level = "warning"
                if rid:
                    rule_severity_map[rid] = level

            # 解析结果
            results_data = run_data.get("results", [])
            parsed_results: List[SarifResult] = []
            for result_data in results_data:
                parsed_results.append(
                    SarifResult.from_sarif(result_data, rule_severity_map)
                )

            # 解析 artifacts
            artifacts_data = run_data.get("artifacts", [])

            sarif_run = SarifRun(
                tool_name=tool_name,
                tool_version=tool_version,
                results=parsed_results,
                artifacts=artifacts_data,
                rules=rules_data,
            )
            parsed_runs.append(sarif_run)

            logger.info(
                "解析工具 [%s] v%s: %d 条结果, %d 条规则",
                tool_name,
                tool_version,
                len(parsed_results),
                len(rules_data),
            )

        return parsed_runs

    # ------------------------------------------------------------------
    # 2. 标准化
    # ------------------------------------------------------------------

    def normalize_results(self, runs: List[SarifRun]) -> List[NormalizedFinding]:
        """将 SARIF 结果转换为统一的 NormalizedFinding 格式。

        处理流程：
          1. 遍历每个 run 中的每条 result；
          2. 提取首个有效位置；
          3. 将工具特有 rule_id 映射到 CWE；
          4. 标准化严重级别；
          5. 构造 NormalizedFinding。

        Args:
            runs: 已解析的 SarifRun 列表。

        Returns:
            标准化后的 NormalizedFinding 列表。
        """
        findings: List[NormalizedFinding] = []

        for run in runs:
            tool_name = run.tool_name.lower()

            for result in run.results:
                # 取第一个有效位置
                primary_loc = SarifLocation()
                if result.locations:
                    primary_loc = result.locations[0]

                # 映射 CWE
                cwe_id = self._map_rule_to_cwe(result.rule_id, tool_name)

                # 标准化严重级别
                severity = self._normalize_severity(result.severity, tool_name)

                # 置信度（如果 SARIF 中有 confidence 属性则使用）
                confidence = result.properties.get("confidence", 1.0)
                if isinstance(confidence, str):
                    confidence = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}.get(
                        confidence.upper(), 0.7
                    )

                finding = NormalizedFinding(
                    rule_id=result.rule_id,
                    message=result.message,
                    file_path=primary_loc.file_path,
                    start_line=primary_loc.start_line,
                    end_line=primary_loc.end_line,
                    start_column=primary_loc.start_column,
                    end_column=primary_loc.end_column,
                    severity=severity,
                    cwe_id=cwe_id,
                    tool_name=run.tool_name,
                    confidence=float(confidence),
                    source_tool_rule=result.rule_id,
                    properties=result.properties,
                )
                findings.append(finding)

        logger.info(
            "标准化完成: %d 个 run → %d 条 NormalizedFinding",
            len(runs),
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # 3. 跨工具去重 & 合并
    # ------------------------------------------------------------------

    def merge_with_internal_findings(
        self,
        sarif_findings: List[NormalizedFinding],
        internal_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """将 SARIF 发现与 HOS-LS 内部发现合并，按位置+类型去重。

        去重策略（参照 ZeroFalse 论文）：
          1. 文件路径标准化后完全匹配；
          2. 行号容差 ±3 行；
          3. CWE 或规则类型匹配；
          4. 描述 Jaccard 相似度 > 0.5。

        当 SARIF 发现与内部发现匹配时，保留内部发现（因为内部发现通常
        包含更丰富的上下文），但将 SARIF 工具信息附加到 metadata 中。

        Args:
            sarif_findings: 标准化后的 SARIF 发现列表。
            internal_findings: HOS-LS 内部发现列表（``AnalysisIssue.to_dict()``
                格式）。

        Returns:
            合并后的发现列表（字典格式）。
        """
        # 将内部发现转换为可比较的元组集合
        merged: List[Dict[str, Any]] = list(internal_findings)
        matched_internal_indices: Set[int] = set()

        for sf in sarif_findings:
            is_duplicate = False

            for idx, internal in enumerate(internal_findings):
                if not self._findings_match(sf, internal):
                    continue

                is_duplicate = True
                matched_internal_indices.add(idx)

                # 将外部工具信息追加到 metadata
                metadata = internal.get("metadata", {})
                external_tools = metadata.get("external_tools", [])
                tool_entry = {
                    "tool": sf.tool_name,
                    "rule_id": sf.rule_id,
                    "cwe_id": sf.cwe_id,
                }
                # 避免重复添加
                if tool_entry not in external_tools:
                    external_tools.append(tool_entry)
                metadata["external_tools"] = external_tools

                # 如果 SARIF 提供了更高的置信度，更新
                existing_confidence = internal.get("confidence", 1.0)
                if sf.confidence > existing_confidence:
                    internal["confidence"] = sf.confidence

                internal["metadata"] = metadata

            if not is_duplicate:
                # 作为新发现加入
                merged.append(sf.to_analysis_issue_dict())

        logger.info(
            "合并完成: %d 条 SARIF + %d 条内部 → %d 条（去重后）",
            len(sarif_findings),
            len(internal_findings),
            len(merged),
        )
        return merged

    # ------------------------------------------------------------------
    # 4. 导出为 SARIF
    # ------------------------------------------------------------------

    def export_to_sarif(
        self,
        internal_findings: List[Dict[str, Any]],
        tool_name: str = "HOS-LS",
    ) -> Dict[str, Any]:
        """将 HOS-LS 内部发现导出为 SARIF v2.1.0 格式。

        Args:
            internal_findings: HOS-LS 内部发现列表（``AnalysisIssue.to_dict()``
                格式）。
            tool_name: 导出时使用的工具名称，默认 ``HOS-LS``。

        Returns:
            符合 SARIF v2.1.0 规范的字典。
        """
        # 收集唯一规则
        rules_map: Dict[str, Dict[str, Any]] = {}
        sarif_results: List[Dict[str, Any]] = []

        for finding in internal_findings:
            rule_id = finding.get("rule_id", "unknown")
            cwe_id = finding.get("cwe_id", "")
            severity = finding.get("severity", "warning")

            # 构建规则定义
            if rule_id not in rules_map:
                rule_def: Dict[str, Any] = {
                    "id": rule_id,
                    "shortDescription": {"text": finding.get("message", "")},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(severity),
                    },
                    "properties": {},
                }
                if cwe_id:
                    rule_def["properties"]["cwe_id"] = cwe_id
                    # 添加 tags
                    rule_def["properties"]["tags"] = [cwe_id]
                rules_map[rule_id] = rule_def

            # 构建结果
            file_path = finding.get("metadata", {}).get("file_path", "")
            if not file_path:
                # 尝试从 properties 中获取
                file_path = finding.get("properties", {}).get("file_path", "")

            line = finding.get("line", 0)
            column = finding.get("column", 0)
            end_line = finding.get("end_line", line)
            end_column = finding.get("end_column", column)

            location: Dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {
                        "startLine": line,
                        "startColumn": column,
                        "endLine": end_line,
                        "endColumn": end_column,
                    },
                }
            }

            result_entry: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(severity),
                "message": {"text": finding.get("message", "")},
                "locations": [location],
            }

            # 添加 fingerprints
            fingerprints: Dict[str, str] = {}
            if file_path and line:
                fingerprints["hosls/v1"] = f"{file_path}:{line}:{rule_id}"
            if fingerprints:
                result_entry["fingerprints"] = fingerprints

            sarif_results.append(result_entry)

        sarif_doc: Dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": "1.0.0",
                            "informationUri": "https://github.com/hos-ls",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        logger.info(
            "导出 SARIF: %d 条发现, %d 条规则定义",
            len(sarif_results),
            len(rules_map),
        )
        return sarif_doc

    # ------------------------------------------------------------------
    # 内部辅助方法
    # ------------------------------------------------------------------

    def _map_rule_to_cwe(self, rule_id: str, tool_name: str) -> str:
        """将工具特有规则 ID 映射到 CWE 编号。

        映射策略因工具而异：
          - **Semgrep**: 从 rule_id 中提取关键词（如 ``sql-injection``），
            在 ``_SEMGREP_CWE_MAP`` 中查找。
          - **CodeQL**: 从查询路径中提取类名（如 ``SqlInjection``），
            在 ``_CODEQL_CWE_MAP`` 中查找。
          - **SonarQube**: 直接匹配规则编号（如 ``S3649``），
            在 ``_SONARQUBE_CWE_MAP`` 中查找。
          - **Bandit**: 匹配测试 ID（如 ``B608``），
            在 ``_BANDIT_CWE_MAP`` 中查找。
          - **ESLint**: 匹配规则名，在 ``_ESLINT_CWE_MAP`` 中查找。

        Args:
            rule_id: 工具原始规则标识符。
            tool_name: 工具名称（小写）。

        Returns:
            CWE 编号字符串（如 ``CWE-89``），未找到时返回空字符串。
        """
        cache_key = f"{tool_name}:{rule_id}"
        if cache_key in self._cwe_cache:
            return self._cwe_cache[cache_key]

        cwe = ""

        if "semgrep" in tool_name:
            cwe = self._map_semgrep_cwe(rule_id)
        elif "codeql" in tool_name:
            cwe = self._map_codeql_cwe(rule_id)
        elif "sonar" in tool_name:
            cwe = self._map_sonarqube_cwe(rule_id)
        elif "bandit" in tool_name:
            cwe = self._map_bandit_cwe(rule_id)
        elif "eslint" in tool_name:
            cwe = self._map_eslint_cwe(rule_id)
        else:
            # 通用策略：尝试所有映射表
            cwe = (
                self._map_semgrep_cwe(rule_id)
                or self._map_codeql_cwe(rule_id)
                or self._map_sonarqube_cwe(rule_id)
                or self._map_bandit_cwe(rule_id)
                or self._map_eslint_cwe(rule_id)
            )

        self._cwe_cache[cache_key] = cwe
        return cwe

    def _map_semgrep_cwe(self, rule_id: str) -> str:
        """Semgrep 规则 → CWE。

        Semgrep 规则 ID 通常形如 ``java.sql-injection`` 或
        ``python.django.security.injection.sql.sql-injection``。
        提取各层级片段进行匹配。
        """
        parts = rule_id.lower().split(".")
        # 从最具体的片段开始尝试
        for i in range(len(parts) - 1, -1, -1):
            segment = parts[i]
            if segment in _SEMGREP_CWE_MAP:
                return _SEMGREP_CWE_MAP[segment]
        # 尝试子串匹配
        rule_lower = rule_id.lower()
        for key, cwe in _SEMGREP_CWE_MAP.items():
            if key in rule_lower:
                return cwe
        return ""

    def _map_codeql_cwe(self, rule_id: str) -> str:
        """CodeQL 规则 → CWE。

        CodeQL 查询 ID 通常形如 ``java/SqlInjection`` 或
        ``java/sql-injection``。提取路径末尾的查询名进行匹配。
        """
        # 提取最后一段
        parts = rule_id.replace("\\", "/").split("/")
        query_name = parts[-1] if parts else rule_id

        # 直接匹配
        if query_name in _CODEQL_CWE_MAP:
            return _CODEQL_CWE_MAP[query_name]

        # 大小写不敏感匹配
        query_lower = query_name.lower()
        for key, cwe in _CODEQL_CWE_MAP.items():
            if key.lower() == query_lower:
                return cwe

        # 子串匹配
        for key, cwe in _CODEQL_CWE_MAP.items():
            if key.lower() in query_lower or query_lower in key.lower():
                return cwe

        return ""

    def _map_sonarqube_cwe(self, rule_id: str) -> str:
        """SonarQube 规则 → CWE。

        SonarQube 规则 ID 通常形如 ``java:S3649``。提取 ``S`` 编号进行匹配。
        """
        # 提取 S 编号
        match = re.search(r"S(\d+)", rule_id, re.IGNORECASE)
        if match:
            s_key = f"S{match.group(1)}"
            if s_key in _SONARQUBE_CWE_MAP:
                return _SONARQUBE_CWE_MAP[s_key]

        # 直接匹配完整 rule_id
        if rule_id in _SONARQUBE_CWE_MAP:
            return _SONARQUBE_CWE_MAP[rule_id]

        return ""

    def _map_bandit_cwe(self, rule_id: str) -> str:
        """Bandit 规则 → CWE。

        Bandit 测试 ID 形如 ``B608``。
        """
        # 提取 B 编号
        match = re.search(r"B(\d+)", rule_id, re.IGNORECASE)
        if match:
            b_key = f"B{match.group(1)}"
            if b_key in _BANDIT_CWE_MAP:
                return _BANDIT_CWE_MAP[b_key]

        return ""

    def _map_eslint_cwe(self, rule_id: str) -> str:
        """ESLint 安全规则 → CWE。"""
        if rule_id in _ESLINT_CWE_MAP:
            return _ESLINT_CWE_MAP[rule_id]

        # 去除插件前缀后匹配
        parts = rule_id.split("/")
        short_name = parts[-1] if parts else rule_id
        if short_name in _ESLINT_CWE_MAP:
            return _ESLINT_CWE_MAP[short_name]

        return ""

    def _normalize_severity(self, sarif_level: str, tool_name: str) -> str:
        """将 SARIF 严重级别标准化为 HOS-LS 内部级别。

        Args:
            sarif_level: SARIF 原始严重级别字符串。
            tool_name: 工具名称（小写），用于工具特有映射。

        Returns:
            标准化后的严重级别：critical / high / medium / low / info。
        """
        level_lower = sarif_level.lower().strip()

        # Bandit 使用大写 HIGH / MEDIUM / LOW
        if "bandit" in tool_name:
            mapped = _BANDIT_SEVERITY_MAP.get(sarif_level.upper(), "")
            if mapped:
                return mapped

        # SARIF 标准级别
        if level_lower in _SARIF_SEVERITY_MAP:
            return _SARIF_SEVERITY_MAP[level_lower]

        # 尝试数值映射（SonarQube security-severity）
        try:
            score = float(sarif_level)
            if score >= 9.0:
                return "critical"
            elif score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            elif score > 0:
                return "low"
            else:
                return "info"
        except (ValueError, TypeError):
            pass

        # 直接匹配 HOS-LS 级别
        valid_levels = {"critical", "high", "medium", "low", "info"}
        if level_lower in valid_levels:
            return level_lower

        return "medium"

    def _severity_to_sarif_level(self, severity: str) -> str:
        """将 HOS-LS 严重级别转换为 SARIF level。"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }
        return mapping.get(severity.lower(), "warning")

    def _findings_match(
        self,
        sarif_finding: NormalizedFinding,
        internal_finding: Dict[str, Any],
    ) -> bool:
        """判断 SARIF 发现与内部发现是否为同一问题（去重匹配）。

        匹配条件（全部满足时视为重复）：
          1. 文件路径标准化后一致；
          2. 行号差在容差范围内（±3 行）；
          3. CWE 匹配 **或** 规则类型匹配 **或** 描述 Jaccard > 0.5。

        Args:
            sarif_finding: 标准化后的 SARIF 发现。
            internal_finding: HOS-LS 内部发现字典。

        Returns:
            是否匹配（重复）。
        """
        # 1. 文件路径匹配
        sf_path = self._normalize_path(sarif_finding.file_path)
        int_meta = internal_finding.get("metadata", {})
        int_path = self._normalize_path(
            int_meta.get("file_path", internal_finding.get("file_path", ""))
        )

        if sf_path and int_path and sf_path != int_path:
            # 尝试包含匹配（处理相对/绝对路径差异）
            if not (sf_path.endswith(int_path) or int_path.endswith(sf_path)):
                return False

        # 2. 行号容差
        sf_line = sarif_finding.start_line
        int_line = internal_finding.get("line", 0)

        if sf_line > 0 and int_line > 0:
            if abs(sf_line - int_line) > self.LINE_TOLERANCE:
                return False
        elif sf_line > 0 or int_line > 0:
            # 一方有行号一方没有，不视为匹配
            return False

        # 3. CWE / 规则类型 / 描述相似度（满足其一即可）
        # 3a. CWE 匹配
        sf_cwe = sarif_finding.cwe_id
        int_cwe = internal_finding.get("cwe_id", "")
        if sf_cwe and int_cwe and sf_cwe == int_cwe:
            return True

        # 3b. 规则 ID 匹配
        sf_rule = sarif_finding.rule_id.lower()
        int_rule = internal_finding.get("rule_id", "").lower()
        if sf_rule and int_rule and sf_rule == int_rule:
            return True

        # 3c. 描述 Jaccard 相似度
        sf_msg = sarif_finding.message
        int_msg = internal_finding.get("message", "")
        if sf_msg and int_msg:
            jaccard = self._jaccard_similarity(sf_msg, int_msg)
            if jaccard > self.JACCARD_THRESHOLD:
                return True

        return False

    @staticmethod
    def _normalize_path(path: str) -> str:
        """标准化文件路径。

        处理：
          - 反斜杠转正斜杠
          - 去除前导 ``./``
          - 统一小写（用于比较）
          - 尝试提取相对路径（去除常见项目根前缀）

        Args:
            path: 原始文件路径。

        Returns:
            标准化后的路径字符串。
        """
        if not path:
            return ""

        normalized = path.replace("\\", "/")

        # 去除前导 ./
        while normalized.startswith("./"):
            normalized = normalized[2:]

        # 尝试提取项目内的相对路径
        # 查找常见源码目录标记
        src_markers = ["/src/", "/lib/", "/app/", "/source/", "/code/"]
        for marker in src_markers:
            idx = normalized.lower().find(marker)
            if idx >= 0:
                normalized = normalized[idx + 1:]
                break

        return normalized.lower().rstrip("/")

    @staticmethod
    def _jaccard_similarity(text_a: str, text_b: str) -> float:
        """计算两段文本的 Jaccard 相似度。

        以词（whitespace 分割后的 token）为基本单位。

        Args:
            text_a: 文本 A。
            text_b: 文本 B。

        Returns:
            Jaccard 相似度（0.0 ~ 1.0）。
        """
        if not text_a or not text_b:
            return 0.0

        tokens_a = set(text_a.lower().split())
        tokens_b = set(text_b.lower().split())

        if not tokens_a or not tokens_b:
            return 0.0

        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b

        return len(intersection) / len(union) if union else 0.0


# ---------------------------------------------------------------------------
# 便捷函数
# ---------------------------------------------------------------------------

def standardize_sarif_file(file_path: str) -> List[NormalizedFinding]:
    """快捷函数：解析 SARIF 文件并直接返回标准化发现列表。

    Args:
        file_path: SARIF 文件路径。

    Returns:
        NormalizedFinding 列表。
    """
    standardizer = SarifStandardizer()
    runs = standardizer.parse_sarif_file(file_path)
    return standardizer.normalize_results(runs)


def merge_sarif_files(
    file_paths: List[str],
    deduplicate: bool = True,
) -> List[NormalizedFinding]:
    """合并多个 SARIF 文件的发现结果。

    Args:
        file_paths: SARIF 文件路径列表。
        deduplicate: 是否执行跨工具去重，默认 True。

    Returns:
        合并（可选去重）后的 NormalizedFinding 列表。
    """
    standardizer = SarifStandardizer()
    all_findings: List[NormalizedFinding] = []

    for fp in file_paths:
        try:
            runs = standardizer.parse_sarif_file(fp)
            findings = standardizer.normalize_results(runs)
            all_findings.extend(findings)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.warning("跳过无法解析的文件 %s: %s", fp, exc)

    if not deduplicate:
        return all_findings

    # 基于位置 + CWE 去重
    unique: List[NormalizedFinding] = []
    seen_keys: Set[Tuple[str, int, str]] = set()

    for finding in all_findings:
        norm_path = SarifStandardizer._normalize_path(finding.file_path)
        # 以 (文件路径, 行号, CWE) 作为去重键
        key = (norm_path, finding.start_line, finding.cwe_id)

        # 如果 CWE 为空，放宽到 (文件路径, 行号, 规则ID)
        if not finding.cwe_id:
            key = (norm_path, finding.start_line, finding.rule_id)

        if key in seen_keys:
            continue

        # 额外检查行号容差范围内的近似匹配
        is_near_duplicate = False
        for existing in unique:
            existing_path = SarifStandardizer._normalize_path(existing.file_path)
            if existing_path != norm_path:
                continue
            if abs(existing.start_line - finding.start_line) > SarifStandardizer.LINE_TOLERANCE:
                continue
            # CWE 匹配
            if finding.cwe_id and existing.cwe_id and finding.cwe_id == existing.cwe_id:
                is_near_duplicate = True
                break
            # 描述相似度
            if finding.message and existing.message:
                jaccard = SarifStandardizer._jaccard_similarity(
                    finding.message, existing.message
                )
                if jaccard > SarifStandardizer.JACCARD_THRESHOLD:
                    is_near_duplicate = True
                    break

        if not is_near_duplicate:
            unique.append(finding)
            seen_keys.add(key)

    logger.info(
        "多文件合并去重: %d 条原始 → %d 条唯一",
        len(all_findings),
        len(unique),
    )
    return unique
