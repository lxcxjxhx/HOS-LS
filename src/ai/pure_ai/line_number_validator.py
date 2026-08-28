"""LineNumber验证器

验证和校正AI报告的行号，确保漏洞位置准确。
"""

import os
import re
from typing import Any, Dict, List, Optional, Tuple

import yaml

from src.ai.pure_ai.line_number_mapper import LineNumberMapper
from src.ai.pure_ai.schema import LineMatchStatus, SignalState
from src.utils.logger import get_logger

logger = get_logger(__name__)

class LineNumberValidator:
    """LineNumber验证器

    验证和校正AI报告的行号，确保漏洞位置准确。
    """

    DEFAULT_CONFIG_PATH = "hos-ls.yaml"

    def __init__(self, tolerance: Optional[int] = None):
        self.tolerance = self._load_tolerance(tolerance)
        self.mapper = LineNumberMapper()

    def _load_tolerance(self, tolerance: Optional[int] = None) -> int:
        """从配置文件加载tolerance值

        Args:
            tolerance: 直接传入的tolerance值，如果不为None则优先使用

        Returns:
            tolerance值
        """
        if tolerance is not None:
            return tolerance

        try:
            config_path = self.DEFAULT_CONFIG_PATH
            if not os.path.exists(config_path):
                project_root = os.path.dirname(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                )
                config_path = os.path.join(project_root, "hos-ls.yaml")

            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                    validation_config = config.get("validation", {})
                    tolerance_value = validation_config.get("line_number_tolerance", None)
                    if tolerance_value is not None and tolerance_value > 0:
                        return int(tolerance_value)
        except Exception:
            pass

        return 10

    def validate_location(self, vulnerability: dict, file_content: str) -> dict:
        """验证并校正行号

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容

        Returns:
            扩展后的漏洞数据
        """
        result = dict(vulnerability)

        location = vulnerability.get("location", "")
        evidence = vulnerability.get("evidence", [])
        # code_snippet = ""
        for ev in evidence:
            if isinstance(ev, dict) and ev.get("code_snippet"):
                # code_snippet = ev["code_snippet"]
                break

        ai_reported_line = -1
        _, parsed_line = self.mapper.parse_location(location)
        if parsed_line is not None:
            ai_reported_line = parsed_line

        result["ai_reported_line"] = ai_reported_line

        if not file_content:
            result["verified_line"] = -1
            result["line_match_status"] = LineMatchStatus.UNVERIFIED.value
            result["candidate_lines"] = []
            return result

        actual_line, match_status, candidates = self.find_actual_line(vulnerability, file_content)
        result["verified_line"] = actual_line
        result["candidate_lines"] = candidates

        if actual_line == -1:
            result["line_match_status"] = LineMatchStatus.UNVERIFIED.value
            return result

        if match_status == "EXACT":
            deviation = self.mapper.calculate_line_deviation(ai_reported_line, actual_line)
            if self.mapper.is_within_tolerance(deviation, self.tolerance):
                result["line_match_status"] = LineMatchStatus.EXACT.value
            else:
                if self.tolerance == 0:
                    result["line_match_status"] = LineMatchStatus.UNVERIFIED.value
                else:
                    result["line_match_status"] = LineMatchStatus.ADJUSTED.value
        elif match_status == "FUZZY":
            deviation = self.mapper.calculate_line_deviation(ai_reported_line, actual_line)
            if self.tolerance == 0:
                result["line_match_status"] = LineMatchStatus.UNVERIFIED.value
            else:
                result["line_match_status"] = LineMatchStatus.ADJUSTED.value
        elif match_status == "ADJUSTED":
            result["line_match_status"] = LineMatchStatus.ADJUSTED.value
        elif match_status == "REPORTED":
            result["line_match_status"] = LineMatchStatus.EXACT.value
        else:
            result["line_match_status"] = LineMatchStatus.UNVERIFIED.value

        return result

    def find_actual_line(self, vulnerability: dict, file_content: str) -> tuple[int, str, list]:
        """查找实际匹配行

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容

        Returns:
            (实际行号, 匹配状态, 候选行列表)
            匹配状态: "EXACT", "ADJUSTED", "FUZZY", "NOT_FOUND"
        """
        rule_name = vulnerability.get("rule_name", "unknown")
        logger.debug("\n ====== find_actual_line START ======")
        logger.debug(f" Rule: {rule_name}")

        if file_content:
            original_line_count = len(file_content.split("\n"))
            file_content = self._normalize_line_endings(file_content)
            normalized_line_count = len(file_content.split("\n"))
            if original_line_count != normalized_line_count:
                logger.debug(
                    f"Line ending normalization: {original_line_count} -> {normalized_line_count} lines"
                )
        evidence = vulnerability.get("evidence", [])
        code_snippet = ""
        ai_reported_line = None

        for ev in evidence:
            if isinstance(ev, dict) and ev.get("code_snippet"):
                code_snippet = ev["code_snippet"]
                break

        location = vulnerability.get("location", "")
        raw_line_str = ""
        if location:
            parts = str(location).split(":")
            if len(parts) >= 2:
                raw_line_str = parts[-1]
                try:
                    if "-" in raw_line_str:
                        ai_reported_line = int(raw_line_str.split("-")[0])
                        logger.debug(
                            f"Range line number detected: {raw_line_str} -> using start: {ai_reported_line}"
                        )
                    else:
                        ai_reported_line = int(raw_line_str)
                except ValueError:
                    pass

        logger.debug(f" AI reported line: {ai_reported_line}")
        logger.debug(f" code_snippet length: {len(code_snippet) if code_snippet else 0}")

        if ai_reported_line and file_content:
            lines = file_content.split("\n")
            if 1 <= ai_reported_line <= len(lines):
                reported_content = lines[ai_reported_line - 1]
                description = vulnerability.get("description", "")
                extracted_identifiers = self._extract_identifiers_from_description(description)

                if code_snippet:
                    ai_line_has_snippet = self._code_snippet_matches_line(
                        code_snippet, reported_content
                    )
                    is_valid_ai_line, reason = self._is_valid_ai_reported_line(
                        reported_content, ai_reported_line, file_content
                    )
                    if ai_line_has_snippet and is_valid_ai_line:
                        logger.debug(
                            f"AI reported line {ai_reported_line} contains code snippet and is valid, using it directly"
                        )
                        return ai_reported_line, "REPORTED", []
                    elif is_valid_ai_line:
                        logger.debug(
                            f"AI reported line {ai_reported_line} is valid code (line content verified)"
                        )
                        if extracted_identifiers:
                            logger.debug(
                                f"Extracted identifiers from description: {extracted_identifiers}"
                            )
                            line_lower = reported_content.lower()
                            matched = any(ident in line_lower for ident in extracted_identifiers)
                            if matched:
                                logger.debug(
                                    "Semantic validation passed: line contains identifier from description"
                                )
                                return ai_reported_line, "REPORTED", []
                        logger.debug(f" Using AI reported line directly: {ai_reported_line}")
                        return ai_reported_line, "REPORTED", []
                    else:
                        logger.debug(f" AI reported line rejected: {reason}, trying fuzzy match...")

                is_valid, reason = self._is_valid_ai_reported_line(
                    reported_content, ai_reported_line, file_content
                )
                if is_valid:
                    logger.debug(
                        f"Using AI reported line directly (has valid code): {ai_reported_line}"
                    )
                    logger.debug(f" Content: {reported_content[:60]}...")

                    if extracted_identifiers:
                        logger.debug(
                            f"Extracted identifiers from description: {extracted_identifiers}"
                        )
                        line_lower = reported_content.lower()
                        matched = any(ident in line_lower for ident in extracted_identifiers)
                        if matched:
                            logger.debug(
                                "Semantic validation passed: line contains identifier from description"
                            )
                            return ai_reported_line, "REPORTED", []
                        else:
                            logger.error(
                                "Semantic validation FAILED: line does not contain identifier from description"
                            )
                            logger.debug(
                                "Triggering keyword-based fuzzy match to find actual line..."
                            )
                            candidates = self._find_lines_by_keywords(
                                [], file_content, ai_reported_line, extracted_identifiers
                            )
                            if candidates:
                                logger.debug(f" Keyword match found: line {candidates}")
                                return candidates[0], "FUZZY", candidates
                            logger.warning(" Keyword match failed, falling back to AI reported line")
                            return ai_reported_line, "FUZZY", []
                    else:
                        return ai_reported_line, "REPORTED", []
                else:
                    logger.debug(
                        f"AI reported line rejected: {reason}, line {ai_reported_line}: {reported_content[:40]}..."
                    )
                    fallback_matched = False
                    if extracted_identifiers and file_content:
                        logger.debug(" Trying identifier-based matching after rejection...")
                        candidates = self._find_lines_by_keywords(
                            [], file_content, ai_reported_line, extracted_identifiers
                        )
                        if candidates:
                            logger.debug(
                                f"Fallback identifier matched: line {candidates}, candidates {candidates}"
                            )
                            return candidates[0], "FUZZY", candidates
                        else:
                            fallback_matched = True
                            logger.debug(" Fallback identifier matching returned no candidates")

                    if fallback_matched or not extracted_identifiers:
                        logger.debug(
                            "No valid match found after AI line rejected, continuing to keyword search..."
                        )
        if self._is_configuration_vulnerability(vulnerability):
            logger.debug(
                "Configuration vulnerability detected, trying joint keyword verification..."
            )
            joint_candidates = self._find_lines_by_joint_keywords(
                vulnerability, file_content, ai_reported_line
            )
            if joint_candidates:
                logger.debug(
                    f"Joint verification matched: line {joint_candidates}, candidates {joint_candidates}"
                )
                logger.debug(" ====== find_actual_line END ======\n")
                return joint_candidates[0], "FUZZY", joint_candidates

        description = vulnerability.get("description", "")
        extracted_identifiers = self._extract_identifiers_from_description(description)
        if extracted_identifiers:
            logger.debug(f" Extracted identifiers from description: {extracted_identifiers}")

        keywords = self._extract_keywords(vulnerability)
        logger.debug(f" Keywords extracted: {len(keywords)}")

        security_keywords = self._extract_security_api_keywords(vulnerability, description)
        if security_keywords:
            logger.debug(f" Security API keywords added: {security_keywords}")
            keywords = list(set(keywords + security_keywords))

        if keywords and file_content:
            logger.debug(" Trying keyword fuzzy match...")
            candidates = self._find_lines_by_keywords(
                keywords, file_content, ai_reported_line, extracted_identifiers
            )
            if candidates:
                logger.debug(f" Keyword matched: line {candidates}, candidates {candidates}")
                logger.debug(" ====== find_actual_line END ======\n")
                return candidates[0], "FUZZY", candidates

        if not keywords and extracted_identifiers and file_content:
            logger.debug(" No keywords but identifiers found, trying identifier-only match...")
            candidates = self._find_lines_by_keywords(
                [], file_content, ai_reported_line, extracted_identifiers
            )
            if candidates:
                logger.debug(
                    f"Identifier-only matched: line {candidates}, candidates {candidates}"
                )
                logger.debug(" ====== find_actual_line END ======\n")
                return candidates[0], "FUZZY", candidates

        logger.debug(" No match found, returning NOT_FOUND")
        logger.debug(" Keywords or file_content empty, cannot use AI reported line directly")
        logger.debug(" ====== find_actual_line END ======\n")
        return -1, "NOT_FOUND", []

    def _extract_keywords(self, vulnerability: dict) -> list:
        """从漏洞数据中提取英文关键词

        只提取英文代码标识符，不包含中文。
        """
        keywords = []

        rule_name = vulnerability.get("rule_name", "")
        if rule_name:
            words = rule_name.split()
            for w in words:
                w_lower = w.lower()
                if w_lower in [
                    "jsoup",
                    "shiro",
                    "struts",
                    "spring",
                    "log4j",
                    "jackson",
                    "fastjson",
                    "commons",
                    "hibernate",
                ]:
                    keywords.append(w_lower)
                elif len(w) > 3 and not self._contains_chinese(w):
                    keywords.append(w_lower)
                    camel_parts = self._split_camel_case(w)
                    keywords.extend([p for p in camel_parts if not self._contains_chinese(p)])

        description = vulnerability.get("description", "")
        if description:
            version_pattern = r"(\d+\.\d+\.\d+[a-zA-Z]*)"
            versions = re.findall(version_pattern, description)
            keywords.extend([v.lower() for v in versions])

            important_patterns = [
                r"([a-zA-Z]+(?:[-_]?[a-zA-Z]+){1,3})\s*version\s*(\d+\.\d+\.\d+)",
                r"version\s*(\d+\.\d+\.\d+)",
                r"@(\w+)",
            ]
            for pattern in important_patterns:
                matches = re.findall(pattern, description.lower())
                for m in matches:
                    if isinstance(m, tuple):
                        keywords.extend([x for x in m if x and not self._contains_chinese(x)])
                    else:
                        if not self._contains_chinese(m):
                            keywords.append(m)

            annotation_pattern = r"@(\w+)"
            annotations = re.findall(annotation_pattern, description)
            for ann in annotations:
                if not self._contains_chinese(ann):
                    keywords.append(f"@{ann.lower()}")
                    if len(ann) > 3:
                        keywords.append(ann.lower())

        vulnerability_type = vulnerability.get("vulnerability_type", vulnerability.get("type", ""))
        if vulnerability_type:
            type_keywords = self._extract_type_keywords(vulnerability_type)
            keywords.extend([k for k in type_keywords if not self._contains_chinese(k)])

        location = vulnerability.get("location", "")
        if location and not self._contains_chinese(location):
            location_keywords = re.findall(r"([a-zA-Z_][a-zA-Z0-9_]{2,})", location)
            common_path_components = {
                "main",
                "src",
                "java",
                "cloud",
                "bizspring",
                "project",
                "component",
                "open",
                "real",
                "base",
                "security",
                "hos",
                "common",
                "config",
                "module",
                "business",
                "gateway",
                "auth",
                "aaa_project",
                "configuration",
                "properties",
                "application",
                "resources",
                "static",
                "test",
                "target",
                "build",
                "lib",
                "webapp",
                "file",
                "path",
                "location",
                "line",
                "root",
                "home",
                "users",
                "home",
                "documents",
                "desktop",
                "downloads",
                "windows",
                "system32",
                "program",
                "files",
                "appdata",
                "github",
                "gitlab",
                "gitee",
                "repository",
                "repo",
                "node_modules",
                "package",
                "modules",
                "dist",
                "coverage",
            }
            filtered_keywords = [
                k.lower()
                for k in location_keywords
                if k.lower() not in ["null", "none", "undefined"]
                and k.lower() not in common_path_components
                and len(k) > 3
            ]
            keywords.extend(filtered_keywords)

        keywords = list(set(keywords))
        keywords = [k for k in keywords if k and len(k) > 1 and not self._contains_chinese(k)]

        if not keywords:
            logger.debug(
                "Keywords still empty after extraction, using identifiers as fallback keywords"
            )
            identifiers = self._extract_identifiers_from_description(
                vulnerability.get("description", "")
            )
            keywords = [i.lower() for i in identifiers if i and len(i) > 2][:30]
            keywords = list(set(keywords))

        return keywords[:30]

    def _extract_security_api_keywords(self, vulnerability: dict, description: str) -> list:
        """从漏洞描述和类型中提取安全API关键词

        针对常见的Java安全配置漏洞，提取对应的API方法名作为关键词，
        帮助精确匹配到实际的漏洞代码行。
        """
        keywords = []
        desc_lower = description.lower()
        vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", "")).lower()
        rule_name = vulnerability.get("rule_name", "").lower()

        csrf_patterns = ["csr", "cross-site request forgery", "跨站请求伪造"]
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in csrf_patterns):
            keywords.extend(["csr", "disable", "csrfdisable", "csrf().disable", "httpsecurity"])

        clickjack_patterns = [
            "clickjack",
            "x-frame",
            "frameoption",
            "frame.options",
            "点击劫持",
            "frame-options",
        ]
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in clickjack_patterns):
            keywords.extend(
                ["frameoptions", "frame.options", "disable", "headers", "httpsecurity", "x-frame"]
            )

        cors_patterns = ["cors", "cross-origin", "跨域"]
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in cors_patterns):
            keywords.extend(["cors", "corsconfiguration", "allowedorigins", "addcorsmapping"])

        token_patterns = ["token", "jwt", "access.token", "refresh.token", "令牌"]
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in token_patterns):
            keywords.extend(
                ["token", "jwt", "accesstoken", "refreshtoken", "tokenstore", "authorization"]
            )

        auth_patterns = [
            "authentication",
            "authorization",
            "认证",
            "授权",
            "permitall",
            "permit.all",
        ]
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in auth_patterns):
            keywords.extend(
                [
                    "permitall",
                    "authenticated",
                    "authorizeexchange",
                    "authentication",
                    "authorization",
                    "security",
                ]
            )

        ssrf_patterns = ["ssr", "server-side request forgery", "服务端请求伪造"]
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in ssrf_patterns):
            keywords.extend(["resttemplate", "httpclient", "urlconnection", "fetch", "request"])

        leak_patterns = ["leak", "disclosure", "暴露", "泄露", "sensitive", "敏感"]
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in leak_patterns):
            keywords.extend(["tostring", "response", "body", "sensitive", "expose", "serialize"])

        exception_patterns = ["exception", "error.handler", "错误处理", "异常"]
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in exception_patterns):
            keywords.extend(
                [
                    "errorhandler",
                    "handleerror",
                    "exceptionhandler",
                    "responsestatus",
                    "restcontrolleradvice",
                ]
            )

        swagger_patterns = ["swagger", "api.doc", "springfox", "文档"]
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in swagger_patterns):
            keywords.extend(["swagger", "enableswagger", "swaggerui", "api-docs", "springfox"])

        keywords = list(set(k.lower() for k in keywords if k and len(k) > 1))
        return keywords

    def _extract_type_keywords(self, vulnerability_type: str) -> list:
        """从漏洞类型提取英文关键词"""
        keywords = []
        type_lower = vulnerability_type.lower()

        if "configuration" in type_lower or "config" in type_lower:
            keywords.extend(["configuration", "config", "properties", "configurationproperties"])
        if "refreshscope" in type_lower or "refresh" in type_lower:
            keywords.extend(["refreshscope", "refresh", "scope", "refreshbeanscope"])
        if "data" in type_lower and "lombok" not in keywords:
            keywords.extend(["data", "lombok", "tostring"])
        if "sql" in type_lower or "injection" in type_lower:
            keywords.extend(["sql", "injection", "sqlInjection", "parameterized"])
        if "xss" in type_lower or "crosssite" in type_lower:
            keywords.extend(["xss", "crosssite", "escape", "htmlencode"])
        if "path" in type_lower and "traversal" in type_lower:
            keywords.extend(["path", "traversal", "pathtraversal", "pathinjection"])
        if "annotation" in type_lower:
            keywords.extend(["annotation", "annotations", "@"])

        return keywords

    def _normalize_line_endings(self, content: str) -> str:
        """规范化换行符，将 CRLF/CR 统一转换为 LF

        Args:
            content: 原始文件内容

        Returns:
            规范化后的文件内容
        """
        if not content:
            return content
        return re.sub(r"\r\n|\r", "\n", content)

    def _is_inside_multiline_comment(self, file_content: str, target_line: int) -> tuple[bool, str]:
        """检测目标行是否在多行注释块内部

        Args:
            file_content: 文件全部内容
            target_line: 目标行号（1-based）

        Returns:
            (是否在注释块内, 原因)
        """
        if not file_content or target_line <= 0:
            return False, ""

        lines = file_content.split("\n")
        if target_line > len(lines):
            return False, ""

        in_block_comment = False

        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.strip()

            if line_num == target_line:
                if in_block_comment:
                    return True, "在多行注释块内"
                return False, ""

            if "/*" in stripped and "*/" not in stripped:
                in_block_comment = True
            elif "*/" in stripped and in_block_comment:
                in_block_comment = False

        return False, ""

    def _is_valid_ai_reported_line(
        self,
        line_content: str,
        line_number: Optional[int] = None,
        file_content: Optional[str] = None,
    ) -> tuple[bool, str]:
        """检查AI报告的行是否为有效的漏洞位置

        Args:
            line_content: 行内容
            line_number: 行号（可选）
            file_content: 文件全部内容（可选，用于检测多行注释）

        Returns:
            (是否有效, 原因)
        """
        if not line_content or not line_content.strip():
            return False, "空行"

        if file_content and line_number is not None:
            inside_comment, reason = self._is_inside_multiline_comment(file_content, line_number)
            if inside_comment:
                return False, reason

        stripped = line_content.strip()

        if stripped.startswith("//"):
            return False, "单行注释"

        if stripped.startswith("/*"):
            return False, "多行注释开始"

        if stripped == "*/":
            return False, "多行注释结束"

        if stripped.startswith("*") and not stripped.startswith("* @"):
            return False, "Javadoc注释行"

        if line_number is not None and line_number <= 15:
            if stripped.startswith("package "):
                return False, "package声明"

            if stripped.startswith("import "):
                return False, "import声明"

        java_keywords = ["public ", "private ", "protected ", "class ", "interface ", "enum "]
        for kw in java_keywords:
            if stripped.startswith(kw):
                return True, "VALID"

        if "@" in stripped and not stripped.startswith("*"):
            annotation_pattern = r"^\s*@(RefreshScope|ConfigurationProperties|Data|Validated|NotNull|NotBlank|Pattern|Value|Component|Controller|RestController|Service|Repository|Bean)"
            if re.search(annotation_pattern, stripped):
                return True, "注解"
            if stripped.startswith("import ") and "@" in stripped:
                return False, "import声明"
            return True, "包含注解"

        if "=" in stripped and not stripped.startswith("//"):
            return True, "赋值语句"

        if stripped.endswith("{") or stripped.endswith("}"):
            return True, "代码块"

        if len(stripped) > 3 and not self._contains_chinese(stripped):
            return True, "有效代码"

        return False, "无效行"

    def _extract_identifiers_from_description(self, description: str) -> list:
        """从描述中提取标识符（字段名、变量名等）

        Args:
            description: 漏洞描述文本

        Returns:
            提取的标识符列表
        """
        identifiers: list[str] = []

        if not description:
            return identifiers

        single_quoted_pattern = r"'([^']+)'"
        matches = re.findall(single_quoted_pattern, description)
        for m in matches:
            if len(m) > 1 and not self._contains_chinese(m):
                identifiers.append(m.lower())

        double_quoted_pattern = r'"([^"]+)"'
        matches = re.findall(double_quoted_pattern, description)
        for m in matches:
            if len(m) > 1 and not self._contains_chinese(m):
                identifiers.append(m.lower())

        var_pattern = r"变量\s+([a-zA-Z_][a-zA-Z0-9_]*)"
        matches = re.findall(var_pattern, description)
        for m in matches:
            if not self._contains_chinese(m):
                identifiers.append(m.lower())

        field_pattern = r"字段\s+([a-zA-Z_][a-zA-Z0-9_]*)"
        matches = re.findall(field_pattern, description)
        for m in matches:
            if not self._contains_chinese(m):
                identifiers.append(m.lower())

        common_field_names = [
            "windows",
            "linux",
            "mac",
            "os",
            "platform",
            "username",
            "user",
            "password",
            "pass",
            "secret",
            "key",
            "token",
            "api",
            "apikey",
            "api_key",
            "access",
            "host",
            "server",
            "url",
            "endpoint",
            "uri",
            "database",
            "db",
            "sql",
            "query",
            "email",
            "phone",
            "mobile",
            "tel",
            "address",
            "ip",
            "port",
            "path",
            "file",
            "timeout",
            "retry",
            "max",
            "min",
            "limit",
            "enabled",
            "disabled",
            "active",
            "status",
            "state",
        ]

        desc_lower = description.lower()
        for field_name in common_field_names:
            if field_name in desc_lower and len(field_name) > 2:
                identifiers.append(field_name)

        annotation_pattern = (
            r"@(RefreshScope|ConfigurationProperties|Data|Validated|NotNull|NotBlank|Pattern|Value)"
        )
        matches = re.findall(annotation_pattern, description, re.IGNORECASE)
        for m in matches:
            identifiers.append(f"@{m.lower()}")

        words = description.split()
        for word in words:
            word_clean = word.strip(".,;:!?()[]{}").lower()
            if word_clean in [
                "refreshscope",
                "configurationproperties",
                "lombok",
                "spring",
                "java",
            ]:
                identifiers.append(word_clean)

        identifiers = list(set(identifiers))
        identifiers = [i for i in identifiers if len(i) > 1]
        return identifiers

    def _code_snippet_matches_line(self, code_snippet: str, line_content: str) -> bool:
        """检查 code snippet 是否与指定行的内容匹配

        使用去空白和大小写不敏感的比较来判断是否匹配。

        Args:
            code_snippet: 代码片段
            line_content: 行内容

        Returns:
            是否匹配
        """
        if not code_snippet or not line_content:
            return False

        snippet_normalized = " ".join(code_snippet.lower().split())
        line_normalized = " ".join(line_content.lower().split())

        if snippet_normalized in line_normalized:
            return True

        snippet_keywords = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]+", code_snippet.lower()))
        line_keywords = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]+", line_content.lower()))

        snippet_keywords = {k for k in snippet_keywords if len(k) > 2}
        if not snippet_keywords:
            return False

        matched = sum(1 for kw in snippet_keywords if kw in line_keywords)
        return matched >= len(snippet_keywords) * 0.7

    def _contains_chinese(self, text: str) -> bool:
        """检查文本是否包含中文"""
        for char in text:
            if "\u4e00" <= char <= "\u9fff":
                return True
        return False

    def _split_camel_case(self, word: str) -> list:
        """拆分驼峰命名和蛇形命名"""
        parts = []
        current = ""

        for i, char in enumerate(word):
            if char.isupper() and i > 0:
                if len(current) >= 2:
                    parts.append(current.lower())
                current = char
            elif char == "_" or char == "-":
                if len(current) >= 2:
                    parts.append(current.lower())
                current = ""
            else:
                current += char

        if len(current) >= 2:
            parts.append(current.lower())

        return parts

    def _find_lines_by_keywords(
        self,
        keywords: list,
        file_content: str,
        preferred_line: Optional[int] = None,
        extracted_identifiers: Optional[list] = None,
    ) -> list:
        """根据关键词查找可能的匹配行

        Args:
            keywords: 关键词列表
            file_content: 文件内容
            preferred_line: AI报告的首选行号
            extracted_identifiers: 从描述中提取的标识符列表（字段名等）
        """
        identifiers = extracted_identifiers or []
        if not file_content:
            return []

        if not keywords and not identifiers:
            return []

        if not keywords and identifiers:
            logger.debug(" Keyword-only mode: using identifiers only (no keywords provided)")

        lines = file_content.split("\n")
        scored_lines = []

        for i, line in enumerate(lines):
            line_lower = line.lower()
            score = 0
            matched_kws = []
            identifier_bonus = 0

            for kw in keywords:
                if isinstance(kw, str) and kw.lower() in line_lower:
                    score += 1
                    matched_kws.append(kw)

            for ident in identifiers:
                ident_lower = ident.lower()
                if ident_lower in line_lower:
                    if self._is_word_boundary_match(ident_lower, line_lower):
                        identifier_bonus += 5
                        matched_kws.append(ident)
                    elif self._is_field_identifier_match(ident_lower, line, line_lower):
                        identifier_bonus += 5
                        matched_kws.append(ident)

            if identifier_bonus > 0 and self._is_field_declaration(line):
                identifier_bonus += 3

            total_score = score + identifier_bonus
            if total_score > 0:
                proximity = abs(i + 1 - preferred_line) if preferred_line else 0
                scored_lines.append((i + 1, total_score, matched_kws, identifier_bonus, proximity))

        scored_lines.sort(
            key=lambda x: (x[4] if preferred_line else 0, -(x[1] + x[3] * 0.5)), reverse=False
        )

        logger.debug(
            f"Keyword match: {len(keywords)} keywords, {len(identifiers)} identifiers, {len(scored_lines)} candidates"
        )
        logger.debug(f" Keywords: {keywords[:10]}...")
        logger.debug(f" Identifiers: {identifiers[:10]}...")
        if scored_lines:
            logger.debug(
                f"Best candidate: line {scored_lines}, score {scored_lines}, identifier_bonus {scored_lines}, matched {scored_lines[:5]}"
            )
            if preferred_line:
                logger.debug(
                    f"AI reported: {preferred_line}, offset: {abs(scored_lines - preferred_line)} lines"
                )
        if scored_lines:
            best_match = scored_lines[0][0]
            best_score = scored_lines[0][1]
            best_identifier_bonus = scored_lines[0][3]
            # best_proximity = scored_lines[0][4]
            tolerance = self.tolerance if self.tolerance > 0 else 5

            if preferred_line:
                offset = abs(best_match - preferred_line)
                if offset <= tolerance:
                    logger.debug(f" Tolerance check passed: offset {offset} <= {tolerance}")
                    return [best_match]
                else:
                    logger.debug(
                        f"Best match exceeds tolerance: offset {offset} > {tolerance}, looking for closer candidates..."
                    )
                    closer_candidates = [
                        (ln, score, kws, ib, prox)
                        for ln, score, kws, ib, prox in scored_lines
                        if abs(ln - preferred_line) <= tolerance
                    ]
                    if closer_candidates:
                        closer_candidates.sort(key=lambda x: (x[4], -(x[1] + x[3] * 0.5)))
                        best_match = closer_candidates[0][0]
                        logger.debug(f" Found closer match within tolerance: line {best_match}")
                        return [best_match]
                    else:
                        high_score_threshold = 3
                        if best_identifier_bonus >= high_score_threshold:
                            logger.debug(
                                f"Best match has high identifier score ({best_identifier_bonus} >= {high_score_threshold}), accepting despite offset {offset}"
                            )
                            return [best_match]
                        elif best_score >= high_score_threshold * 2:
                            logger.debug(
                                f"Best match has very high keyword score ({best_score} >= {high_score_threshold * 2}), accepting despite offset {offset}"
                            )
                            return [best_match]
                        logger.debug(" No candidates within tolerance, returning best available")
                        top_candidates = [ln for ln, _, _, _, _ in scored_lines[:5]]
                        logger.debug(f" Returning top 5 candidates: {top_candidates}")
                        return top_candidates
            elif best_identifier_bonus > 0:
                logger.debug(" Identifier match found (no preferred_line), accepting match")
                return [best_match]

            if identifiers:
                target_candidates = [
                    (ln, score, kws, ib, prox)
                    for ln, score, kws, ib, prox in scored_lines
                    if any(ident in kws for ident in identifiers)
                ]
                if target_candidates:
                    target_candidates.sort(key=lambda x: (x[4], -(x[1] + x[3] * 0.5)))
                    best_target = target_candidates[0]
                    logger.debug(
                        f"Found target identifier match: line {best_target}, score {best_target}"
                    )
                    return [best_target[0]]
                else:
                    logger.debug(" No target identifier found in candidates")

            top_candidates = [ln for ln, _, _, _, _ in scored_lines[:5]]
            logger.debug(f" Returning top 5 candidates: {top_candidates}")
            return top_candidates

        return []

    def _is_configuration_vulnerability(self, vulnerability: dict) -> bool:
        """检查是否为配置类漏洞（需要联合关键词验证）

        Args:
            vulnerability: 漏洞数据

        Returns:
            是否为配置类漏洞
        """
        rule_name = vulnerability.get("rule_name", "").lower()
        description = vulnerability.get("description", "").lower()
        vulnerability_type = vulnerability.get("vulnerability_type", "").lower()

        config_keywords = [
            "configuration",
            "config",
            "routerfunction",
            "router",
            "endpoint",
            "handler",
            "mapping",
            "requestmapping",
            "getmapping",
            "postmapping",
            "putmapping",
            "deletemapping",
            "bean",
            "refreshscope",
            "configurationproperties",
            "resttemplate",
            "webclient",
            "feign",
            "loadbalancer",
        ]

        combined = f"{rule_name} {description} {vulnerability_type}"
        return any(kw in combined for kw in config_keywords)

    def _extract_joint_keywords(self, vulnerability: dict) -> tuple[list, list]:
        """提取联合验证关键词

        对于配置类漏洞，提取必须同时出现的关键词对。

        Args:
            vulnerability: 漏洞数据

        Returns:
            (必需关键词列表, 可选关键词列表)
        """
        required_keywords = []
        optional_keywords = []

        rule_name = vulnerability.get("rule_name", "")
        description = vulnerability.get("description", "")
        # vulnerability_type = vulnerability.get("vulnerability_type", "")

        if "routerfunction" in rule_name.lower() or "routerfunction" in description.lower():
            router_patterns = [
                r"router\s*\(",
                r"functions?\.router",
                r"route\s*\(",
                r"path\s*=",
                r"method\s*=",
            ]
            for pattern in router_patterns:
                matches = re.findall(pattern, description, re.IGNORECASE)
                required_keywords.extend([m.lower() for m in matches if m])

            handler_patterns = [
                r"(?:handler|bean|method)\s+([a-zA-Z_][a-zA-Z0-9_]*)",
                r"::\s*([a-zA-Z_][a-zA-Z0-9_]*)",
            ]
            for pattern in handler_patterns:
                matches = re.findall(pattern, description, re.IGNORECASE)
                optional_keywords.extend([m.lower() for m in matches if m])

        if "resttemplate" in rule_name.lower() or "resttemplate" in description.lower():
            resttemplate_patterns = [
                r"RestTemplate",
                r"@LoadBalanced",
                r"URL\s*\(",
                r"getForObject",
                r"getForEntity",
                r"postForObject",
            ]
            for pattern in resttemplate_patterns:
                if re.search(pattern, description, re.IGNORECASE):
                    required_keywords.append(pattern.lower())

        if (
            "configurationproperties" in rule_name.lower()
            or "configurationproperties" in description.lower()
        ):
            configprops_patterns = [
                r"@ConfigurationProperties",
                r"prefix\s*=",
                r"@RefreshScope",
            ]
            for pattern in configprops_patterns:
                if re.search(pattern, description, re.IGNORECASE):
                    required_keywords.append(pattern.lower())

        description_keywords = self._extract_keywords(vulnerability)
        required_keywords.extend(description_keywords[:5])
        optional_keywords.extend(description_keywords[5:])

        required_keywords = list(set([k for k in required_keywords if k and len(k) > 1]))
        optional_keywords = list(set([k for k in optional_keywords if k and len(k) > 1]))

        return required_keywords, optional_keywords

    def _find_lines_by_joint_keywords(
        self, vulnerability: dict, file_content: str, preferred_line: Optional[int] = None
    ) -> list:
        """根据联合关键词查找匹配行（所有必需关键词必须同时出现）

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容
            preferred_line: AI报告的首选行号

        Returns:
            匹配行号列表
        """
        if not file_content:
            return []

        required_kws, optional_kws = self._extract_joint_keywords(vulnerability)

        if not required_kws:
            return self._find_lines_by_keywords(
                self._extract_keywords(vulnerability), file_content, preferred_line, None
            )

        logger.debug(
            f"Joint verification: {len(required_kws)} required keywords, {len(optional_kws)} optional keywords"
        )
        logger.debug(f" Required keywords: {required_kws}")
        logger.debug(f" Optional keywords: {optional_kws}")

        lines = file_content.split("\n")
        joint_candidates = []

        for i, line in enumerate(lines):
            line_lower = line.lower()
            matched_required = []
            matched_optional = []

            for kw in required_kws:
                if isinstance(kw, str) and kw.lower() in line_lower:
                    matched_required.append(kw)

            if len(matched_required) < len(required_kws):
                continue

            for kw in optional_kws:
                if isinstance(kw, str) and kw.lower() in line_lower:
                    matched_optional.append(kw)

            all_matched = matched_required + matched_optional
            if all_matched:
                joint_candidates.append((i + 1, len(all_matched), all_matched, matched_required))

        joint_candidates.sort(
            key=lambda x: (
                len(x[3]),
                x[1],
                -abs(x[0] - (preferred_line or 0)) if preferred_line else 0,
            ),
            reverse=True,
        )

        if joint_candidates:
            logger.debug(f" Joint verification found {len(joint_candidates)} candidates")
            logger.debug(
                f"Best joint match: line {joint_candidates}, required matched: {joint_candidates}"
            )
            return [ln for ln, _, _, _ in joint_candidates]

        logger.warning(" Joint verification failed, falling back to standard keyword search")
        return self._find_lines_by_keywords(
            required_kws + optional_kws, file_content, preferred_line, None
        )

    def _is_field_declaration(self, line: str) -> bool:
        """检查行是否为字段声明"""
        line_stripped = line.strip()
        if not line_stripped:
            return False
        field_patterns = [
            r"private\s+\w+",
            r"public\s+\w+",
            r"protected\s+\w+",
            r"\w+\s+\w+\s*=",
        ]
        import re

        for pattern in field_patterns:
            if re.search(pattern, line):
                return True
        return False

    def _is_word_boundary_match(self, word: str, text: str) -> bool:
        """检查单词是否作为独立单词出现在文本中（使用单词边界）

        Args:
            word: 要检查的单词
            text: 文本（已转换为小写）

        Returns:
            是否作为独立单词出现
        """
        import re

        pattern = r"\b" + re.escape(word) + r"\b"
        return bool(re.search(pattern, text))

    def _is_field_identifier_match(
        self, word: str, line: str, line_lower: Optional[str] = None
    ) -> bool:
        """检查单词是否作为字段标识符出现在行中

        字段标识符匹配的情况：
        1. 单词作为变量名出现在赋值语句中（如 private String xxx = xxx）
        2. 单词作为方法参数名出现

        Args:
            word: 要检查的单词
            line: 行内容
            line_lower: 行内容的小写版本（可选，如果为None会重新计算）

        Returns:
            是否作为字段标识符出现
        """
        if line_lower is None:
            line_lower = line.lower()

        import re

        field_assignment_patterns = [
            r"private\s+\w+\s+\w+\s*=",
            r"public\s+\w+\s+\w+\s*=",
            r"protected\s+\w+\s+\w+\s*=",
            r'\w+\s+\w+\s*=\s*"?\w+"?\s*;',
        ]

        for pattern in field_assignment_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                if word in line_lower:
                    return True
        return False

    def adjust_line_number(self, vulnerability: dict, file_content: str) -> dict:
        """执行自动校正

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容

        Returns:
            校正后的漏洞数据
        """
        validated = self.validate_location(vulnerability, file_content)

        if validated.get("line_match_status") == LineMatchStatus.UNVERIFIED.value:
            return self.mark_unverified(validated, validated.get("candidate_lines", []))

        if validated.get("verified_line", -1) > 0:
            location = validated.get("location", "")
            file_path, _ = self.mapper.parse_location(location)
            if file_path and validated.get("verified_line", -1) > 0:
                adjusted_location = f"{file_path}:{validated['verified_line']}"
                validated["location"] = adjusted_location

        return validated

    def mark_unverified(self, vulnerability: dict, candidates: list) -> dict:
        """标记无法验证的漏洞

        Args:
            vulnerability: 漏洞数据
            candidates: 候选行号列表

        Returns:
            标记后的漏洞数据
        """
        result = dict(vulnerability)
        result["line_match_status"] = LineMatchStatus.UNVERIFIED.value
        result["candidate_lines"] = candidates

        if result.get("signal_state") == SignalState.CONFIRMED.value:
            result["signal_state"] = SignalState.UNCERTAIN.value
            result["verification_decision"] = "UNCERTAIN"
            result["verification_reason"] = (
                f"行号无法验证，候选行: {candidates[:5]}" if candidates else "行号无法验证，未找到匹配代码"
            )

        return result