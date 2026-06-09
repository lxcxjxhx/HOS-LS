"""
框架安全模式检测模块

提供常见框架的安全/不安全模式定义，用于降低安全扫描误报率。
涵盖 MyBatis-Plus、Spring Security、Spring Data JPA 等主流框架。
"""

import os
import re
from typing import Any, Dict, List


FRAMEWORK_SAFE_PATTERNS: Dict[str, Dict] = {
    "mybatis_plus_wrappers_query": {
        "regex": r'Wrappers\.query\s*\(',
        "description": "MyBatis-Plus Wrappers.query() 使用预编译语句，防御SQL注入",
        "safety_level": "safe",
        "framework": "mybatis-plus",
    },
    "mybatis_plus_wrappers_lambda_query": {
        "regex": r'Wrappers\.lambdaQuery\s*\(',
        "description": "MyBatis-Plus Wrappers.lambdaQuery() 使用预编译语句，防御SQL注入",
        "safety_level": "safe",
        "framework": "mybatis-plus",
    },
    "mybatis_plus_query_wrapper": {
        "regex": r'QueryWrapper\s*<',
        "description": "MyBatis-Plus QueryWrapper 使用参数化查询",
        "safety_level": "safe",
        "framework": "mybatis-plus",
    },
    "mybatis_plus_lambda_query_wrapper": {
        "regex": r'LambdaQueryWrapper\s*<',
        "description": "MyBatis-Plus LambdaQueryWrapper 使用参数化查询",
        "safety_level": "safe",
        "framework": "mybatis-plus",
    },
    "mybatis_parameter_binding": {
        "regex": r'#\{[\w.]+\}',
        "description": "MyBatis #{parameter} 参数绑定语法，使用预编译语句",
        "safety_level": "safe",
        "framework": "mybatis",
    },
    "spring_preauthorize": {
        "regex": r'@PreAuthorize\s*\(',
        "description": "Spring Security @PreAuthorize 方法级访问控制",
        "safety_level": "safe",
        "framework": "spring-security",
    },
    "spring_secured": {
        "regex": r'@Secured\s*\(',
        "description": "Spring Security @Secured 角色访问控制",
        "safety_level": "safe",
        "framework": "spring-security",
    },
    "spring_roles_allowed": {
        "regex": r'@RolesAllowed\s*\(',
        "description": "JSR-250 @RolesAllowed 基于角色的访问控制",
        "safety_level": "safe",
        "framework": "spring-security",
    },
    "spring_post_authorize": {
        "regex": r'@PostAuthorize\s*\(',
        "description": "Spring Security @PostAuthorize 方法返回后访问控制",
        "safety_level": "safe",
        "framework": "spring-security",
    },
    "spring_pre_filter": {
        "regex": r'@PreFilter\s*\(',
        "description": "Spring Security @PreFilter 集合元素过滤",
        "safety_level": "safe",
        "framework": "spring-security",
    },
    "spring_post_filter": {
        "regex": r'@PostFilter\s*\(',
        "description": "Spring Security @PostFilter 集合返回值过滤",
        "safety_level": "safe",
        "framework": "spring-security",
    },
    "spring_transactional": {
        "regex": r'@Transactional\s*(?:\(|$)',
        "description": "Spring @Transactional 事务管理，保证数据一致性",
        "safety_level": "safe",
        "framework": "spring",
    },
    "jpa_param_query": {
        "regex": r':\w+',
        "description": "JPA/Hibernate 命名参数查询 (:param)，使用参数化",
        "safety_level": "safe",
        "framework": "jpa",
    },
    "jpa_param_query_index": {
        "regex": r'\?\d*',
        "description": "JPA/Hibernate 位置参数查询 (?1)，使用参数化",
        "safety_level": "safe",
        "framework": "jpa",
    },
    "spring_valid": {
        "regex": r'@Valid\s',
        "description": "Spring @Valid 输入校验注解",
        "safety_level": "safe",
        "framework": "spring-validation",
    },
    "spring_validated": {
        "regex": r'@Validated\s*(?:\(|$)',
        "description": "Spring @Validated 分组校验注解",
        "safety_level": "safe",
        "framework": "spring-validation",
    },
    "validation_not_blank": {
        "regex": r'@NotBlank\s*(?:\(|$)',
        "description": "Bean Validation @NotBlank 非空校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_not_null": {
        "regex": r'@NotNull\s*(?:\(|$)',
        "description": "Bean Validation @NotNull 非空校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_not_empty": {
        "regex": r'@NotEmpty\s*(?:\(|$)',
        "description": "Bean Validation @NotEmpty 非空校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_size": {
        "regex": r'@Size\s*\(',
        "description": "Bean Validation @Size 长度校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_pattern": {
        "regex": r'@Pattern\s*\(',
        "description": "Bean Validation @Pattern 正则校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_email": {
        "regex": r'@Email\s*(?:\(|$)',
        "description": "Bean Validation @Email 邮箱格式校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_min": {
        "regex": r'@Min\s*\(',
        "description": "Bean Validation @Min 最小值校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_max": {
        "regex": r'@Max\s*\(',
        "description": "Bean Validation @Max 最大值校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_digits": {
        "regex": r'@Digits\s*\(',
        "description": "Bean Validation @Digits 数字精度校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_positive": {
        "regex": r'@Positive\s*(?:\(|$)',
        "description": "Bean Validation @Positive 正数校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_negative": {
        "regex": r'@Negative\s*(?:\(|$)',
        "description": "Bean Validation @Negative 负数校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_past": {
        "regex": r'@Past\s*(?:\(|$)',
        "description": "Bean Validation @Past 过去时间校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
    "validation_future": {
        "regex": r'@Future\s*(?:\(|$)',
        "description": "Bean Validation @Future 未来时间校验",
        "safety_level": "safe",
        "framework": "bean-validation",
    },
}


FRAMEWORK_UNSAFE_PATTERNS: Dict[str, Dict] = {
    "mybatis_string_concat": {
        "regex": r'\$\{[\w.]+\}',
        "description": "MyBatis ${property} 字符串拼接语法，存在SQL注入风险",
        "risk_level": "high",
        "framework": "mybatis",
    },
    "string_sql_concat": {
        "regex": r'(?i)(?:String|StringBuilder|StringBuffer)\s+\w+\s*=.*["\'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)',
        "description": "使用字符串拼接构建SQL语句，存在SQL注入风险",
        "risk_level": "high",
        "framework": "general",
    },
    "runtime_exec": {
        "regex": r'Runtime\.getRuntime\s*\(\)\s*\.exec\s*\(',
        "description": "Runtime.exec() 执行系统命令，存在命令注入风险",
        "risk_level": "high",
        "framework": "general",
    },
    "process_builder_string": {
        "regex": r'ProcessBuilder\s*\(\s*["\']',
        "description": "ProcessBuilder 使用字符串参数，存在命令注入风险",
        "risk_level": "high",
        "framework": "general",
    },
}


FRAMEWORK_SECURITY_ANNOTATIONS: List[str] = [
    "@EnableWebSecurity",
    "@EnableWebMvc",
    "@CrossOrigin",
    "@PreAuthorize",
    "@PostAuthorize",
    "@PostFilter",
    "@PreFilter",
    "@Secured",
    "@RolesAllowed",
    "@PermitAll",
    "@DenyAll",
    "@Transactional",
    "@Valid",
    "@Validated",
    "@NotBlank",
    "@NotNull",
    "@NotEmpty",
    "@Size",
    "@Pattern",
    "@Email",
    "@Min",
    "@Max",
    "@AssertTrue",
    "@AssertFalse",
    "@DecimalMin",
    "@DecimalMax",
    "@Digits",
    "@Past",
    "@Future",
    "@Negative",
    "@Positive",
    "@RestControllerAdvice",
    "@ExceptionHandler",
    "@ConfigurationProperties",
    "@ConfigProperty",
    "@Value",
]

SECURITY_ANNOTATION_WEIGHTS: Dict[str, Dict] = {
    "@PreAuthorize": {
        "weight": 0.85,
        "risk_reduction": 0.4,
        "severity_downgrade": True,
        "description": "方法级SpEL表达式访问控制，提供细粒度权限校验",
        "mitigates": ["authorization_bypass", "broken_access_control", "insecure_direct_object_reference", "privilege_escalation"],
    },
    "@PostAuthorize": {
        "weight": 0.80,
        "risk_reduction": 0.35,
        "severity_downgrade": True,
        "description": "方法返回后基于返回值的访问控制",
        "mitigates": ["information_disclosure", "insecure_direct_object_reference"],
    },
    "@Secured": {
        "weight": 0.75,
        "risk_reduction": 0.3,
        "severity_downgrade": True,
        "description": "基于角色的访问控制注解",
        "mitigates": ["authorization_bypass", "broken_access_control"],
    },
    "@RolesAllowed": {
        "weight": 0.75,
        "risk_reduction": 0.3,
        "severity_downgrade": True,
        "description": "JSR-250标准角色访问控制",
        "mitigates": ["authorization_bypass", "broken_access_control"],
    },
    "@PreFilter": {
        "weight": 0.70,
        "risk_reduction": 0.25,
        "severity_downgrade": False,
        "description": "方法执行前集合元素过滤",
        "mitigates": ["mass_assignment", "insecure_direct_object_reference"],
    },
    "@PostFilter": {
        "weight": 0.70,
        "risk_reduction": 0.25,
        "severity_downgrade": False,
        "description": "方法返回后集合结果过滤",
        "mitigates": ["information_disclosure", "horizontal_privilege_escalation"],
    },
    "@AuthenticationPrincipal": {
        "weight": 0.80,
        "risk_reduction": 0.35,
        "severity_downgrade": True,
        "description": "自动注入已认证用户主体，确保调用者已认证",
        "mitigates": ["authentication_bypass", "broken_access_control"],
    },
    "@EnableWebMvc": {
        "weight": 0.65,
        "risk_reduction": 0.25,
        "severity_downgrade": False,
        "description": "Spring MVC安全配置，提供请求级安全控制",
        "mitigates": ["xss", "csrf", "insecure_direct_object_reference"],
    },
    "@RestControllerAdvice": {
        "weight": 0.70,
        "risk_reduction": 0.30,
        "severity_downgrade": True,
        "description": "全局异常处理，防止敏感信息泄露",
        "mitigates": ["information_disclosure", "sensitive_data_exposure", "stack_trace_leak"],
    },
    "@ExceptionHandler": {
        "weight": 0.65,
        "risk_reduction": 0.25,
        "severity_downgrade": False,
        "description": "异常处理机制，可拦截敏感错误信息输出",
        "mitigates": ["information_disclosure", "stack_trace_leak"],
    },
    "@ConfigurationProperties": {
        "weight": 0.50,
        "risk_reduction": 0.15,
        "severity_downgrade": False,
        "description": "Spring Boot配置绑定，需验证输入防止注入",
        "mitigates": ["injection"],
    },
    "@ConfigProperty": {
        "weight": 0.50,
        "risk_reduction": 0.15,
        "severity_downgrade": False,
        "description": "Quarkus配置属性注入，需验证输入",
        "mitigates": ["injection"],
    },
    "@Value": {
        "weight": 0.50,
        "risk_reduction": 0.15,
        "severity_downgrade": False,
        "description": "Micronaut/Spring值注入，需验证输入防止注入",
        "mitigates": ["injection"],
    },
}

ATTACK_DIFFICULTY_FACTORS: Dict[str, Dict] = {
    "preauthorize_spel_complex": {
        "pattern": r'@PreAuthorize\s*\([^)]*(?:hasRole|hasAuthority|authentication|principal|#this|filterObject)[^)]*\)',
        "difficulty_increase": 0.3,
        "description": "复杂SpEL表达式增加攻击难度",
    },
    "multiple_auth_annotations": {
        "pattern": None,
        "min_count": 2,
        "annotations": list(SECURITY_ANNOTATION_WEIGHTS.keys()),
        "difficulty_increase": 0.2,
        "description": "多层安全注解叠加增加攻击难度",
    },
    "transactional_security": {
        "pattern": r'@Transactional',
        "difficulty_increase": 0.1,
        "description": "事务保护降低数据篡改风险",
    },
}

ANNOTATION_VULN_MITIGATION: Dict[str, List[str]] = {
    "sql_injection": ["@Param", "@Query", "@NamedQuery", "@NamedNativeQuery"],
    "xss": ["@HtmlEscape", "@XssProtection", "ContentSecurityPolicy", "@ResponseBody"],
    "csrf": ["@CsrfProtection", "@EnableCsrf"],
    "injection": ["@Valid", "@Validated", "@NotBlank", "@Pattern", "@Size", "@Email", "@Min", "@Max"],
    "path_traversal": ["@Pattern", "@Validated"],
    "command_injection": ["@Pattern", "@Validated", "@NotBlank"],
    "auth_bypass": ["@PreAuthorize", "@PostAuthorize", "@Secured", "@RolesAllowed", "@AuthenticationPrincipal"],
    "sensitive_data_exposure": ["@JsonIgnore", "@JsonProperty(access=READ_ONLY)", "@RestControllerAdvice", "@ExceptionHandler"],
    "deserialization": ["@JsonFilter", "@JsonIgnoreProperties"],
    "ssrf": ["@Pattern", "@Validated"],
    "open_redirect": ["@Pattern", "@Validated"],
    "ldap_injection": ["@Pattern", "@Validated", "@NotBlank"],
    "xxe": ["@EnableXmlSecurity"],
}


def detect_lombok_sensitive_fields(content: str, file_path: str = "") -> List[Dict[str, Any]]:
    """
    检测使用了 Lombok @Data 注解的类中包含敏感字段的情况。

    Args:
        content: 文件内容字符串
        file_path: 文件路径（可选）

    Returns:
        检测结果列表，每个元素包含漏洞信息
    """
    findings: List[Dict[str, Any]] = []

    sensitive_field_names = [
        "password", "token", "secret", "key", "apiKey", "apiSecret",
        "accessToken", "refreshToken", "privateKey", "credential"
    ]

    data_class_pattern = re.compile(
        r'@Data\s*\n\s*(?:@\w+(?:\([^)]*\))?\s*\n\s*)*'
        r'(?:public\s+)?class\s+(\w+)(?:\s+extends\s+\w+)?(?:\s+implements\s+[\w,\s]+)?\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
        re.MULTILINE
    )

    for match in data_class_pattern.finditer(content):
        class_name = match.group(1)
        class_body = match.group(2)

        field_pattern = re.compile(
            r'(?:private|public|protected)?\s*(?:static\s+)?(?:final\s+)?\w+\s+(\w+)\s*;',
            re.MULTILINE
        )

        for field_match in field_pattern.finditer(class_body):
            field_name = field_match.group(1)

            for sensitive in sensitive_field_names:
                if field_name.lower() == sensitive.lower():
                    finding_line = content[:match.start()].count('\n') + 1
                    findings.append({
                        "type": "lombok_sensitive_field_exposure",
                        "severity": "high",
                        "description": f"类 '{class_name}' 使用 @Data 注解，自动生成敏感字段 '{field_name}' 的 getter/setter，可能导致敏感数据泄露",
                        "file": file_path,
                        "line": finding_line,
                        "class_name": class_name,
                        "field_name": field_name,
                        "recommendation": "使用 @JsonIgnore 或 @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) 注解敏感字段，或手动编写 getter/setter 控制序列化行为",
                    })
                    break

    return findings


def detect_jpa_query_injection(content: str) -> List[Dict[str, Any]]:
    """
    检测 Spring Data JPA @Query 注解中潜在的 SQL 注入风险。

    Args:
        content: 文件内容字符串

    Returns:
        检测结果列表，每个元素包含漏洞信息
    """
    findings: List[Dict[str, Any]] = []

    string_concat_pattern = re.compile(
        r'@Query\s*\(\s*["\'].*\+.*["\']',
        re.MULTILINE | re.DOTALL
    )

    dollar_sign_pattern = re.compile(
        r'@Query\s*\([^)]*nativeQuery\s*=\s*true[^)]*\$\{',
        re.MULTILINE | re.DOTALL
    )

    for match in string_concat_pattern.finditer(content):
        line_num = content[:match.start()].count('\n') + 1
        findings.append({
            "type": "jpa_query_string_concatenation",
            "severity": "high",
            "description": "@Query 注解中使用字符串拼接构建查询语句，存在 SQL 注入风险",
            "line": line_num,
            "recommendation": "使用命名参数 (:param) 或位置参数 (?1) 替代字符串拼接",
        })

    for match in dollar_sign_pattern.finditer(content):
        line_num = content[:match.start()].count('\n') + 1
        findings.append({
            "type": "jpa_native_query_dollar_syntax",
            "severity": "high",
            "description": "@Query (nativeQuery=true) 中使用 ${} 语法，存在 SQL 注入风险",
            "line": line_num,
            "recommendation": "使用命名参数 (:param) 替代 ${} 占位符",
        })

    return findings


def detect_hibernate_native_sql(content: str) -> List[Dict[str, Any]]:
    """
    检测 Hibernate 原生 SQL 查询中的潜在安全风险。

    Args:
        content: 文件内容字符串

    Returns:
        检测结果列表，每个元素包含漏洞信息
    """
    findings: List[Dict[str, Any]] = []

    create_sql_query_pattern = re.compile(
        r'(?:session|sessionFactory|currentSession)\s*\.\s*createSQLQuery\s*\(',
        re.MULTILINE
    )

    create_native_query_pattern = re.compile(
        r'(?:entityManager|em)\s*\.\s*createNativeQuery\s*\(',
        re.MULTILINE
    )

    named_native_query_pattern = re.compile(
        r'@NamedNativeQuery\s*\(',
        re.MULTILINE
    )

    for match in create_sql_query_pattern.finditer(content):
        line_num = content[:match.start()].count('\n') + 1
        context_start = max(0, match.start() - 50)
        context_end = min(len(content), match.end() + 100)
        context = content[context_start:context_end]

        has_concatenation = "+" in context or ".concat(" in context or "String.format" in context

        findings.append({
            "type": "hibernate_create_sql_query",
            "severity": "high" if has_concatenation else "medium",
            "description": "使用 session.createSQLQuery() 执行原生 SQL 查询" + ("，且检测到字符串拼接，存在 SQL 注入风险" if has_concatenation else "，需确保使用参数化查询"),
            "line": line_num,
            "recommendation": "优先使用 HQL/JPQL 或 Spring Data JPA 方法；如必须使用原生 SQL，请使用参数化查询 (setParameter)",
        })

    for match in create_native_query_pattern.finditer(content):
        line_num = content[:match.start()].count('\n') + 1
        context_start = max(0, match.start() - 50)
        context_end = min(len(content), match.end() + 100)
        context = content[context_start:context_end]

        has_concatenation = "+" in context or ".concat(" in context or "String.format" in context

        findings.append({
            "type": "hibernate_create_native_query",
            "severity": "high" if has_concatenation else "medium",
            "description": "使用 entityManager.createNativeQuery() 执行原生 SQL 查询" + ("，且检测到字符串拼接，存在 SQL 注入风险" if has_concatenation else "，需确保使用参数化查询"),
            "line": line_num,
            "recommendation": "优先使用 JPQL；如必须使用原生 SQL，请使用 setParameter() 进行参数绑定",
        })

    for match in named_native_query_pattern.finditer(content):
        line_num = content[:match.start()].count('\n') + 1
        context_start = max(0, match.start() - 50)
        context_end = min(len(content), match.end() + 200)
        context = content[context_start:context_end]

        has_string_concat = re.search(r'["\'].*\+.*["\']', context, re.DOTALL)
        has_dollar_syntax = "${" in context

        if has_string_concat or has_dollar_syntax:
            findings.append({
                "type": "hibernate_named_native_query_unsafe",
                "severity": "high",
                "description": "@NamedNativeQuery 中包含不安全的 SQL 拼接模式",
                "line": line_num,
                "recommendation": "使用命名参数 (:param) 替代字符串拼接",
            })

    return findings


def match_framework_patterns(content: str) -> Dict:
    """
    扫描文件内容，返回匹配到的框架安全/不安全模式。

    Args:
        content: 文件内容字符串

    Returns:
        包含匹配结果的字典:
        {
            "safe": [{"pattern": str, "description": str, "matches": int}, ...],
            "unsafe": [{"pattern": str, "description": str, "risk_level": str, "matches": int}, ...],
            "total_safe": int,
            "total_unsafe": int,
        }
    """
    result = {
        "safe": [],
        "unsafe": [],
        "total_safe": 0,
        "total_unsafe": 0,
    }

    for name, info in FRAMEWORK_SAFE_PATTERNS.items():
        pattern = info["regex"]
        matches = re.findall(pattern, content)
        count = len(matches)
        if count > 0:
            result["safe"].append({
                "pattern": name,
                "regex": pattern,
                "description": info["description"],
                "framework": info["framework"],
                "matches": count,
            })
            result["total_safe"] += count

    for name, info in FRAMEWORK_UNSAFE_PATTERNS.items():
        pattern = info["regex"]
        matches = re.findall(pattern, content)
        count = len(matches)
        if count > 0:
            result["unsafe"].append({
                "pattern": name,
                "regex": pattern,
                "description": info["description"],
                "framework": info["framework"],
                "risk_level": info["risk_level"],
                "matches": count,
            })
            result["total_unsafe"] += count

    return result


def has_security_control(content: str) -> bool:
    """
    检查文件是否包含安全控制注解。

    Args:
        content: 文件内容字符串

    Returns:
        是否包含安全控制注解
    """
    for annotation in FRAMEWORK_SECURITY_ANNOTATIONS:
        escaped = re.escape(annotation)
        if re.search(escaped, content):
            return True
    return False


def get_framework_summary(content: str) -> Dict[str, int]:
    """
    获取文件中各框架模式的使用统计。

    Args:
        content: 文件内容字符串

    Returns:
        框架名称 -> 匹配次数的映射
    """
    summary: Dict[str, int] = {}
    matches = match_framework_patterns(content)

    for item in matches["safe"]:
        fw = item["framework"]
        summary[fw] = summary.get(fw, 0) + item["matches"]

    for item in matches["unsafe"]:
        fw = item["framework"]
        summary[fw] = summary.get(fw, 0) + item["matches"]

    return summary


def detect_security_annotations_in_context(content: str, target_line: int = 0, context_lines: int = 20) -> Dict[str, Any]:
    """
    在代码上下文中检测安全注解并评估其缓解效果。

    Args:
        content: 文件内容字符串
        target_line: 目标行号（0表示全局扫描）
        context_lines: 上下文行数

    Returns:
        包含检测到的安全注解及其缓解效果的字典:
        {
            "annotations_found": List[str],
            "max_risk_reduction": float,
            "should_downgrade_severity": bool,
            "mitigation_description": str,
            "attack_difficulty_score": float,
            "protection_layers": int,
        }
    """
    result: Dict[str, Any] = {
        "annotations_found": [],
        "max_risk_reduction": 0.0,
        "should_downgrade_severity": False,
        "mitigation_description": "",
        "attack_difficulty_score": 0.0,
        "protection_layers": 0,
    }

    if target_line > 0:
        lines = content.split('\n')
        start = max(0, target_line - context_lines - 1)
        end = min(len(lines), target_line + context_lines)
        search_content = '\n'.join(lines[start:end])
    else:
        search_content = content

    search_content_str = str(search_content)

    for annotation, weight_info in SECURITY_ANNOTATION_WEIGHTS.items():
        escaped = re.escape(annotation)
        if re.search(escaped, search_content_str):
            result["annotations_found"].append(annotation)
            risk_red = weight_info.get("risk_reduction", 0.0)
            if risk_red > result["max_risk_reduction"]:
                result["max_risk_reduction"] = risk_red
            if weight_info.get("severity_downgrade", False):
                result["should_downgrade_severity"] = True

    result["protection_layers"] = len(result["annotations_found"])

    for factor_name, factor_info in ATTACK_DIFFICULTY_FACTORS.items():
        pattern = factor_info.get("pattern")
        if pattern:
            if re.search(pattern, search_content_str):
                result["attack_difficulty_score"] += factor_info.get("difficulty_increase", 0.0)

        if factor_info.get("min_count"):
            matching_count = 0
            for ann in factor_info.get("annotations", []):
                if re.search(re.escape(ann), search_content_str):
                    matching_count += 1
            if matching_count >= factor_info["min_count"]:
                result["attack_difficulty_score"] += factor_info.get("difficulty_increase", 0.0)

    result["attack_difficulty_score"] = min(1.0, result["attack_difficulty_score"])

    if result["annotations_found"]:
        descriptions = []
        for ann in result["annotations_found"]:
            if ann in SECURITY_ANNOTATION_WEIGHTS:
                descriptions.append(SECURITY_ANNOTATION_WEIGHTS[ann]["description"])
        result["mitigation_description"] = " | ".join(descriptions)

    return result


def calculate_mitigated_severity(
    original_severity: str,
    security_context: Dict[str, Any],
    vuln_type: str = ""
) -> str:
    """
    根据安全上下文计算缓解后的严重级别。

    仅当注解与漏洞类型相关时才降级。

    Args:
        original_severity: 原始严重级别
        security_context: detect_security_annotations_in_context 的返回值
        vuln_type: 漏洞类型（用于判断是否被缓解）

    Returns:
        缓解后的严重级别
    """
    if not security_context.get("should_downgrade_severity", False):
        return original_severity

    severity_order = ["critical", "high", "medium", "low", "info"]
    vuln_type_lower = vuln_type.lower()

    mitigated_annotations = []
    ignored_annotations = []

    vuln_mitigating_annotations = ANNOTATION_VULN_MITIGATION.get(vuln_type_lower, [])

    if not vuln_type_lower:
        return original_severity

    for ann in security_context.get("annotations_found", []):
        if ann in SECURITY_ANNOTATION_WEIGHTS:
            mitigates_list = SECURITY_ANNOTATION_WEIGHTS[ann].get("mitigates", [])
            ann_relevant = False
            if vuln_mitigating_annotations and ann in vuln_mitigating_annotations:
                ann_relevant = True
            elif mitigates_list and any(m in vuln_type_lower for m in mitigates_list):
                ann_relevant = True

            if ann_relevant:
                mitigated_annotations.append(ann)
            else:
                ignored_annotations.append(ann)

    if not mitigated_annotations and security_context.get("max_risk_reduction", 0) < 0.3:
        return original_severity

    if not mitigated_annotations and security_context.get("max_risk_reduction", 0) >= 0.3:
        relevant_found = False
        for ann in security_context.get("annotations_found", []):
            if ann in SECURITY_ANNOTATION_WEIGHTS:
                mitigates_list = SECURITY_ANNOTATION_WEIGHTS[ann].get("mitigates", [])
                if mitigates_list and any(m in vuln_type_lower for m in mitigates_list):
                    relevant_found = True
                    break
        if not relevant_found:
            return original_severity

    try:
        original_index = severity_order.index(original_severity.lower())
    except ValueError:
        return original_severity

    risk_reduction = security_context.get("max_risk_reduction", 0.0)
    downgrade_steps = 0

    if risk_reduction >= 0.4:
        downgrade_steps = 2
    elif risk_reduction >= 0.3:
        downgrade_steps = 1

    new_index = min(len(severity_order) - 1, original_index + downgrade_steps)
    return severity_order[new_index]


def generate_framework_mitigation_report(
    security_context: Dict[str, Any],
    vuln_type: str = "",
    original_severity: str = "",
    mitigated_severity: str = ""
) -> str:
    """
    生成框架缓解措施报告文本。

    Args:
        security_context: detect_security_annotations_in_context 的返回值
        vuln_type: 漏洞类型
        original_severity: 原始严重级别
        mitigated_severity: 缓解后的严重级别

    Returns:
        框架缓解措施报告文本
    """
    if not security_context.get("annotations_found"):
        return ""

    report_parts = []
    report_parts.append("=" * 60)
    report_parts.append("【框架缓解措施分析】")
    report_parts.append("=" * 60)

    report_parts.append(f"\n检测到 {security_context['protection_layers']} 层安全保护:")
    for ann in security_context["annotations_found"]:
        if ann in SECURITY_ANNOTATION_WEIGHTS:
            info = SECURITY_ANNOTATION_WEIGHTS[ann]
            report_parts.append(f"  - {ann}: {info['description']}")
            report_parts.append(f"    风险降低系数: {info['risk_reduction']}")
            mitigates = info.get("mitigates", [])
            if mitigates:
                report_parts.append(f"    缓解风险: {', '.join(mitigates)}")

    report_parts.append(f"\n攻击难度评分: {security_context['attack_difficulty_score']:.2f} (0=易, 1=难)")

    if original_severity and mitigated_severity and original_severity != mitigated_severity:
        report_parts.append(f"\n严重级别调整: {original_severity.upper()} -> {mitigated_severity.upper()}")
        report_parts.append(f"调整原因: 框架安全注解提供有效缓解")

    if vuln_type:
        vuln_type_lower = vuln_type.lower()
        applicable_mitigations = []
        for ann in security_context["annotations_found"]:
            if ann in SECURITY_ANNOTATION_WEIGHTS:
                mitigates_list = SECURITY_ANNOTATION_WEIGHTS[ann].get("mitigates", [])
                if any(m in vuln_type_lower for m in mitigates_list):
                    applicable_mitigations.append(ann)
        if applicable_mitigations:
            report_parts.append(f"\n直接缓解当前漏洞的注解: {', '.join(applicable_mitigations)}")

    report_parts.append("")
    return "\n".join(report_parts)


FRAMEWORK_CONFIG_SECURITY_PATTERNS: Dict[str, Dict] = {
    "spring_security_config": {
        "files": ["application.yml", "application.yaml", "application.properties"],
        "regex": r'(?:security|csrf|cors|headers|session-management|authentication|authorization)',
        "description": "Spring Boot安全配置项",
        "risk_level": "info",
        "framework": "spring-boot",
    },
    "spring_actuator_exposure": {
        "files": ["application.yml", "application.yaml", "application.properties"],
        "regex": r'management\.endpoints\.web\.exposure\.include\s*[=:]\s*["\']?\*["\']?',
        "description": "Spring Boot Actuator所有端点暴露，可能导致信息泄露",
        "risk_level": "high",
        "framework": "spring-boot",
    },
    "spring_debug_enabled": {
        "files": ["application.yml", "application.yaml", "application.properties"],
        "regex": r'(?:debug\s*[=:]\s*true|server\.error\.include-(?:stacktrace|exception)\s*[=:]\s*always)',
        "description": "Spring Boot调试模式或错误信息泄露配置",
        "risk_level": "medium",
        "framework": "spring-boot",
    },
    "quarkus_config_property": {
        "files": ["application.properties", "application.yml"],
        "regex": r'io\.quarkus\.ConfigProperty|@ConfigProperty',
        "description": "Quarkus配置属性注入",
        "risk_level": "info",
        "framework": "quarkus",
    },
    "micronaut_value_injection": {
        "files": ["application.yml", "application.yaml"],
        "regex": r'@Value\s*\(',
        "description": "Micronaut值注入注解",
        "risk_level": "info",
        "framework": "micronaut",
    },
}


def detect_config_security_issues(file_path: str, content: str) -> List[Dict[str, Any]]:
    """
    检测框架配置文件中的安全配置问题。

    Args:
        file_path: 配置文件路径
        content: 文件内容

    Returns:
        安全配置问题列表
    """
    findings: List[Dict[str, Any]] = []
    file_basename = os.path.basename(str(file_path)) if file_path else ""
    content_lower = content.lower()

    for name, info in FRAMEWORK_CONFIG_SECURITY_PATTERNS.items():
        matching_files = info.get("files", [])
        if file_basename and file_basename.lower() not in [f.lower() for f in matching_files]:
            continue

        pattern = info.get("regex", "")
        if not pattern:
            continue

        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                "type": f"config_{name}",
                "severity": info.get("risk_level", "info"),
                "description": info["description"],
                "file": file_path,
                "line": line_num,
                "framework": info.get("framework", "general"),
                "recommendation": f"审查{name}配置是否符合安全最佳实践",
            })

    return findings
