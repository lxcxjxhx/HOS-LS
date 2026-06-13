"""代码漏洞信号扫描模块

收集代码中的漏洞模式匹配信号，作为AI分析的输入线索。
本模块不直接报告漏洞发现，仅收集可疑信号供AI分析器确认。

支持的信号类型:
- SQL注入信号 (${} in MyBatis Mapper, 字符串拼接等)
- 命令注入信号 (Runtime.exec, os.system等)
- 路径遍历信号 (File路径拼接等)
- 硬编码凭证信号
- 不安全随机数信号
- 弱加密信号
- 其他模式信号

信号仅作为AI分析的参考线索，最终判定由AI分析器完成。
"""

import re
import shutil
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from src.utils.logger import get_logger

logger = get_logger(__name__)


class CodeVulnLevel(Enum):
    """漏洞级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CodeVulnFinding:
    """代码漏洞发现（仅由AI分析器创建，不再由模式匹配直接产生）"""
    file_path: str
    line_number: int
    code_snippet: str
    vuln_type: str
    level: CodeVulnLevel
    description: str
    remediation: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnSignal:
    """漏洞模式匹配信号 - 仅作为AI分析的输入线索

    信号不代表确认的漏洞，需要AI分析器进一步确认。
    如果AI分析器不可用，信号应被忽略，不应直接报告。
    """
    file_path: str
    line_number: int
    code_snippet: str
    signal_type: str       # 对应原vuln_type，如 mybatis_dollar_brace_sql
    description: str       # 模式描述
    matched_text: str      # 实际匹配到的文本
    context: Dict[str, Any] = field(default_factory=dict)  # 上下文信息

    # 向后兼容属性：供使用 CodeVulnFinding 的旧代码访问
    @property
    def vuln_type(self) -> str:
        """兼容属性，映射到 signal_type"""
        return self.signal_type

    @property
    def level(self) -> CodeVulnLevel:
        """兼容属性，从 context 中获取 suggested_level"""
        level_str = self.context.get('suggested_level', 'medium')
        try:
            return CodeVulnLevel(level_str)
        except ValueError:
            return CodeVulnLevel.MEDIUM

    @property
    def remediation(self) -> str:
        """兼容属性，从 context 中获取 suggested_remediation"""
        return self.context.get('suggested_remediation', '')


class ContextAnalyzer:
    """上下文分析器 - 收集上下文信息供AI分析参考

    本类不再直接判定误报或跳过分析，而是收集上下文信息
    （如框架保护、输入校验、内部方法调用等）供AI分析器综合判断。
    所有模式匹配仅作为"上下文线索"，不用于直接 dismiss 任何发现。
    """

    NON_SECURITY_PATTERNS = [
        (r'NullPointerException|空指针异常|潜在.*空指针', '非安全漏洞', '代码质量问题'),
        (r'未使用.*参数|unused.*parameter|unused.*argument', '非安全漏洞', '代码质量问题'),
        (r'未使用的Throwable|unused.*Throwable', '非安全漏洞', '代码质量问题'),
        (r'接口.*缺少实现|interface.*implementation', '非安全漏洞', '代码设计问题'),
        (r'方法签名.*未定义|method.*not.*defined', '非安全漏洞', '代码设计问题'),
        (r'日志级别|logging.*level', '非安全漏洞', '配置问题'),
        (r'硬编码.*路径|hardcoded.*path', '非安全漏洞', '代码质量问题'),
    ]

    MYBATIS_SAFE_CONTEXT_PATTERNS = [
        r'propertyName.*Map\.get',
        r'propertyName.*from.*enum',
        r'propertyName.*Constants',
        r'columnName.*enumMap',
        r'\w+\.get\(\s*["\']?\w+["\']?\s*\)',  # Map.get("key")
        r'BeanUtils\.copyProperties',
        r'ObjectMapper',
    ]

    SQL_CONTEXT_KEYWORDS = [
        'select', 'insert', 'update', 'delete', 'where', 'from', 'join',
        'order by', 'group by', 'having', 'limit', 'having'
    ]

    MYBATIS_LIKELY_SAFE_PATTERNS = [
        r'findByProperty',  # 上下文线索：可能是内部方法
        r'exists',  # 上下文线索：可能是内部方法
        r'getAll',  # 上下文线索：查询所有
        r'count',  # 上下文线索：计数
        r'getById',  # 上下文线索：ID查询
        r'getOne',  # 上下文线索：单条查询
    ]

    SQL_INJECTION_SAFE_PATTERNS = [
        r'String\.static\(\s*["\']',
        r'"[^"]*"\s*\+\s*"[^\n]*"',
        r'\.intern\(\)',
    ]

    SQL_INJECTION_FALSE_POSITIVE_PATTERNS = [
        (r'ORDER\s+BY\s+\$\{', 'ORDER BY 使用 ${} 但字段来自内部枚举映射'),
        (r'LIMIT\s+\$\{', 'LIMIT 使用 ${} 但值来自固定配置'),
        (r'IN\s*\(\$\{', 'IN 子句使用 ${} 但来自内部方法'),
    ]

    INTERNAL_METHOD_PATTERNS = [
        r'\.getId\(\)',
        r'\.getCode\(\)',
        r'\.getName\(\)',
        r'\.getType\(\)',
        r'\.getStatus\(\)',
        r'\.getValue\(\)',
        r'\.getKey\(\)',
        r'\.toString\(\)',
        r'String\.valueOf\(',
        r'new\s+String\(',
        r'\.static\(',
        r'enum\.',
        r'Enum\.',
        r'Constants\.',
        r'Config\.',
    ]

    VALIDATION_PATTERNS = [
        r'@NotNull',
        r'@NotBlank',
        r'@NotEmpty',
        r'@Pattern',
        r'@Size',
        r'@Min',
        r'@Max',
        r'@Valid',
        r'validate',
        r'check',
        r'isValid',
        r'assert',
    ]

    SAFE_COLUMN_SOURCES = [
        r'enumMap\.get',
        r'columns\.get',
        r'fieldMap\.get',
        r'Map\.get\("',
        r'StringUtils\.',
        r'CollUtils\.',
        r'ListUtils\.',
        r'CollectionUtils\.',
    ]

    def __init__(self):
        self._safe_patterns = [re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_SAFE_PATTERNS]
        self._internal_patterns = [re.compile(p, re.IGNORECASE) for p in self.INTERNAL_METHOD_PATTERNS]
        self._validation_patterns = [re.compile(p, re.IGNORECASE) for p in self.VALIDATION_PATTERNS]
        self._safe_column_patterns = [re.compile(p, re.IGNORECASE) for p in self.SAFE_COLUMN_SOURCES]
        self._non_security_patterns = [(re.compile(p, re.IGNORECASE), reason, category) for p, reason, category in self.NON_SECURITY_PATTERNS]
        self._mybatis_safe_patterns = [re.compile(p, re.IGNORECASE) for p in self.MYBATIS_SAFE_CONTEXT_PATTERNS]
        self._mybatis_likely_safe_patterns = [re.compile(p, re.IGNORECASE) for p in self.MYBATIS_LIKELY_SAFE_PATTERNS]

    def is_non_security_issue(self, description: str, title: str = "") -> Tuple[bool, str, str]:
        """检查是否为非安全漏洞

        Args:
            description: 漏洞描述
            title: 漏洞标题

        Returns:
            (is_non_security, reason, category) 元组
        """
        combined_text = f"{title} {description}".lower()

        for pattern, reason, category in self._non_security_patterns:
            if pattern.search(combined_text):
                return True, reason, category

        return False, "", ""

    def analyze_mybatis_dollar_brace_context(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        surrounding_lines: List[str] = None
    ) -> Dict[str, Any]:
        """分析 MyBatis ${} 拼接的上下文，收集线索供AI参考

        注意：本方法不再直接判定 is_likely_safe 或调整 confidence，
        而是收集上下文线索（如参数来源、校验逻辑等）供AI分析器判断。

        Returns:
            包含上下文线索的字典（is_framework_protected, has_validation,
            is_internal_source, safe_pattern_indicators 等）
        """
        result = {
            'analysis_type': 'mybatis_dollar_brace',
            'framework_indicators': [],
            'validation_indicators': [],
            'internal_source_indicators': [],
            'safe_pattern_indicators': [],
        }

        full_context = code_snippet
        if surrounding_lines:
            full_context = '\n'.join(surrounding_lines)

        for safe_pattern in self._mybatis_safe_patterns:
            if safe_pattern.search(full_context):
                result['safe_pattern_indicators'].append('内部Map/Bean映射模式')

        method_name_match = re.search(r'(findBy\w+|exists|getAll|count|getById|getOne)', file_path)
        if method_name_match:
            method_name = method_name_match.group(1)
            for likely_safe_pattern in self._mybatis_likely_safe_patterns:
                if likely_safe_pattern.search(method_name):
                    result['internal_source_indicators'].append(f'方法名 {method_name} 暗示内部查询')

        if 'propertyName' in code_snippet and ('enumMap' in full_context or 'getColumns()' in full_context):
            result['internal_source_indicators'].append('propertyName 来自列名映射')

        for validation_pattern in self._validation_patterns:
            if validation_pattern.search(full_context):
                result['validation_indicators'].append('发现输入校验逻辑')

        return result

    def analyze_sql_injection_context(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        surrounding_lines: List[str] = None
    ) -> Dict[str, Any]:
        """分析 SQL 注入发现的上下文，收集线索供AI参考

        注意：本方法不再直接判定 is_false_positive 或调整 confidence，
        而是收集上下文信息（框架类型、参数化查询特征、内部来源等）供AI分析。

        Returns:
            包含上下文线索的字典（framework_type, parameterized_indicators,
            internal_source_indicators, validation_indicators 等）
        """
        result = {
            'analysis_type': 'sql_injection_context',
            'framework_type': None,
            'parameterized_indicators': [],
            'internal_source_indicators': [],
            'validation_indicators': [],
            'safe_context_hints': [],
            'string_concat_analysis': {},
        }

        file_path_str = str(file_path)
        code_snippet_str = str(code_snippet)

        if surrounding_lines:
            full_context = '\n'.join(surrounding_lines)
        else:
            full_context = code_snippet_str

        if self.is_framework_security_class(file_path_str):
            result['framework_type'] = 'framework_security_class'
            result['safe_context_hints'].append('框架层安全类，可能内置SQL防护')

        if re.search(r'#\{[^}]+\}', code_snippet_str) and not re.search(r'\$\{[^}]+\}', code_snippet_str):
            result['parameterized_indicators'].append('MyBatis预编译参数 #{}')

        jpa_criteria_keywords = ['CriteriaBuilder', 'CriteriaQuery', 'Root', 'EntityManager']
        jpa_safe_methods = ['cb.equal(', 'cb.like(', 'cb.greaterThan(', 'cb.lessThan(', 'cb.and(', 'cb.or(', 'cb.not(']
        if any(kw in full_context for kw in jpa_criteria_keywords) and any(m in full_context for m in jpa_safe_methods):
            result['framework_type'] = 'jpa_criteria'
            result['parameterized_indicators'].append('JPA Criteria API参数化查询')

        hibernate_keywords = ['Criteria', 'Restrictions', 'session.createCriteria(']
        if any(kw in full_context for kw in hibernate_keywords):
            result['framework_type'] = 'hibernate_criteria'
            result['parameterized_indicators'].append('Hibernate Criteria API参数化查询')

        mybatis_plus_wrapper_keywords = ['QueryWrapper', 'LambdaQueryWrapper', 'QueryChainWrapper', 'LambdaQueryChainWrapper']
        mybatis_plus_safe_methods = ['.eq(', '.ne(', '.gt(', '.ge(', '.lt(', '.le(', '.like(', '.notLike(', '.likeLeft(', '.likeRight(', '.isNull(', '.isNotNull(', '.in(', '.notIn(', '.inSql(', '.notInSql(', '.between(', '.groupBy(', '.orderByAsc(', '.orderByDesc(', '.having(', '.exists(', '.notExists(', '.apply(', '.last(']
        if any(kw in full_context for kw in mybatis_plus_wrapper_keywords) and any(m in full_context for m in mybatis_plus_safe_methods):
            result['framework_type'] = 'mybatis_plus'
            result['parameterized_indicators'].append('MyBatis-Plus Wrapper参数化查询')

        spring_data_jpa_safe_patterns = [
            r'@Query\s*\(\s*["\'].*#\{#entityName\}.*["\']',
            r'JpaSpecificationExecutor',
            r'Specification<',
            r'Root<',
            r'CriteriaBuilder',
            r'CriteriaQuery',
            r'CriteriaUpdate',
            r'CriteriaDelete',
            r'EntityManager\.createQuery',
            r'EntityManager\.createNamedQuery',
            r'TypedQuery<',
        ]
        if any(re.search(p, full_context, re.IGNORECASE) for p in spring_data_jpa_safe_patterns):
            safe_methods_jpa = ['.equal(', '.like(', '.greaterThan(', '.lessThan(', '.between(', '.in(', '.isNotNull(', '.isTrue(', '.isFalse(', '.isNull(', '.notEqual(', '.greaterThanOrEqualTo(', '.lessThanOrEqualTo(', '.asc(', '.desc(']
            if any(m in full_context for m in safe_methods_jpa):
                result['framework_type'] = 'spring_data_jpa'
                result['parameterized_indicators'].append('Spring Data JPA参数化查询')

        stored_proc_patterns = [
            r'CallableStatement',
            r'prepareCall\s*\(',
            r'\bCALL\s+',
            r'\bEXEC\s+',
            r'{\s*call\s+',
            r'createStoredProcedureCall',
            r'StoredProcedureQuery',
        ]
        for sp_pattern in stored_proc_patterns:
            if re.search(sp_pattern, full_context, re.IGNORECASE):
                param_patterns = [r'\?', r'#\{', r':\w+', r'setString\s*\(', r'setInt\s*\(', r'setLong\s*\(', r'setObject\s*\(', r'withParameter\s*\(']
                if any(re.search(pp, full_context) for pp in param_patterns):
                    result['framework_type'] = 'stored_procedure'
                    result['parameterized_indicators'].append('存储过程参数化调用')

        concat_only_literals = re.search(r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']', code_snippet_str)
        if concat_only_literals:
            test_clean = re.sub(r'["\'][^"\']*["\'](?:\s*\+\s*["\'][^"\']*["\'])*', '', code_snippet_str)
            test_clean = re.sub(r'\s+', '', test_clean)
            test_clean = test_clean.replace(';', '').replace('(', '').replace(')', '')
            if not test_clean or test_clean.isalpha() or re.match(r'^[a-zA-Z.]*$', test_clean):
                result['string_concat_analysis'] = {'only_literals': True, 'reason': '仅涉及字符串字面量拼接'}

        if 'StringLiteral' in code_snippet_str or 'static String' in code_snippet_str:
            result['safe_context_hints'].append('使用了字符串字面量')

        for pattern in self._safe_patterns:
            if pattern.search(code_snippet_str):
                result['safe_context_hints'].append('使用了安全的字符串拼接方式')

        for internal_pattern in self._internal_patterns:
            if internal_pattern.search(code_snippet_str):
                result['internal_source_indicators'].append('参数来自内部方法调用')

        for safe_column_pattern in self._safe_column_patterns:
            if safe_column_pattern.search(code_snippet_str):
                result['internal_source_indicators'].append('列名来自安全的内部映射')

        if surrounding_lines:
            for validation_pattern in self._validation_patterns:
                if validation_pattern.search(full_context):
                    result['validation_indicators'].append('发现参数校验逻辑')

        if 'session' in code_snippet_str.lower() or 'request' in code_snippet_str.lower():
            result['safe_context_hints'].append('涉及session/request上下文')

        return result

    def analyze_permission_context(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        surrounding_lines: List[str] = None
    ) -> Dict[str, Any]:
        """分析权限控制的上下文，收集线索供AI参考

        注意：本方法不再直接判定 is_likely_covered，
        而是收集权限配置线索供AI分析器判断。

        Returns:
            包含权限线索的字典（framework_protected, permission_indicators等）
        """
        result = {
            'analysis_type': 'permission_context',
            'framework_protected': False,
            'framework_protected_reason': None,
            'permission_indicators': [],
        }

        file_path_str = str(file_path)

        if self.is_framework_security_class(file_path_str):
            result['framework_protected'] = True
            result['framework_protected_reason'] = '框架层安全类，可能内置安全防护'

        if surrounding_lines:
            controller_result = self.analyze_controller_permission_context(
                file_path_str,
                line_number,
                surrounding_lines
            )
            if controller_result.get('has_permission_annotation'):
                result['permission_indicators'].append(controller_result.get('reason', ''))

        permission_indicators = [
            r'@PreAuthorize',
            r'@Secured',
            r'@RolesAllowed',
            r'hasRole',
            r'hasAuthority',
            r'permitAll\(\)',
            r'denyAll\(\)',
            r'securityInterceptor',
            r'WebSecurityConfigurerAdapter',
            r'SecurityConfig',
        ]

        if surrounding_lines:
            full_context = '\n'.join(surrounding_lines)
            for indicator in permission_indicators:
                if re.search(indicator, full_context, re.IGNORECASE):
                    result['permission_indicators'].append(f'发现权限控制配置: {indicator}')

        return result

    def analyze_deserialization_context(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        surrounding_lines: List[str] = None
    ) -> Dict[str, Any]:
        """分析反序列化漏洞的上下文，收集线索供AI参考

        注意：本方法不再直接判定 is_external_controllable，
        而是收集数据源线索供AI分析器判断。

        Returns:
            包含数据源线索的字典（internal_source_indicators, external_indicators等）
        """
        result = {
            'analysis_type': 'deserialization_context',
            'internal_source_indicators': [],
            'external_source_indicators': [],
        }

        internal_sources = [
            r'InternalRedisTemplate',
            r'内部服务',
            r'internal',
            r'from\s+Redis',
            r'getRedisTemplate',
            r'redisTemplate\.opsForValue',
        ]

        if surrounding_lines:
            full_context = '\n'.join(surrounding_lines)
            for source in internal_sources:
                if re.search(source, full_context, re.IGNORECASE):
                    result['internal_source_indicators'].append(f'数据可能来源于内部Redis: {source}')

        external_indicators = [
            r'@RequestBody',
            r'request\.body',
            r'HTTP.*request',
            r'user.*input',
        ]

        for indicator in external_indicators:
            if re.search(indicator, code_snippet, re.IGNORECASE):
                result['external_source_indicators'].append(f'外部可控输入指标: {indicator}')

        return result

    def analyze_controller_permission_context(
        self,
        file_path: str,
        line_number: int,
        surrounding_lines: List[str]
    ) -> Dict[str, Any]:
        """分析Controller层权限上下文，收集线索供AI参考

        Returns:
            包含权限注解线索的字典（has_permission_annotation, reason等）
        """
        result = {
            'analysis_type': 'controller_permission',
            'has_permission_annotation': False,
            'reason': None,
        }

        permission_annotations = [
            r'@PreAuthorize\([^)]*\)',
            r'@Secured\([^)]*\)',
            r'@RolesAllowed\([^)]*\)',
            r'@PermitAll',
            r'@DenyAll',
        ]

        if surrounding_lines:
            full_context = '\n'.join(surrounding_lines)

            for pattern in permission_annotations:
                if re.search(pattern, full_context, re.IGNORECASE):
                    result['has_permission_annotation'] = True
                    result['reason'] = f'发现权限注解: {pattern}'
                    return result

        return result

    def is_framework_security_class(
        self,
        file_path: str,
        class_name: str = None
    ) -> bool:
        """判断是否为框架层安全类（上下文线索，非最终判定）

        框架层安全类通常是Spring Security等框架自带的，
        这些类内部可能已有安全防护。此信息作为上下文线索供AI参考，
        不用于直接跳过分析。
        """
        framework_classes = [
            r'JdbcClientDetailsService',
            r'JdbcAuthenticationManager',
            r'DefaultSecurityFilterChain',
            r'SecurityConfigurerAdapter',
            r'AuthorizationServerConfigurerAdapter',
            r'ResourceServerConfigurerAdapter',
        ]

        if class_name:
            for pattern in framework_classes:
                if re.search(pattern, class_name, re.IGNORECASE):
                    return True

        file_path_str = str(file_path)
        for pattern in framework_classes:
            if re.search(pattern, file_path_str, re.IGNORECASE):
                return True

        return False


class InputTracer:
    """输入追踪器 - 用于追踪用户输入是否可达"""

    def __init__(self):
        pass

    def trace_input_controllability(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str
    ) -> Dict[str, Any]:
        """追踪输入可控性

        Returns:
            包含 is_user_controllable, confidence 等字段的字典
        """
        result = {
            'is_user_controllable': False,
            'confidence': 1.0,
            'input_source': None,
            'trace_type': 'input_controllability'
        }

        user_input_indicators = [
            'getParameter', 'getQueryString', 'getHeader',
            'request.body', 'request.get', '@RequestParam',
            'requestParam', 'RequestBody', 'cookie', 'session'
        ]

        for indicator in user_input_indicators:
            if indicator in code_snippet:
                result['is_user_controllable'] = True
                result['input_source'] = indicator
                result['confidence'] = 0.9
                return result

        safe_indicators = [
            'String.valueOf', 'String.static', 'new String',
            'intern()', '.trim()'
        ]

        for safe in safe_indicators:
            if safe in code_snippet:
                result['confidence'] = 0.5

        return result


class CodeVulnPatterns:
    """代码漏洞检测模式"""

    SQL_INJECTION_PATTERNS = [
        (r'\$\{[^}]+\}', 'mybatis_dollar_brace_sql', 'MyBatis ${} 动态SQL拼接'),
        (r'\${(?!\{)[^}]+}', 'mybatis_dollar_brace_sql', 'MyBatis ${} 动态SQL拼接'),
        (r'execute\s*\(\s*["\'].*\+.*["\']', 'sql_string_concat', 'SQL语句字符串拼接'),
        (r'cursor\.execute\s*\(\s*["\'].*\%s.*\+', 'python_sql_concat', 'Python SQL字符串拼接'),
        (r'query\s*\(\s*["\'].*\.format\(', 'python_sql_format', 'Python SQL .format()拼接'),
    ]

    COMMAND_INJECTION_PATTERNS = [
        (r'Runtime\s*\.\s*exec\s*\(', 'java_runtime_exec', 'Java Runtime.exec()调用'),
        (r'ProcessBuilder\s*\(', 'java_processbuilder', 'Java ProcessBuilder使用'),
        (r'os\s*\.\s*system\s*\(', 'python_os_system', 'Python os.system()调用'),
        (r'subprocess\s*\.\s*(call|run|Popen)\s*\(.*shell\s*=\s*True', 'python_subprocess_shell', 'Python subprocess shell=True'),
        (r'exec\s*\(.*\+', 'python_exec_concat', 'Python exec字符串拼接'),
        (r'eval\s*\(.*\+', 'python_eval_concat', 'Python eval字符串拼接'),
    ]

    PATH_TRAVERSAL_PATTERNS = [
        (r'new\s+File\s*\(\s*[^,]+\s*,\s*[^,]+\s*\)', 'java_file_path_join', 'Java File路径拼接'),
        (r'Paths\s*\.\s*get\s*\([^)]+\+[^)]+\)', 'java_paths_get_concat', 'Java Paths.get()字符串拼接'),
        (r'open\s*\([^)]*\+[^)]*\)', 'python_file_open_concat', 'Python文件open()字符串拼接'),
        (r'FileInputStream\s*\([^)]+\+[^)]+\)', 'java_fileinputstream_concat', 'Java FileInputStream路径拼接'),
    ]

    HARDCODED_SECRET_PATTERNS = [
        # Generic credential patterns removed - covered by Semgrep
        # Framework-specific patterns preserved below:
    ]

    SEMGREP_COVERED_PATTERNS_COUNT = 7
    FRAMEWORK_SPECIFIC_PATTERNS_COUNT = 0

    DEFAULT_PASSWORD_PATTERNS = [
        (r'=?\s*["\']123456["\']', 'default_password_123456', '默认密码123456'),
        (r'=?\s*["\']password["\']', 'default_password_password', '默认密码password'),
        (r'=?\s*["\']admin["\']', 'default_password_admin', '默认密码admin'),
        (r'=?\s*["\']000000["\']', 'default_password_000000', '默认密码000000'),
    ]

    INSECURE_RANDOM_PATTERNS = [
        (r'Math\.random\(\)', 'insecure_random_math', '使用Math.random()不安全随机数'),
        (r'System\.nanoTime\(\)', 'insecure_random_time', '使用System.nanoTime()不安全随机数'),
        (r'Random\.(nextInt|nextLong|nextBytes|nextDouble|nextFloat|nextGaussian)\s*\(', 'insecure_random_methods', '使用Random类不安全随机方法'),
        (r'new\s+Random\(\s*\)', 'insecure_random_instantiation', '使用Random类实例化不安全随机数'),
    ]

    WEAK_CRYPTO_PATTERNS = [
        (r'MD5(?=.*(?:hash|digest|encrypt|decrypt|getInstance|MessageDigest))', 'weak_hash_md5', '使用MD5哈希算法'),
        (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', 'weak_hash_md5', '使用MD5哈希算法'),
        (r'SHA1(?=.*(?:hash|digest|encrypt|decrypt|getInstance|MessageDigest))', 'weak_hash_sha1', '使用SHA1哈希算法'),
        (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', 'weak_hash_sha1', '使用SHA1哈希算法'),
        (r'Cipher\.getInstance\s*\(\s*["\']DES["\']', 'weak_cipher_des', '使用DES加密算法'),
        (r'Cipher\.getInstance\s*\(\s*["\']DESede["\']', 'weak_cipher_des', '使用3DES加密算法'),
        (r'DES\.new\s*\(', 'weak_cipher_des', '使用DES加密算法'),
        (r'DES3\.new\s*\(', 'weak_cipher_des', '使用3DES加密算法'),
        (r'from\s+Crypto\.Cipher\s+import\s+DES\b', 'weak_cipher_des', '使用DES加密算法'),
        (r'from\s+Crypto\.Cipher\s+import\s+DES3\b', 'weak_cipher_des', '使用3DES加密算法'),
        (r'RC4\.new\s*\(', 'weak_cipher_rc4', '使用RC4加密算法'),
        (r'random\.Random\s*\(', 'insecure_random_random', '使用random.Random不安全随机数'),
    ]

    INSECURE_REQUEST_PATTERNS = [
        (r'getHeader\s*\(\s*["\']userName["\']', 'insecure_header_username', '从请求头获取用户名'),
        (r'getHeader\s*\(\s*["\']userId["\']', 'insecure_header_userid', '从请求头获取用户ID'),
        (r'getHeader\s*\(\s*["\']token["\']', 'insecure_header_token', '从请求头获取令牌'),
    ]

    CSRF_PATTERNS = [
        (r'csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)', 'csrf_disabled', 'CSRF防护已禁用'),
        (r'\.\s*csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)', 'csrf_disabled', 'CSRF防护已禁用'),
    ]

    XSS_PATTERNS = [
        (r'innerHTML\s*=', 'xss_innerHTML', '使用innerHTML可能导致XSS'),
        (r'document\s*\.\s*write\s*\(', 'xss_document_write', '使用document.write可能导致XSS'),
        (r'unsafeReponse\.set', 'xss_unsafe_response', '设置不安全响应头'),
    ]

    FILE_UPLOAD_PATTERNS = [
        (r'MultipartFile', 'file_upload_endpoint', '文件上传接口'),
        (r'@PostMapping.*upload', 'file_upload_upload', '文件上传接口'),
        (r'@RequestParam\s*\(\s*["\']file["\']', 'file_upload_param', '文件上传参数'),
    ]

    SENSITIVE_PATH_HARDCODED = [
        (r'["\']\/home\/[^"\']+["\']', 'hardcoded_linux_path', '硬编码Linux路径'),
        (r'["\']C:\\[^"\']+["\']', 'hardcoded_windows_path', '硬编码Windows路径'),
        (r'["\']D:\\[^"\']+["\']', 'hardcoded_windows_path', '硬编码Windows路径'),
    ]

    FALSE_POSITIVE_PATTERNS = [
        re.compile(r'password\s*=\s*["\'](?:test|example|your_|changeme|xxx|placeholder|insert|TODO|FIXME|change.?me)', re.IGNORECASE),
        re.compile(r'password\s*=\s*["\']["\']', re.IGNORECASE),
        re.compile(r'@Value.*password', re.IGNORECASE),
        re.compile(r'\$\{.*password', re.IGNORECASE),
        re.compile(r'\$\{spring\.[^}]*\}', re.IGNORECASE),
        re.compile(r'\$\{env\.[^}]*\}', re.IGNORECASE),
        re.compile(r'\$\{DB_[^}]*\}', re.IGNORECASE),
        re.compile(r'#\{[^}]*\}', re.IGNORECASE),
        re.compile(r'secret\s*=\s*["\'](?:test|example|your_|changeme|xxx|placeholder)', re.IGNORECASE),
        re.compile(r'api[_-]?key\s*=\s*["\'](?:your_|example|test|placeholder|INSERT_|CHANGE_ME)', re.IGNORECASE),
        re.compile(r'token\s*=\s*["\'](?:your_|example|test|placeholder)', re.IGNORECASE),
    ]

    COMMENT_PATTERNS = [
        re.compile(r'^\s*//'),
        re.compile(r'^\s*/\*'),
        re.compile(r'^\s*\*'),
        re.compile(r'^\s*#\s+'),
        re.compile(r'^\s*<!--'),
    ]

    DEFAULT_PASSWORD_INDICATORS = [
        re.compile(r'(?:default|example|placeholder|demo|sample|template)', re.IGNORECASE),
    ]

    DEFAULT_VALUE_PASSWORD_PATTERNS = [
        re.compile(r'password\s*=\s*["\']["\']', re.IGNORECASE),
        re.compile(r'password\s*=\s*null', re.IGNORECASE),
        re.compile(r'password\s*=\s*""', re.IGNORECASE),
        re.compile(r'password\s*=\s*["\']changeme["\']', re.IGNORECASE),
        re.compile(r'password\s*=\s*["\']password["\']', re.IGNORECASE),
    ]

    TEST_CODE_INDICATORS = [
        re.compile(r'@Test', re.IGNORECASE),
        re.compile(r'@Test\b'),
        re.compile(r'test_method'),
        re.compile(r'def\s+test_'),
        re.compile(r'function\s+test'),
    ]

    # 以下映射仅作为AI分析器的"初始建议"和"修复模板"，AI可覆盖这些值
    VULN_LEVEL_MAP = {
        'mybatis_dollar_brace_sql': CodeVulnLevel.CRITICAL,
        'sql_string_concat': CodeVulnLevel.CRITICAL,
        'python_sql_concat': CodeVulnLevel.CRITICAL,
        'java_runtime_exec': CodeVulnLevel.CRITICAL,
        'java_processbuilder': CodeVulnLevel.HIGH,
        'python_os_system': CodeVulnLevel.HIGH,
        'python_subprocess_shell': CodeVulnLevel.HIGH,
        'python_exec_concat': CodeVulnLevel.CRITICAL,
        'python_eval_concat': CodeVulnLevel.CRITICAL,
        'hardcoded_password': CodeVulnLevel.CRITICAL,
        'hardcoded_secret': CodeVulnLevel.CRITICAL,
        'hardcoded_api_key': CodeVulnLevel.CRITICAL,
        'hardcoded_access_key': CodeVulnLevel.CRITICAL,
        'hardcoded_token': CodeVulnLevel.HIGH,
        'default_password_123456': CodeVulnLevel.HIGH,
        'default_password_password': CodeVulnLevel.HIGH,
        'default_password_admin': CodeVulnLevel.HIGH,
        'mybatis_dollar_brace_sql': CodeVulnLevel.CRITICAL,
        'java_file_path_join': CodeVulnLevel.HIGH,
        'java_paths_get_concat': CodeVulnLevel.HIGH,
        'python_file_open_concat': CodeVulnLevel.HIGH,
        'java_fileinputstream_concat': CodeVulnLevel.HIGH,
        'weak_hash_md5': CodeVulnLevel.HIGH,
        'weak_hash_sha1': CodeVulnLevel.MEDIUM,
        'weak_cipher_des': CodeVulnLevel.HIGH,
        'weak_cipher_rc4': CodeVulnLevel.HIGH,
        'insecure_random_random': CodeVulnLevel.MEDIUM,
        'insecure_random_math': CodeVulnLevel.MEDIUM,
        'insecure_random_time': CodeVulnLevel.MEDIUM,
        'insecure_random_methods': CodeVulnLevel.MEDIUM,
        'insecure_random_instantiation': CodeVulnLevel.MEDIUM,
        'insecure_header_username': CodeVulnLevel.MEDIUM,
        'insecure_header_userid': CodeVulnLevel.MEDIUM,
        'insecure_header_token': CodeVulnLevel.MEDIUM,
        'csrf_disabled': CodeVulnLevel.MEDIUM,
        'xss_innerHTML': CodeVulnLevel.HIGH,
        'xss_document_write': CodeVulnLevel.HIGH,
        'file_upload_endpoint': CodeVulnLevel.MEDIUM,
        'file_upload_upload': CodeVulnLevel.MEDIUM,
        'file_upload_param': CodeVulnLevel.MEDIUM,
        'hardcoded_linux_path': CodeVulnLevel.LOW,
        'hardcoded_windows_path': CodeVulnLevel.LOW,
    }

    REMEDIATION_MAP = {
        'mybatis_dollar_brace_sql': '使用 #{} 替代 ${} 进行SQL参数绑定',
        'sql_string_concat': '使用参数化查询替代字符串拼接',
        'python_sql_concat': '使用参数化查询替代字符串拼接',
        'python_sql_format': '使用参数化查询替代.format()拼接',
        'java_runtime_exec': '避免使用Runtime.exec()，使用ProcessBuilder并验证输入',
        'java_processbuilder': '验证所有输入参数，使用shlex.quote()转义',
        'python_os_system': '使用subprocess.run()并设置shell=False',
        'python_subprocess_shell': '设置shell=False，使用列表参数',
        'python_exec_concat': '避免使用exec()，使用安全的替代方案',
        'python_eval_concat': '避免使用eval()，使用安全的替代方案',
        'hardcoded_password': '使用环境变量或密钥管理服务存储密码',
        'hardcoded_secret': '使用环境变量或密钥管理服务存储密钥',
        'hardcoded_api_key': '使用环境变量存储API密钥',
        'hardcoded_access_key': '使用AWS Secrets Manager等密钥管理服务',
        'hardcoded_token': '使用OAuth流程动态获取令牌',
        'default_password_123456': '修改默认密码为强密码',
        'default_password_password': '修改默认密码为强密码',
        'default_password_admin': '修改默认密码为强密码',
        'java_file_path_join': '使用Paths.get()并验证路径',
        'java_paths_get_concat': '避免字符串拼接构建文件路径',
        'python_file_open_concat': '使用os.path.join()构建路径',
        'java_fileinputstream_concat': '验证并清理文件路径输入',
        'weak_hash_md5': '使用SHA-256或更强的哈希算法',
        'weak_hash_sha1': '使用SHA-256或更强的哈希算法',
        'weak_cipher_des': '使用AES加密算法',
        'weak_cipher_rc4': '使用安全的加密算法',
        'insecure_random_random': '使用secrets模块生成安全随机数',
        'insecure_random_math': '使用SecureRandom或secrets模块生成安全随机数',
        'insecure_random_time': '使用SecureRandom或secrets模块生成安全随机数',
        'insecure_random_methods': '使用SecureRandom或secrets模块生成安全随机数',
        'insecure_random_instantiation': '使用SecureRandom或secrets模块生成安全随机数',
        'insecure_header_username': '从Token解析获取用户名，不要从请求头',
        'insecure_header_userid': '从Token解析获取用户ID，不要从请求头',
        'insecure_header_token': '正确验证Token，不要信任未验证的请求头',
        'csrf_disabled': '启用CSRF防护保护应用',
        'xss_innerHTML': '使用textContent或对输入进行转义',
        'xss_document_write': '避免使用document.write()，使用textContent',
        'file_upload_endpoint': '验证文件类型和大小，存储到安全位置',
        'file_upload_upload': '验证上传文件的MIME类型和内容',
        'file_upload_param': '限制文件大小，验证文件类型',
        'hardcoded_linux_path': '使用配置文件或环境变量',
        'hardcoded_windows_path': '使用配置文件或环境变量',
    }

    @classmethod
    def get_all_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        patterns = []
        for pattern_str, name, desc in (
            cls.SQL_INJECTION_PATTERNS +
            cls.COMMAND_INJECTION_PATTERNS +
            cls.PATH_TRAVERSAL_PATTERNS +
            cls.HARDCODED_SECRET_PATTERNS +
            cls.DEFAULT_PASSWORD_PATTERNS +
            cls.INSECURE_RANDOM_PATTERNS +
            cls.WEAK_CRYPTO_PATTERNS +
            cls.INSECURE_REQUEST_PATTERNS +
            cls.CSRF_PATTERNS +
            cls.XSS_PATTERNS +
            cls.FILE_UPLOAD_PATTERNS +
            cls.SENSITIVE_PATH_HARDCODED
        ):
            patterns.append((re.compile(pattern_str, re.IGNORECASE), name, desc))
        return patterns


class CodeVulnScanner:
    """代码漏洞扫描器 - 收集信号供AI分析

    本扫描器不再直接报告漏洞发现。模式匹配仅用于收集可疑信号，
    信号需传递给AI分析器进行确认。如果AI分析器不可用，
    信号应被忽略，不应直接报告为漏洞。
    """

    CODE_EXTENSIONS = {
        '.java', '.py', '.js', '.ts', '.jsx', '.tsx', '.xml', '.go', '.rs', '.rb', '.php', '.c', '.cpp', '.h'
    }

    MYBATIS_EXTENSIONS = {'.xml'}

    FILE_CACHE_MAX_SIZE = 100 * 1024 * 1024

    def __init__(
        self,
        enable_verification: bool = True,
        project_root: str = "",
        nvd_db_path: str = None,
        hallucination_threshold: float = 0.2,
        scanner_threshold: float = 0.5
    ):
        """初始化代码漏洞扫描器

        Args:
            enable_verification: 是否启用验证流程
            project_root: 项目根目录
            nvd_db_path: NVD 数据库路径
            hallucination_threshold: 幻觉阈值
            scanner_threshold: 扫描器置信度阈值
        """
        self.patterns = CodeVulnPatterns.get_all_patterns()
        self.level_map = CodeVulnPatterns.VULN_LEVEL_MAP
        self.remediation_map = CodeVulnPatterns.REMEDIATION_MAP
        self.enable_verification = enable_verification
        self.project_root = project_root
        self.hallucination_threshold = hallucination_threshold
        self.scanner_threshold = scanner_threshold
        self._verification_adapter = None

        self._file_content_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_size = 0

        self._semgrep_available = self._detect_semgrep_availability()
        if self._semgrep_available:
            semgrep_count = CodeVulnPatterns.SEMGREP_COVERED_PATTERNS_COUNT
            framework_count = CodeVulnPatterns.FRAMEWORK_SPECIFIC_PATTERNS_COUNT
            logger.info(
                f"已启用 Semgrep，跳过 {semgrep_count} 条通用凭证规则，"
                f"保留 {framework_count} 条框架特有规则"
            )

        self._context_analyzer = ContextAnalyzer()
        self._input_tracer = InputTracer()

        if self.enable_verification:
            self._init_verification_adapter(nvd_db_path)

    @staticmethod
    def _detect_semgrep_availability() -> bool:
        """检测 Semgrep 是否可用"""
        return shutil.which("semgrep") is not None

    def _is_line_commented(self, line: str, all_lines: List[str], current_line: int) -> bool:
        """检测单行是否被注释"""
        stripped = line.strip()

        if stripped.startswith('//'):
            return True
        if stripped.startswith('/*') and stripped.endswith('*/'):
            return True
        if stripped.startswith('*'):
            if current_line > 0:
                prev_line = all_lines[current_line - 1].strip()
                if prev_line.startswith('/**'):
                    return True

        return False

    def _build_commented_method_index(self, lines: List[str]) -> Dict[int, bool]:
        """构建被注释方法行的索引

        Returns:
            Dict[int, bool]: key 是方法定义行号，value True 表示该方法被注释
        """
        result = {}
        method_modifiers = ['public', 'private', 'protected', 'def ', 'function ', 'class ']

        for i, line in enumerate(lines):
            stripped = line.strip()

            if stripped.startswith('//') and any(mod in stripped for mod in method_modifiers):
                for j in range(i + 1, len(lines)):
                    next_line = lines[j].strip()
                    if next_line.startswith('//'):
                        continue
                    if any(mod in next_line for mod in method_modifiers):
                        result[j + 1] = True
                        break

        return result

    def _is_method_accessible(
        self,
        file_path: str,
        line_number: int,
        all_lines: List[str],
        commented_method_lines: Dict[int, bool]
    ) -> bool:
        """检测方法是否可访问（未被注释）

        检查方法定义前是否有注释前缀，如：
        // @GetMapping("/login")
        // public R login(...)

        如果是注释掉的方法，返回 False
        """
        if line_number in commented_method_lines:
            return False

        method_modifiers = ['public ', 'private ', 'protected ', 'def ', 'function ']

        for i in range(line_number - 1, max(0, line_number - 20), -1):
            prev_line = all_lines[i].strip()

            if any(modifier in prev_line for modifier in method_modifiers):
                for j in range(i + 1, line_number - 1):
                    check_line = all_lines[j].strip()
                    if check_line.startswith('//'):
                        return False
                return True

        return True

    def _analyze_signal_context(self, signal: VulnSignal, all_lines: List[str] = None) -> Dict[str, Any]:
        """分析信号的上下文，收集线索供AI参考

        Args:
            signal: 漏洞信号
            all_lines: 文件的所有行（用于上下文分析）

        注意：本方法不再判定 is_likely_false_positive 或调整 confidence，
        而是收集上下文线索供AI分析器综合判断。
        """
        result = {}

        surrounding_lines = None
        if all_lines and signal.line_number > 0:
            start = max(0, signal.line_number - 30)
            end = min(len(all_lines), signal.line_number + 5)
            surrounding_lines = all_lines[start:end]

        if signal.signal_type in ['mybatis_dollar_brace_sql', 'sql_string_concat', 'python_sql_concat', 'python_sql_format']:
            if signal.signal_type == 'mybatis_dollar_brace_sql' and hasattr(self._context_analyzer, 'analyze_mybatis_dollar_brace_context'):
                context = self._context_analyzer.analyze_mybatis_dollar_brace_context(
                    signal.file_path,
                    signal.line_number,
                    signal.code_snippet,
                    surrounding_lines
                )
                result['mybatis_context'] = context
            else:
                context = self._context_analyzer.analyze_sql_injection_context(
                    signal.file_path,
                    signal.line_number,
                    signal.code_snippet,
                    surrounding_lines
                )
                result['sql_injection_context'] = context

        if signal.signal_type in ['hardcoded_permission', 'missing_permission_annotation', 'unauthorized_access']:
            context = self._context_analyzer.analyze_permission_context(
                signal.file_path,
                signal.line_number,
                signal.code_snippet,
                surrounding_lines
            )
            result['permission_context'] = context

        if signal.signal_type in ['jackson_deserialization', 'redis_deserialization', 'jdk_serialization']:
            context = self._context_analyzer.analyze_deserialization_context(
                signal.file_path,
                signal.line_number,
                signal.code_snippet,
                surrounding_lines
            )
            result['deserialization_context'] = context

        input_trace = self._input_tracer.trace_input_controllability(
            signal.file_path,
            signal.line_number,
            signal.code_snippet
        )
        if input_trace:
            result['input_trace'] = input_trace

        return result

    def _init_verification_adapter(self, nvd_db_path: str = None) -> None:
        """初始化验证适配器"""
        try:
            from src.analyzers.verification_adapter import VerificationAdapter
            self._verification_adapter = VerificationAdapter(
                project_root=self.project_root,
                nvd_db_path=nvd_db_path
            )
        except Exception as e:
            logger.warning(f"验证适配器初始化失败: {e}")
            self._verification_adapter = None

    def _evict_cache_if_needed(self) -> None:
        while self._cache_size > self.FILE_CACHE_MAX_SIZE and self._file_content_cache:
            oldest_key = min(self._file_content_cache, key=lambda k: self._file_content_cache[k]['timestamp'])
            self._cache_size -= self._file_content_cache[oldest_key]['size']
            del self._file_content_cache[oldest_key]

    def _read_file_with_cache(self, file_path: str) -> Optional[str]:
        file_path_str = str(file_path)
        if file_path_str in self._file_content_cache:
            entry = self._file_content_cache[file_path_str]
            entry['timestamp'] = time.time()
            return entry['content']

        try:
            with open(file_path_str, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.debug(f"无法读取文件 {file_path_str}: {e}")
            return None

        content_size = len(content.encode('utf-8'))
        self._file_content_cache[file_path_str] = {
            'content': content,
            'timestamp': time.time(),
            'size': content_size,
        }
        self._cache_size += content_size
        self._evict_cache_if_needed()
        return content

    def is_code_file(self, file_path: str) -> bool:
        path = Path(file_path)
        return path.suffix.lower() in self.CODE_EXTENSIONS

    def is_mybatis_mapper(self, file_path: str) -> bool:
        path = Path(file_path)
        if path.suffix.lower() == '.xml':
            path_str = str(path).lower()
            if 'mapper' in path_str or 'mybatis' in path_str or 'ibatis' in path_str:
                return True

            content = ''
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(2000)
            except Exception:
                pass

            content_lower = content.lower()

            if '<mapper' in content_lower or 'mybatis' in content_lower or 'ibatis' in content_lower:
                return True

            if any(tag in content_lower for tag in ['<select', '<insert', '<update', '<delete']) and any(keyword in content_lower for keyword in ['#{', '${', 'sqlsegment', 'ew.']):
                return True

        return False

    def scan_files(self, file_paths: List[str]) -> List[VulnSignal]:
        """扫描多个文件，收集所有信号"""
        all_signals = []
        for file_path in file_paths:
            if self.is_code_file(file_path) or self.is_mybatis_mapper(file_path):
                signals = self.scan_file(file_path)
                all_signals.extend(signals)
        return all_signals

    def scan_file(self, file_path: str, content: Optional[str] = None) -> List[VulnSignal]:
        """扫描文件，收集漏洞模式匹配信号（不直接创建漏洞发现）

        返回的信号仅作为AI分析的输入线索，不代表确认的漏洞。
        每个信号包含模式匹配信息和初步的上下文分析结果。
        如果AI分析器不可用，信号应被忽略，不应直接报告。
        """
        signals = []

        if content is None:
            content = self._read_file_with_cache(file_path)
            if content is None:
                return signals

        lines = content.split('\n')

        commented_method_lines = self._build_commented_method_index(lines)

        for line_num, line in enumerate(lines, start=1):
            original_line = line
            line = line.strip()
            if not line:
                continue

            if self._is_line_commented(line, lines, line_num):
                continue

            if not self._is_method_accessible(file_path, line_num, lines, commented_method_lines):
                continue

            for pattern, name, desc in self.patterns:
                match = pattern.search(original_line)
                if match:
                    file_path_str = str(file_path)

                    is_comment = False
                    for comment_pattern in CodeVulnPatterns.COMMENT_PATTERNS:
                        if comment_pattern.search(original_line):
                            is_comment = True
                            break
                    if is_comment:
                        continue

                    is_false_positive = False
                    if name in ['hardcoded_password', 'hardcoded_secret', 'hardcoded_api_key', 'hardcoded_token']:
                        for fp_pattern in CodeVulnPatterns.FALSE_POSITIVE_PATTERNS:
                            if fp_pattern.search(original_line):
                                is_false_positive = True
                                break
                    if is_false_positive:
                        continue

                    signal_meta: Dict[str, Any] = {
                        'is_test_code': False,
                        'is_comment_example': False,
                        'is_default_value': False,
                        'is_default_with_indicator': False,
                    }

                    if name in ['hardcoded_password', 'hardcoded_secret']:
                        for dv_pattern in CodeVulnPatterns.DEFAULT_VALUE_PASSWORD_PATTERNS:
                            if dv_pattern.search(original_line):
                                signal_meta['is_default_value'] = True
                                break

                    is_test_code = False
                    is_comment_example = False
                    if name in ['hardcoded_password', 'hardcoded_secret', 'hardcoded_api_key', 'hardcoded_token']:
                        file_path_lower = file_path_str.lower()
                        if '/test/' in file_path_lower or '\\test\\' in file_path_lower or file_path_lower.endswith('_test.py') or file_path_lower.endswith('.test.js') or file_path_lower.endswith('.spec.ts'):
                            is_test_code = True
                        else:
                            context_start = max(0, line_num - 30)
                            context_lines = lines[context_start:line_num]
                            for test_indicator in CodeVulnPatterns.TEST_CODE_INDICATORS:
                                if any(test_indicator.search(cl) for cl in context_lines):
                                    is_test_code = True
                                    break
                        stripped_line = original_line.strip()
                        if '//' in stripped_line or '/*' in stripped_line or '*' == stripped_line.lstrip()[:1]:
                            comment_part = stripped_line.split('//')[-1] if '//' in stripped_line else ''
                            if not comment_part:
                                comment_part = stripped_line.split('/*')[-1] if '/*' in stripped_line else ''
                            if any(kw in comment_part.lower() for kw in ['example', 'sample', 'demo', 'test', 'placeholder', 'xxx', 'todo']):
                                is_comment_example = True
                    signal_meta['is_test_code'] = is_test_code
                    signal_meta['is_comment_example'] = is_comment_example

                    is_default_with_indicator = False
                    if name.startswith('default_password'):
                        for indicator in CodeVulnPatterns.DEFAULT_PASSWORD_INDICATORS:
                            if indicator.search(original_line):
                                is_default_with_indicator = True
                                break
                    signal_meta['is_default_with_indicator'] = is_default_with_indicator

                    non_security_info = self._context_analyzer.is_non_security_issue(desc, name)
                    if non_security_info[0]:
                        signal_meta['is_non_security'] = True
                        signal_meta['non_security_reason'] = non_security_info[1]
                        signal_meta['non_security_category'] = non_security_info[2]

                    suggested_level = self.level_map.get(name, CodeVulnLevel.MEDIUM)
                    if is_default_with_indicator:
                        suggested_level = CodeVulnLevel.INFO
                    if signal_meta['is_default_value']:
                        if name == 'hardcoded_password':
                            suggested_level = CodeVulnLevel.MEDIUM
                        else:
                            suggested_level = CodeVulnLevel.LOW
                    if is_test_code:
                        if suggested_level in [CodeVulnLevel.CRITICAL, CodeVulnLevel.HIGH]:
                            suggested_level = CodeVulnLevel.MEDIUM
                        elif suggested_level == CodeVulnLevel.MEDIUM:
                            suggested_level = CodeVulnLevel.LOW
                    if is_comment_example:
                        if suggested_level in [CodeVulnLevel.CRITICAL, CodeVulnLevel.HIGH]:
                            suggested_level = CodeVulnLevel.MEDIUM
                        elif suggested_level == CodeVulnLevel.MEDIUM:
                            suggested_level = CodeVulnLevel.LOW
                    signal_meta['suggested_level'] = suggested_level.value

                    signal_meta['suggested_remediation'] = self.remediation_map.get(name, '进行安全修复')

                    if name.startswith('insecure_random'):
                        security_sensitive_keywords = [
                            'token', 'key', 'secret', 'salt', 'nonce', 'seed',
                            'password', 'session', 'auth', 'credential', 'iv',
                            'initializationVector', 'signature', 'signatureKey',
                            'SecureRandom', 'generateKey', 'generateToken',
                            'createSession', 'generateSalt', 'generateNonce'
                        ]
                        context_start = max(0, line_num - 20)
                        context_end = min(len(lines), line_num + 10)
                        nearby_context = '\n'.join(lines[context_start:context_end])
                        for kw in security_sensitive_keywords:
                            if kw.lower() in nearby_context.lower():
                                signal_meta['security_sensitive_context'] = True
                                signal_meta['sensitive_keyword'] = kw
                                break

                    signal = VulnSignal(
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=original_line.strip()[:200],
                        signal_type=name,
                        description=desc,
                        matched_text=match.group(0) if match else '',
                        context=signal_meta,
                    )

                    context_info = self._analyze_signal_context(signal, lines)
                    if context_info:
                        signal.context.update(context_info)

                    signals.append(signal)

        return signals

    def collect_signals_for_ai(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """收集所有信号并格式化为AI分析器的输入

        本方法将信号整理为AI可理解的格式，供AI分析器进行确认。
        如果AI分析器不可用，不应直接报告这些信号。

        Returns:
            信号列表，每个信号包含文件、行号、类型、匹配文本和上下文信息
        """
        all_signals = []
        for file_path in file_paths:
            if self.is_code_file(file_path) or self.is_mybatis_mapper(file_path):
                signals = self.scan_file(file_path)
                for s in signals:
                    all_signals.append({
                        'file_path': s.file_path,
                        'line_number': s.line_number,
                        'code_snippet': s.code_snippet,
                        'signal_type': s.signal_type,
                        'description': s.description,
                        'matched_text': s.matched_text,
                        'suggested_level': s.context.get('suggested_level', 'medium'),
                        'suggested_remediation': s.context.get('suggested_remediation', ''),
                        'context': s.context,
                    })
        return all_signals

    def scan_with_verification(
        self,
        file_paths: List[str],
        project_root: str = None,
        filter_hallucinations: bool = True
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """扫描并验证结果

        Args:
            file_paths: 文件路径列表
            project_root: 项目根目录
            filter_hallucinations: 是否过滤幻觉发现

        Returns:
            (验证后的发现列表, 验证统计)
        """
        root = project_root or self.project_root
        findings = self.scan_files(file_paths)

        if not findings:
            return [], {
                'total_findings': 0,
                'triple_verified': 0,
                'double_verified': 0,
                'single_verified': 0,
                'needs_review': 0,
                'potential_hallucination': 0,
                'hallucinations_filtered': 0,
                'average_confidence': 0.0,
            }

        if self.enable_verification and self._verification_adapter:
            verified_findings, stats = self._verification_adapter.verify_scanner_results(
                findings,
                scanner_name='CodeVulnScanner',
                project_root=root,
                filter_hallucinations=filter_hallucinations,
                hallucination_threshold=self.hallucination_threshold,
                scanner_threshold=self.scanner_threshold
            )
            return verified_findings, stats.to_dict()

        return [
            {
                'id': f"code_vuln_{f.file_path}_{f.line_number}",
                'rule_id': f.vuln_type,
                'rule_name': f.vuln_type,
                'severity': f.level.value if hasattr(f.level, 'value') else str(f.level),
                'description': f.description,
                'file_path': f.file_path,
                'line': f.line_number,
                'code_snippet': f.code_snippet,
                'fix_suggestion': f.remediation,
                'confidence': 0.5,
                'metadata': {
                    'source_scanner': 'CodeVulnScanner',
                    'vuln_type': f.vuln_type,
                }
            }
            for f in findings
        ], {
            'total_findings': len(findings),
            'triple_verified': 0,
            'double_verified': 0,
            'single_verified': 0,
            'needs_review': 0,
            'potential_hallucination': 0,
            'hallucinations_filtered': 0,
            'average_confidence': 0.5,
        }
