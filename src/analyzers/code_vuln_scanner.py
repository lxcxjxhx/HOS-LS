"""代码漏洞模式扫描模块

专门用于快速扫描代码文件中的常见漏洞模式，使用正则表达式匹配，速度快。
不需要AI分析，适用于Java、Python、JavaScript等语言的常见漏洞检测。

支持的漏洞类型:
- SQL注入 (${} in MyBatis Mapper)
- 硬编码凭证
- 敏感文件路径硬编码
- 不安全的随机数
- 弱加密算法
- 危险函数调用
"""

import re
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


@dataclass
class CodeVulnFinding:
    """代码漏洞发现"""
    file_path: str
    line_number: int
    code_snippet: str
    vuln_type: str
    level: CodeVulnLevel
    description: str
    remediation: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContextAnalyzer:
    """上下文分析器 - 用于分析代码上下文以识别误报"""

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

    MYBATIS_LIKELY_SAFE_PATTERNS = [
        r'findByProperty',  # 内部方法，通常安全
        r'exists',  # 内部方法，通常安全
        r'getAll',  # 查询所有
        r'count',  # 计数
        r'getById',  # ID查询
        r'getOne',  # 单条查询
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
        """分析 MyBatis ${} 拼接的上下文，判断是否为误报

        Args:
            file_path: 文件路径
            line_number: 行号
            code_snippet: 代码片段
            surrounding_lines: 周围代码行

        Returns:
            包含 is_likely_safe, reason, confidence 的字典
        """
        result = {
            'is_likely_safe': False,
            'reason': None,
            'confidence': 1.0,
            'analysis_type': 'mybatis_dollar_brace',
            'suggested_confidence_adjustment': 0.0
        }

        full_context = code_snippet
        if surrounding_lines:
            full_context = '\n'.join(surrounding_lines)

        for safe_pattern in self._mybatis_safe_patterns:
            if safe_pattern.search(full_context):
                result['is_likely_safe'] = True
                result['reason'] = '参数来自安全的内部Map/Bean映射，非外部可控'
                result['confidence'] = 0.2
                result['suggested_confidence_adjustment'] = -0.6
                return result

        method_name_match = re.search(r'(findBy\w+|exists|getAll|count|getById|getOne)', file_path)
        if method_name_match:
            method_name = method_name_match.group(1)
            for likely_safe_pattern in self._mybatis_likely_safe_patterns:
                if likely_safe_pattern.search(method_name):
                    result['is_likely_safe'] = True
                    result['reason'] = f'MyBatis方法 {method_name} 通常用于内部查询'
                    result['confidence'] = 0.3
                    result['suggested_confidence_adjustment'] = -0.5
                    return result

        if 'propertyName' in code_snippet and ('enumMap' in full_context or 'getColumns()' in full_context):
            result['is_likely_safe'] = True
            result['reason'] = 'propertyName 来自列名映射，非外部可控'
            result['confidence'] = 0.25
            result['suggested_confidence_adjustment'] = -0.5
            return result

        for validation_pattern in self._validation_patterns:
            if validation_pattern.search(full_context):
                result['confidence'] = 0.5
                result['suggested_confidence_adjustment'] = -0.3
                result['reason'] = '发现输入校验逻辑'
                return result

        return result

    def analyze_sql_injection_context(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        surrounding_lines: List[str] = None
    ) -> Dict[str, Any]:
        """分析 SQL 注入发现的上下文

        Returns:
            包含 is_false_positive, reason, confidence 等字段的字典
        """
        result = {
            'is_false_positive': False,
            'reason': None,
            'confidence': 1.0,
            'analysis_type': 'sql_injection_context',
            'suggested_confidence_adjustment': 0.0
        }

        file_path_str = str(file_path)

        if self.is_framework_security_class(file_path_str):
            result['is_false_positive'] = True
            result['reason'] = '框架层安全类，已内置SQL防护'
            result['confidence'] = 0.15
            result['suggested_confidence_adjustment'] = -0.7
            return result

        if 'StringLiteral' in code_snippet or 'static String' in code_snippet:
            result['is_false_positive'] = True
            result['reason'] = '使用了字符串字面量，不涉及外部输入'
            result['confidence'] = 0.9
            result['suggested_confidence_adjustment'] = -0.5
            return result

        for pattern in self._safe_patterns:
            if pattern.search(code_snippet):
                result['is_false_positive'] = True
                result['reason'] = '代码使用了安全的字符串拼接方式'
                result['confidence'] = 0.8
                result['suggested_confidence_adjustment'] = -0.3
                return result

        for internal_pattern in self._internal_patterns:
            if internal_pattern.search(code_snippet):
                result['is_false_positive'] = False
                result['reason'] = '参数来自内部方法调用，非外部可控输入'
                result['confidence'] = 0.4
                result['suggested_confidence_adjustment'] = -0.4
                return result

        for safe_column_pattern in self._safe_column_patterns:
            if safe_column_pattern.search(code_snippet):
                result['is_false_positive'] = False
                result['reason'] = '列名来自安全的内部映射'
                result['confidence'] = 0.5
                result['suggested_confidence_adjustment'] = -0.3
                return result

        if surrounding_lines:
            full_context = '\n'.join(surrounding_lines)
            for validation_pattern in self._validation_patterns:
                if validation_pattern.search(full_context):
                    result['confidence'] = 0.6
                    result['suggested_confidence_adjustment'] = -0.2
                    result['reason'] = '发现参数校验逻辑'
                    return result

        if 'session' in code_snippet.lower() or 'request' in code_snippet.lower():
            result['confidence'] = 0.7
            result['suggested_confidence_adjustment'] = 0.1

        return result

    def analyze_permission_context(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        surrounding_lines: List[str] = None
    ) -> Dict[str, Any]:
        """分析权限控制的上下文

        Returns:
            包含 is_likely_covered, reason, confidence 等字段的字典
        """
        result = {
            'is_likely_covered': False,
            'reason': None,
            'confidence': 1.0,
            'analysis_type': 'permission_context',
            'suggested_confidence_adjustment': 0.0
        }

        file_path_str = str(file_path)

        if self.is_framework_security_class(file_path_str):
            result['is_likely_covered'] = True
            result['reason'] = '框架层安全类，已内置安全防护'
            result['confidence'] = 0.2
            result['suggested_confidence_adjustment'] = -0.6
            return result

        if surrounding_lines:
            controller_result = self.analyze_controller_permission_context(
                file_path_str,
                line_number,
                surrounding_lines
            )
            if controller_result.get('is_secure'):
                result['is_likely_covered'] = True
                result['reason'] = controller_result.get('reason', '')
                result['confidence'] = controller_result.get('confidence', 0.2)
                result['suggested_confidence_adjustment'] = -0.6
                return result

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
                    result['is_likely_covered'] = True
                    result['reason'] = f'发现权限控制配置: {indicator}'
                    result['confidence'] = 0.6
                    result['suggested_confidence_adjustment'] = -0.3
                    return result

        return result

    def analyze_deserialization_context(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        surrounding_lines: List[str] = None
    ) -> Dict[str, Any]:
        """分析反序列化漏洞的上下文

        Returns:
            包含 is_external_controllable, reason, confidence 等字段的字典
        """
        result = {
            'is_external_controllable': False,
            'reason': None,
            'confidence': 1.0,
            'analysis_type': 'deserialization_context',
            'suggested_confidence_adjustment': 0.0
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
                    result['is_external_controllable'] = False
                    result['reason'] = '数据来源于内部Redis，非外部可控'
                    result['confidence'] = 0.3
                    result['suggested_confidence_adjustment'] = -0.5
                    return result

        external_indicators = [
            r'@RequestBody',
            r'request\.body',
            r'HTTP.*request',
            r'user.*input',
        ]

        for indicator in external_indicators:
            if re.search(indicator, code_snippet, re.IGNORECASE):
                result['is_external_controllable'] = True
                result['confidence'] = 0.9
                result['suggested_confidence_adjustment'] = 0.2
                return result

        return result

    def analyze_controller_permission_context(
        self,
        file_path: str,
        line_number: int,
        surrounding_lines: List[str]
    ) -> Dict[str, Any]:
        """分析Controller层权限上下文

        Returns:
            包含 is_secure, reason, confidence 等字段的字典
        """
        result = {
            'is_secure': False,
            'reason': None,
            'confidence': 1.0,
            'analysis_type': 'controller_permission',
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
                    result['is_secure'] = True
                    result['reason'] = f'发现权限注解: {pattern}'
                    result['confidence'] = 0.2
                    return result

        return result

    def is_framework_security_class(
        self,
        file_path: str,
        class_name: str = None
    ) -> bool:
        """判断是否为框架层安全类

        框架层安全类通常是Spring Security等框架自带的，
        这些类内部已经做了安全防护，不需要报告漏洞。
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
        (r'password\s*=\s*["\'][^"\']{6,}["\']', 'hardcoded_password', '硬编码密码'),
        (r'password\s*=\s*"[^"]{6,}"', 'hardcoded_password', '硬编码密码'),
        (r'pwd\s*=\s*["\'][^"\']{6,}["\']', 'hardcoded_password', '硬编码密码'),
        (r'secret\s*=\s*["\'][^"\']{6,}["\']', 'hardcoded_secret', '硬编码密钥'),
        (r'api[_-]?key\s*=\s*["\'][^"\']{6,}["\']', 'hardcoded_api_key', '硬编码API密钥'),
        (r'access[_-]?key\s*=\s*["\'][^"\']{6,}["\']', 'hardcoded_access_key', '硬编码访问密钥'),
        (r'token\s*=\s*["\'][^"\']{10,}["\']', 'hardcoded_token', '硬编码令牌'),
    ]

    DEFAULT_PASSWORD_PATTERNS = [
        (r'=?\s*["\']123456["\']', 'default_password_123456', '默认密码123456'),
        (r'=?\s*["\']password["\']', 'default_password_password', '默认密码password'),
        (r'=?\s*["\']admin["\']', 'default_password_admin', '默认密码admin'),
        (r'=?\s*["\']000000["\']', 'default_password_000000', '默认密码000000'),
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
    """代码漏洞扫描器"""

    CODE_EXTENSIONS = {
        '.java', '.py', '.js', '.ts', '.jsx', '.tsx', '.xml', '.go', '.rs', '.rb', '.php', '.c', '.cpp', '.h'
    }

    MYBATIS_EXTENSIONS = {'.xml'}

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

        self._context_analyzer = ContextAnalyzer()
        self._input_tracer = InputTracer()

        if self.enable_verification:
            self._init_verification_adapter(nvd_db_path)

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

    def _analyze_finding_context(self, finding: CodeVulnFinding, all_lines: List[str] = None) -> Dict[str, Any]:
        """分析发现的上下文，返回是否可能是误报

        Args:
            finding: 漏洞发现
            all_lines: 文件的所有行（用于上下文分析）
        """
        result = {}

        surrounding_lines = None
        if all_lines and finding.line_number > 0:
            start = max(0, finding.line_number - 10)
            end = min(len(all_lines), finding.line_number + 5)
            surrounding_lines = all_lines[start:end]

        if finding.vuln_type in ['mybatis_dollar_brace_sql', 'sql_string_concat', 'python_sql_concat', 'python_sql_format']:
            if finding.vuln_type == 'mybatis_dollar_brace_sql' and hasattr(self._context_analyzer, 'analyze_mybatis_dollar_brace_context'):
                context = self._context_analyzer.analyze_mybatis_dollar_brace_context(
                    finding.file_path,
                    finding.line_number,
                    finding.code_snippet,
                    surrounding_lines
                )
                if context.get('is_likely_safe'):
                    result['is_likely_false_positive'] = True
                    result['reason'] = context.get('reason', '')
                    result['context_confidence'] = context.get('confidence', 0.5)
                elif context.get('suggested_confidence_adjustment', 0) != 0:
                    result['confidence_adjustment'] = context.get('suggested_confidence_adjustment', 0)
                    result['context_reason'] = context.get('reason', '')
            else:
                context = self._context_analyzer.analyze_sql_injection_context(
                    finding.file_path,
                    finding.line_number,
                    finding.code_snippet,
                    surrounding_lines
                )
                if context.get('is_false_positive'):
                    result['is_likely_false_positive'] = True
                    result['reason'] = context.get('reason', '')
                    result['context_confidence'] = context.get('confidence', 0.5)
                elif context.get('suggested_confidence_adjustment', 0) != 0:
                    result['confidence_adjustment'] = context.get('suggested_confidence_adjustment', 0)
                    result['context_reason'] = context.get('reason', '')

        if finding.vuln_type in ['hardcoded_permission', 'missing_permission_annotation', 'unauthorized_access']:
            context = self._context_analyzer.analyze_permission_context(
                finding.file_path,
                finding.line_number,
                finding.code_snippet,
                surrounding_lines
            )
            if context.get('is_likely_covered'):
                result['permission_likely_covered'] = True
                result['permission_reason'] = context.get('reason', '')
                result['context_confidence'] = context.get('confidence', 0.5)

        if finding.vuln_type in ['jackson_deserialization', 'redis_deserialization', 'jdk_serialization']:
            context = self._context_analyzer.analyze_deserialization_context(
                finding.file_path,
                finding.line_number,
                finding.code_snippet,
                surrounding_lines
            )
            if not context.get('is_external_controllable', True):
                result['deserialization_likely_safe'] = True
                result['deserialization_reason'] = context.get('reason', '')
                result['context_confidence'] = context.get('confidence', 0.5)

        input_trace = self._input_tracer.trace_input_controllability(
            finding.file_path,
            finding.line_number,
            finding.code_snippet
        )
        if input_trace:
            result['input_controlled'] = input_trace.get('is_user_controllable', False)
            result['input_source'] = input_trace.get('input_source', '')

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
            except:
                pass

            content_lower = content.lower()

            if '<mapper' in content_lower or 'mybatis' in content_lower or 'ibatis' in content_lower:
                return True

            if any(tag in content_lower for tag in ['<select', '<insert', '<update', '<delete']) and any(keyword in content_lower for keyword in ['#{', '${', 'sqlsegment', 'ew.']):
                return True

        return False

    def scan_file(self, file_path: str, content: Optional[str] = None) -> List[CodeVulnFinding]:
        findings = []

        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                logger.debug(f"无法读取文件 {file_path}: {e}")
                return findings

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
                if pattern.search(original_line):
                    level = self.level_map.get(name, CodeVulnLevel.MEDIUM)
                    remediation = self.remediation_map.get(name, '进行安全修复')

                    finding = CodeVulnFinding(
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=original_line.strip()[:200],
                        vuln_type=name,
                        level=level,
                        description=desc,
                        remediation=remediation,
                        metadata={}
                    )

                    is_non_security, reason, category = self._context_analyzer.is_non_security_issue(desc, name)
                    if is_non_security:
                        finding.metadata['is_non_security'] = True
                        finding.metadata['non_security_reason'] = reason
                        finding.metadata['non_security_category'] = category
                        finding.level = CodeVulnLevel.LOW

                    context_result = self._analyze_finding_context(finding)
                    if context_result:
                        finding.metadata.update(context_result)
                        if context_result.get('is_likely_false_positive'):
                            finding.level = CodeVulnLevel.LOW
                            finding.metadata['is_likely_false_positive'] = True
                            finding.metadata['false_positive_reason'] = context_result.get('reason', '')

                    findings.append(finding)

        return findings

    def scan_files(self, file_paths: List[str]) -> List[CodeVulnFinding]:
        all_findings = []
        for file_path in file_paths:
            if self.is_code_file(file_path) or self.is_mybatis_mapper(file_path):
                findings = self.scan_file(file_path)
                all_findings.extend(findings)
        return all_findings

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
