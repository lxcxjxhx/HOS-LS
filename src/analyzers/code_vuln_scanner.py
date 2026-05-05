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
        (r'MD5', 'weak_hash_md5', '使用MD5哈希算法'),
        (r'SHA1', 'weak_hash_sha1', '使用SHA1哈希算法'),
        (r'DES', 'weak_cipher_des', '使用DES加密算法'),
        (r'RC4', 'weak_cipher_rc4', '使用RC4加密算法'),
        (r'random\.Random', 'insecure_random_random', '使用random.Random不安全随机数'),
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

        if self.enable_verification:
            self._init_verification_adapter(nvd_db_path)

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

        for line_num, line in enumerate(lines, start=1):
            original_line = line
            line = line.strip()
            if not line:
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
                        remediation=remediation
                    )
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
