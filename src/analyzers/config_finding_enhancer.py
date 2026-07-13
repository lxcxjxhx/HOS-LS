"""配置文件敏感信息增强审查模块

对通过正则模式匹配的发现进行上下文感知增强，包括：
- 结合上下文环境评估实际风险等级
- 提供详细的中文描述
- 提供针对性的修复建议
"""

import re
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from src.analyzers.config_scanner import ConfigFinding, SensitivityLevel


class EnhancedSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class EnhancedConfigFinding:
    rule_id: str
    rule_name: str
    description: str
    severity: EnhancedSeverity
    remediation: str
    risk_factors: list


WEAK_PASSWORDS = {
    '123456', 'password', 'passwd', '12345678', 'qwerty', 'abc123',
    'monkey', '1234567', 'letmein', 'trustno1', 'dragon', 'baseball',
    'iloveyou', 'master', 'sunshine', 'ashley', 'bailey', 'shadow',
    '123123', '654321', 'superman', 'qazwsx', 'michael', 'football',
    'password1', 'password123', 'admin', 'login', 'welcome', 'hello'
}


class ConfigFindingEnhancer:
    def __init__(self):
        self.patterns = self._init_patterns()

    def _init_patterns(self) -> Dict[str, Dict[str, Any]]:
        return {
            'database_password': {
                'keywords': ['db', 'database', 'datasource', 'oracle', 'mysql', 'postgresql', 'mariadb', 'sqlserver'],
                'env_var': '${DB_PASSWORD}',
                'spring_template': 'spring.datasource.password=${DB_PASSWORD}',
                'desc_template': '数据库连接{context}发现明文密码',
                'risk_template': '可能导致{db_type}数据库被非法访问，造成数据泄露',
            },
            'redis_password': {
                'keywords': ['redis', 'cache', 'session'],
                'env_var': '${REDIS_PASSWORD}',
                'spring_template': 'spring.redis.password=${REDIS_PASSWORD}',
                'desc_template': 'Redis缓存{context}发现明文密码',
                'risk_template': '可能导致Redis缓存被非法访问，数据被窃取或篡改',
            },
            'smtp_password': {
                'keywords': ['mail', 'smtp', 'email', 'mail.smtp'],
                'env_var': '${MAIL_PASSWORD}',
                'spring_template': 'spring.mail.password=${MAIL_PASSWORD}',
                'desc_template': '邮件服务{context}发现SMTP明文密码',
                'risk_template': '可能导致邮件服务被滥用，发送垃圾邮件或钓鱼邮件',
            },
            'hardcoded_api_key': {
                'keywords': ['api', 'key', 'apikey', 'rest', 'service'],
                'env_var': '${API_KEY}',
                'spring_template': 'app.api.key=${API_KEY}',
                'desc_template': 'API服务{context}发现硬编码API密钥',
                'risk_template': '可能导致第三方服务被非法调用，产生费用或数据泄露',
            },
            'hardcoded_access_key_id': {
                'keywords': ['access', 'aws', 'aliyun', 'cloud', 'oss', 's3'],
                'env_var': '${CLOUD_ACCESS_KEY_ID}',
                'spring_template': 'cloud.access.key.id=${CLOUD_ACCESS_KEY_ID}',
                'desc_template': '云服务{context}发现访问密钥ID',
                'risk_template': '云服务凭证暴露，可能导致云资源被非法访问或产生费用',
            },
            'hardcoded_access_key_secret': {
                'keywords': ['access', 'secret', 'aws', 'aliyun', 'cloud', 'oss', 's3'],
                'env_var': '${CLOUD_ACCESS_KEY_SECRET}',
                'spring_template': 'cloud.access.key.secret=${CLOUD_ACCESS_KEY_SECRET}',
                'desc_template': '云服务{context}发现访问密钥Secret',
                'risk_template': '云服务凭证暴露，可能导致云资源被完全控制',
            },
            'jwt_secret': {
                'keywords': ['jwt', 'token', 'signing', 'secret'],
                'env_var': '${JWT_SECRET}',
                'spring_template': 'jwt.secret=${JWT_SECRET}',
                'desc_template': 'JWT服务{context}发现硬编码签名密钥',
                'risk_template': '可能导致JWT令牌被伪造，身份验证被绕过',
            },
            'client_secret': {
                'keywords': ['client', 'oauth', '3rd', 'third'],
                'env_var': '${OAUTH_CLIENT_SECRET}',
                'spring_template': 'security.oauth2.client.client-secret=${OAUTH_CLIENT_SECRET}',
                'desc_template': 'OAuth客户端{context}发现硬编码密钥',
                'risk_template': '可能导致OAuth认证被破解，第三方应用被冒充',
            },
            'encryption_key': {
                'keywords': ['encrypt', 'crypto', 'aes', 'rsa', '密钥'],
                'env_var': '${ENCRYPTION_KEY}',
                'spring_template': 'app.encryption.key=${ENCRYPTION_KEY}',
                'desc_template': '加密服务{context}发现硬编码加密密钥',
                'risk_template': '可能导致加密数据被解密，敏感信息泄露',
            },
            'hardcoded_username': {
                'keywords': ['username', 'user', 'name', 'account', 'login'],
                'env_var': None,
                'spring_template': None,
                'desc_template': '应用配置{context}发现硬编码用户名',
                'risk_template': '可能导致攻击者获取有效用户名，进行暴力破解',
            },
            'login_password': {
                'keywords': ['login', 'signin', 'auth', 'credential'],
                'env_var': '${LOGIN_PASSWORD}',
                'spring_template': 'app.login.password=${LOGIN_PASSWORD}',
                'desc_template': '登录配置{context}发现明文密码',
                'risk_template': '可能导致用户账户被非法登录',
            },
            'default_password': {
                'keywords': ['default', 'initial', 'admin'],
                'env_var': None,
                'spring_template': None,
                'desc_template': '配置{context}发现默认密码',
                'risk_template': '使用默认密码极易被攻击，需立即修改',
            },
            'sensitive_path_exposure': {
                'keywords': [],
                'env_var': None,
                'spring_template': None,
                'desc_template': '敏感路径{context}暴露',
                'risk_template': '可能导致应用敏感信息被未授权访问',
            },
        }

    def _get_path_risk_level(self, path: str) -> tuple:
        path_lower = path.lower()
        if 'env' in path_lower or 'heapdump' in path_lower:
            return EnhancedSeverity.CRITICAL, '可获取环境变量和堆内存快照，可导致敏感配置和内存数据泄露'
        elif 'beans' in path_lower or 'configprops' in path_lower or 'mappings' in path_lower:
            return EnhancedSeverity.HIGH, '可获取应用完整配置、Bean映射和API路径信息'
        elif 'threaddump' in path_lower or 'logfile' in path_lower:
            return EnhancedSeverity.HIGH, '可获取线程堆栈和日志文件，可能泄露敏感操作信息'
        elif 'health' in path_lower:
            return EnhancedSeverity.LOW, '仅健康检查端点，风险较低'
        elif 'druid' in path_lower:
            return EnhancedSeverity.HIGH, 'Druid监控面板暴露，可能泄露数据库连接池和SQL统计信息'
        elif 'admin' in path_lower or 'debug' in path_lower:
            return EnhancedSeverity.MEDIUM, '管理员或调试端点暴露，建议限制访问'
        elif 'actuator' in path_lower:
            return EnhancedSeverity.HIGH, 'Spring Boot Actuator端点暴露，可能泄露应用敏感信息'
        else:
            return EnhancedSeverity.MEDIUM, '敏感路径暴露，建议限制访问'

    def _is_weak_password(self, value: str) -> bool:
        value_lower = value.lower()
        if value_lower in WEAK_PASSWORDS:
            return True
        if len(value) < 6:
            return True
        if value.isdigit() and len(value) < 8:
            return True
        if re.match(r'^[a-zA-Z]+$', value) and len(value) < 8:
            return True
        return False

    def _is_placeholder(self, value: str) -> bool:
        value_lower = value.lower()
        placeholders = {
            'xxx', 'xxx...', 'your_password', 'your_secret',
            '***', '****', '*****', '<secret>', '<password>',
            '${', '${}', '{{', '}}', '${password}', '${secret}',
            'changeme', 'changepassword', 'your-key-here',
            'xxxxxxxx', 'xxxxxxxxxxxxxxxx', 'xxxxxxxxxxxxx',
            'example', 'test', 'null', 'none', 'undefined'
        }
        if value_lower in placeholders:
            return True
        if value_lower.startswith('${') or value_lower.startswith('{{'):
            return True
        return False

    def _is_spel_reference(self, value: str) -> bool:
        return bool(re.match(r'#\{.*\}', value)) or bool(re.match(r'\$\{.*\}', value))

    def _detect_context(self, key: str, file_path: str = '') -> str:
        key_lower = key.lower()
        file_lower = file_path.lower()

        if any(k in key_lower for k in ['prod', 'production']):
            return '（生产环境）'
        elif any(k in key_lower for k in ['dev', 'development', 'test']):
            return '（开发/测试环境）'
        elif 'dev' in file_lower or 'test' in file_lower:
            return '（开发/测试环境）'
        elif 'prod' in file_lower:
            return '（生产环境）'
        else:
            return ''

    def _detect_db_type(self, key: str, file_path: str, value: str = '') -> str:
        key_lower = key.lower()
        file_lower = file_path.lower()
        value_lower = value.lower()

        if 'oracle' in key_lower or 'oracle' in file_lower:
            return 'Oracle'
        elif 'postgresql' in key_lower or 'postgres' in key_lower or 'pg' in key_lower:
            return 'PostgreSQL'
        elif 'mysql' in key_lower or 'mysql' in file_lower:
            return 'MySQL'
        elif 'mariadb' in key_lower or 'maria' in key_lower:
            return 'MariaDB'
        elif 'sqlserver' in key_lower or 'mssql' in key_lower:
            return 'SQL Server'
        elif 'mongodb' in key_lower or 'mongo' in key_lower:
            return 'MongoDB'
        else:
            return '数据库'

    def _is_encrypted(self, value: str) -> bool:
        value_lower = value.lower()
        encrypted_indicators = ['aes', 'rsa', 'encrypt', 'bouncy', 'jg', 'des3', 'base64']
        return any(indicator in value_lower for indicator in encrypted_indicators)

    def enhance(self, finding: ConfigFinding) -> EnhancedConfigFinding:
        pattern_info = self.patterns.get(finding.pattern_name, {})
        key = finding.key.lower()
        value = finding.value
        file_path = finding.file_path

        risk_factors = []

        if finding.pattern_name == 'sensitive_path_exposure':
            severity, path_risk_desc = self._get_path_risk_level(value)
            context = self._detect_context(key, file_path)
            desc = f"{context}在配置中发现敏感路径 {value}，{path_risk_desc}"

            remediation_map = {
                EnhancedSeverity.CRITICAL: '立即在生产环境禁用相关端点：management.endpoints.enabled-by-default=false',
                EnhancedSeverity.HIGH: '限制端点访问：使用Spring Security配置IP白名单，或通过防火墙限制',
                EnhancedSeverity.MEDIUM: '建议配置访问认证，或在application.yml设置 management.endpoint.*.enabled=false',
                EnhancedSeverity.LOW: '建议在生产环境移除或禁用',
            }

            return EnhancedConfigFinding(
                rule_id=finding.pattern_name.upper(),
                rule_name='敏感路径暴露',
                description=desc,
                severity=severity,
                remediation=remediation_map.get(severity, '建议限制访问'),
                risk_factors=[path_risk_desc]
            )

        desc_template = pattern_info.get('desc_template', '配置{context}发现敏感信息')
        risk_template = pattern_info.get('risk_template', '敏感信息暴露可能导致安全风险')
        env_var = pattern_info.get('env_var')
        spring_template = pattern_info.get('spring_template')
        context = self._detect_context(key, file_path)

        if self._is_placeholder(value):
            return EnhancedConfigFinding(
                rule_id=finding.pattern_name.upper(),
                rule_name=pattern_info.get('desc_template', '敏感信息').format(context=context).split('发现')[1] if '发现' in pattern_info.get('desc_template', '') else '敏感信息',
                description=f'{context}发现疑似占位符，已被脱敏处理',
                severity=EnhancedSeverity.INFO,
                remediation='无需处理',
                risk_factors=[]
            )

        if self._is_spel_reference(value):
            return EnhancedConfigFinding(
                rule_id=finding.pattern_name.upper(),
                rule_name=pattern_info.get('desc_template', '敏感信息').format(context=context).split('发现')[1] if '发现' in pattern_info.get('desc_template', '') else '敏感信息',
                description=f'{context}发现使用SpEL表达式引用外部配置（如 #{{...}} 或 ${{...}}），风险较低',
                severity=EnhancedSeverity.LOW,
                remediation='确认外部配置源已加密，建议启用Spring Cloud Config加密存储',
                risk_factors=['使用外部配置引用', '需确认配置源安全性']
            )

        base_desc = desc_template.format(context=context)

        if finding.pattern_name in ['database_password', 'redis_password', 'smtp_password', 'login_password']:
            if self._is_weak_password(value):
                severity = EnhancedSeverity.CRITICAL
                risk_factors.append('弱密码风险')
                desc = f'{base_desc}（弱密码：长度不足或为常见弱密码）'
            elif self._is_encrypted(value):
                severity = EnhancedSeverity.LOW
                risk_factors.append('已加密')
                desc = f'{base_desc}（已加密）'
            else:
                db_type = self._detect_db_type(key, file_path, value)
                severity = EnhancedSeverity.HIGH
                desc = f'{base_desc}，可能导致{db_type}被非法访问'

                if 'prod' in context or 'prod' in file_path.lower():
                    severity = EnhancedSeverity.CRITICAL
                    risk_factors.append('生产环境风险')

        elif finding.pattern_name == 'hardcoded_username':
            if value.lower() in ['admin', 'root', 'administrator', 'user']:
                severity = EnhancedSeverity.MEDIUM
                desc = f'{base_desc}（常见管理员账户名）'
                risk_factors.append('常见管理员账户名易被暴力破解')
            else:
                severity = EnhancedSeverity.MEDIUM
                desc = f'{base_desc}'
                risk_factors.append('建议使用非常规账户名')

        elif finding.pattern_name in ['hardcoded_access_key_id', 'hardcoded_access_key_secret']:
            severity = EnhancedSeverity.CRITICAL
            risk_factors.append('云服务凭证暴露')
            desc = f'{base_desc}，云服务凭证泄露可能导致云资源被非法控制'

        elif finding.pattern_name in ['jwt_secret', 'client_secret', 'encryption_key']:
            if self._is_encrypted(value):
                severity = EnhancedSeverity.LOW
                desc = f'{base_desc}（已加密存储）'
            else:
                severity = EnhancedSeverity.HIGH
                desc = f'{base_desc}'

        elif finding.pattern_name == 'default_password':
            severity = EnhancedSeverity.CRITICAL
            risk_factors.append('使用默认密码')
            desc = f'{base_desc}，极易被攻击者利用'
            risk_template = '使用默认密码极易被攻击者利用，可能导致完全系统入侵'

        elif finding.pattern_name == 'hardcoded_api_key':
            if any(k in key for k in ['public', 'pub']):
                severity = EnhancedSeverity.MEDIUM
                desc = f'{base_desc}（公钥风险较低，但建议使用环境变量）'
            else:
                severity = EnhancedSeverity.HIGH
                desc = f'{base_desc}'

        else:
            severity_map = {
                SensitivityLevel.CRITICAL: EnhancedSeverity.CRITICAL,
                SensitivityLevel.HIGH: EnhancedSeverity.HIGH,
                SensitivityLevel.MEDIUM: EnhancedSeverity.MEDIUM,
                SensitivityLevel.LOW: EnhancedSeverity.LOW,
            }
            severity = severity_map.get(finding.sensitivity, EnhancedSeverity.MEDIUM)
            desc = f'{base_desc}'

        if env_var and spring_template:
            remediation = f"使用环境变量替代：{env_var}\n例如：{spring_template}"
        elif env_var:
            remediation = f"使用环境变量替代：{env_var}"
        else:
            remediation = '建议使用环境变量或密钥管理服务存储敏感信息'

        return EnhancedConfigFinding(
            rule_id=finding.pattern_name.upper(),
            rule_name=desc.split('）')[0].split('（')[0] if '）' in desc or '（' in desc else desc[:20],
            description=desc,
            severity=severity,
            remediation=remediation,
            risk_factors=risk_factors
        )


def enhance_config_finding(finding: ConfigFinding) -> Dict[str, Any]:
    enhancer = ConfigFindingEnhancer()
    enhanced = enhancer.enhance(finding)

    return {
        'rule_id': enhanced.rule_id,
        'rule_name': enhanced.rule_name,
        'description': enhanced.description,
        'severity': enhanced.severity.value,
        'remediation': enhanced.remediation,
        'risk_factors': enhanced.risk_factors
    }


def enhance_config_findings(findings: list) -> list:
    enhancer = ConfigFindingEnhancer()
    return [enhancer.enhance(f) for f in findings]