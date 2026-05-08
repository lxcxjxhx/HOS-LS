from pathlib import Path
from typing import Dict, List, Optional, Any
import json
import re

from .interfaces import ValidationResult, VulnContext
from .method_storage import MethodStorage, MethodDefinition


class AIPOCGenerator:
    """
    AI POC（验证脚本）生成器

    使用 project-security 技能自动生成泛化 POC 验证脚本
    生成的 POC 作为方法存储，而非硬编码
    """

    VULN_TYPE_PATTERNS = {
        'sql_injection': [
            r'\$\{.*?\}',
            r'".*?"\s*\+',
            r'\.createQuery\(',
            r'\.createNativeQuery\(',
            r'EntityWrapper',
        ],
        'auth_bypass': [
            r'@Secured\([',
            r'@PermitAll',
            r'permitAll\(\)',
            r'hasRole\(',
            r'hasAuthority\(',
        ],
        'ssrf': [
            r'RestTemplate',
            r'WebClient',
            r'URL\(',
            r'HttpClient',
            r'OkHttpClient',
        ],
        'xss': [
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'\.write\(',
            r'v-html',
        ],
        'deserialization': [
            r'ObjectInputStream',
            r'ReadObject\(',
            r'JSON\.parse\(',
            r'jackson',
        ],
        'path_traversal': [
            r'new File\(',
            r'Paths\.get\(',
            r'FileInputStream',
            r'\.getRealPath\(',
        ],
    }

    def __init__(self, method_storage: MethodStorage, pocs_output_path: str):
        self.method_storage = method_storage
        self.pocs_output_path = Path(pocs_output_path)
        self.pocs_output_path.mkdir(parents=True, exist_ok=True)

    def generate_poc(self, context: VulnContext, validator_name: str = None) -> str:
        """
        为漏洞生成 POC 验证脚本

        Args:
            context: 漏洞上下文
            validator_name: 验证器名称（可选）

        Returns:
            POC 方法ID（存储在 method_storage 中）
        """
        method_id = self._generate_method_id(context)

        pattern = self._detect_pattern(context)
        vuln_type = context.vuln_type

        validation_steps = self._generate_validation_steps(context, pattern)
        poc_code = self._generate_poc_code(context, pattern)

        method_def = MethodDefinition(
            id=method_id,
            name=f"{vuln_type.replace('_', ' ').title()} POC - {context.file_path}:{context.line_number}",
            vuln_type=vuln_type,
            pattern=pattern,
            confidence_level='high',
            validation={
                'type': 'code_analysis',
                'steps': validation_steps
            },
            poc_template=poc_code,
            evidence_required=['code_snippet', 'file_path'],
            metadata={
                'file_path': context.file_path,
                'line_number': context.line_number,
                'validator_name': validator_name,
                'generated_by': 'AIPOCGenerator'
            }
        )

        self.method_storage.save_method(method_id, method_def)

        self._save_poc_file(method_id, poc_code, context)

        return method_id

    def generate_generalized_poc(self, vuln_type: str, pattern: str = None) -> str:
        """
        生成泛化 POC 验证方法

        Args:
            vuln_type: 漏洞类型
            pattern: 漏洞模式（可选）

        Returns:
            POC 方法ID
        """
        if pattern is None:
            pattern = self._get_default_pattern(vuln_type)

        method_id = f"{vuln_type}_generalized_{hash(pattern) % 10000:04d}"

        validation_steps = self._get_generalized_steps(vuln_type)
        poc_code = self._generate_generalized_poc_code(vuln_type, pattern)

        method_def = MethodDefinition(
            id=method_id,
            name=f"泛化 {vuln_type.replace('_', ' ').title()} 验证",
            vuln_type=vuln_type,
            pattern=pattern,
            confidence_level='medium',
            validation={
                'type': 'generalized',
                'steps': validation_steps
            },
            poc_template=poc_code,
            evidence_required=[],
            metadata={
                'is_generalized': True,
                'generated_by': 'AIPOCGenerator'
            }
        )

        self.method_storage.save_method(method_id, method_def)

        return method_id

    def generate_verification_steps(self, context: VulnContext) -> List[str]:
        """
        生成验证步骤（人工验证用）

        Args:
            context: 漏洞上下文

        Returns:
            步骤列表
        """
        steps = []

        vuln_type = context.vuln_type

        if vuln_type == 'sql_injection':
            steps.extend([
                f"1. 检查 {context.file_path}:{context.line_number} 处的代码片段",
                "2. 提取 SQL 语句中的参数引用",
                "3. 追踪参数来源（服务层调用链）",
                "4. 确认参数是否来自用户输入",
                "5. 检查是否有输入验证或参数化查询",
                "6. 评估漏洞可利用性"
            ])
        elif vuln_type == 'auth_bypass':
            steps.extend([
                f"1. 检查 {context.file_path}:{context.line_number} 处的安全配置",
                "2. 确认是否配置了适当的权限控制",
                "3. 检查是否有遗漏的接口或路径",
                "4. 验证认证和授权机制是否完整",
                "5. 测试是否存在绕过可能"
            ])
        elif vuln_type == 'ssrf':
            steps.extend([
                f"1. 检查 {context.file_path}:{context.line_number} 处的 URL 处理",
                "2. 确认 URL 来源是否可控",
                "3. 检查是否有 URL 验证或域名白名单",
                "4. 评估内网资源访问风险",
                "5. 测试是否存在 DNS 重绑定绕过"
            ])
        else:
            steps.extend([
                f"1. 检查 {context.file_path}:{context.line_number} 处的代码",
                "2. 分析漏洞上下文和触发条件",
                "3. 确定漏洞可利用性",
                "4. 评估影响范围"
            ])

        return steps

    def auto_adjust_poc(self, poc_method_id: str, feedback: Dict[str, Any]) -> str:
        """
        根据反馈自动调整 POC

        Args:
            poc_method_id: POC 方法ID
            feedback: 用户反馈（如验证结果不符合预期）

        Returns:
            调整后的 POC 方法ID
        """
        original_method = self.method_storage.load_method(poc_method_id)
        if original_method is None:
            return None

        adjustment_type = feedback.get('type', 'unknown')
        details = feedback.get('details', '')

        new_method_id = f"{poc_method_id}_adjusted"

        if adjustment_type == 'false_positive':
            new_confidence = 'low'
            new_validation_steps = original_method.validation.get('steps', [])
            new_validation_steps.append(f"人工复核标记为误报: {details}")
        elif adjustment_type == 'missed_case':
            new_confidence = original_method.confidence_level
            new_validation_steps = original_method.validation.get('steps', [])
            new_validation_steps.append(f"补充验证步骤: {details}")
        else:
            new_method_id = poc_method_id
            return new_method_id

        new_method_def = MethodDefinition(
            id=new_method_id,
            name=original_method.name + " (Adjusted)",
            vuln_type=original_method.vuln_type,
            pattern=original_method.pattern,
            confidence_level=new_confidence,
            validation={
                'type': original_method.validation.get('type', 'adjusted'),
                'steps': new_validation_steps
            },
            poc_template=original_method.poc_template,
            evidence_required=original_method.evidence_required,
            metadata={
                'original_method_id': poc_method_id,
                'adjustment_type': adjustment_type,
                'adjustment_details': details
            }
        )

        self.method_storage.save_method(new_method_id, new_method_def)

        return new_method_id

    def _generate_method_id(self, context: VulnContext) -> str:
        """生成方法ID"""
        file_name = Path(context.file_path).stem
        vuln_type = context.vuln_type.replace(' ', '_')
        return f"{vuln_type}_{file_name}_L{context.line_number}"

    def _detect_pattern(self, context: VulnContext) -> str:
        """检测漏洞模式"""
        code_snippet = context.code_snippet
        vuln_type = context.vuln_type

        patterns = self.VULN_TYPE_PATTERNS.get(vuln_type, [])

        for pattern in patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return pattern

        return self._get_default_pattern(vuln_type)

    def _get_default_pattern(self, vuln_type: str) -> str:
        """获取漏洞类型的默认模式"""
        defaults = {
            'sql_injection': r'\$\{.*?\}|".*?"\s*\+',
            'auth_bypass': r'@Secured\(|@PermitAll',
            'ssrf': r'RestTemplate|URL\(',
            'xss': r'\.innerHTML\s*=',
            'deserialization': r'ObjectInputStream',
            'path_traversal': r'new File\(|Paths\.get\(',
        }
        return defaults.get(vuln_type, r'.*')

    def _generate_validation_steps(self, context: VulnContext, pattern: str) -> List[str]:
        """生成验证步骤"""
        vuln_type = context.vuln_type

        steps_map = {
            'sql_injection': [
                'extract_param_from_pattern',
                'find_service_layer_callers',
                'check_hardcoded_values',
                'check_user_controllability',
                'verify_input_validation'
            ],
            'auth_bypass': [
                'check_security_annotation',
                'analyze_permission_config',
                'test_endpoint_access',
                'verify_auth_mechanism'
            ],
            'ssrf': [
                'identify_url_source',
                'check_url_validation',
                'test_internal_resource_access',
                'verify_dns_rebinding_protection'
            ],
        }

        return steps_map.get(vuln_type, ['analyze_context', 'evaluate_exploitability'])

    def _get_generalized_steps(self, vuln_type: str) -> List[str]:
        """获取泛化验证步骤"""
        return self._generate_validation_steps(
            VulnContext('', 0, '', vuln_type, ''),
            self._get_default_pattern(vuln_type)
        )

    def _generate_poc_code(self, context: VulnContext, pattern: str) -> str:
        """生成 POC 代码"""
        vuln_type = context.vuln_type

        poc_templates = {
            'sql_injection': f'''
def verify_sql_injection(target_path, param_name):
    """
    验证 SQL 注入漏洞

    目标: {context.file_path}:{context.line_number}
    模式: {{pattern}}

    测试步骤:
    1. 构造恶意 SQL payload
    2. 发送请求
    3. 检查响应中的异常信息
    """
    payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--"
    ]

    results = []
    for payload in payloads:
        try:
            response = send_request(target_path, {{param_name}}: payload)
            if check_sql_error(response):
                results.append({{'payload': payload, 'exploitable': True}})
        except Exception as e:
            continue

    return {{
        'is_exploitable': len(results) > 0,
        'evidence': results
    }}
''',
            'auth_bypass': f'''
def verify_auth_bypass(target_endpoint):
    """
    验证认证绕过漏洞

    目标: {context.file_path}:{context.line_number}

    测试步骤:
    1. 尝试未授权访问
    2. 检查是否返回预期数据
    """
    test_cases = [
        {{'request': 'GET', 'path': target_endpoint, 'auth': None}},
        {{'request': 'GET', 'path': target_endpoint, 'auth': 'invalid_token'}},
    ]

    results = []
    for test in test_cases:
        response = send_request(**test)
        if response.status_code == 200:
            results.append({{'test': test, 'exploitable': True}})

    return {{
        'is_exploitable': len(results) > 0,
        'evidence': results
    }}
''',
            'ssrf': f'''
def verify_ssrf(target_url):
    """
    验证 SSRF 漏洞

    目标: {context.file_path}:{context.line_number}

    测试步骤:
    1. 构造指向内部资源的 URL
    2. 检查是否能访问内网资源
    """
    test_urls = [
        'http://localhost:8080/internal/admin',
        'http://169.254.169.254/latest/meta-data/',
        'http://internal.aws.ec2.metadata/'
    ]

    results = []
    for url in test_urls:
        try:
            response = send_request(url)
            if response.status_code == 200:
                results.append({{'url': url, 'exploitable': True}})
        except Exception as e:
            continue

    return {{
        'is_exploitable': len(results) > 0,
        'evidence': results
    }}
'''
        }

        return poc_templates.get(vuln_type, 'def verify_vulnerability(target): pass')

    def _generate_generalized_poc_code(self, vuln_type: str, pattern: str) -> str:
        """生成泛化 POC 代码"""
        return f'''
def verify_{vuln_type}(target, param=None):
    """
    泛化 {vuln_type} 验证

    模式: {{pattern}}

    此为自动生成的泛化 POC，具体逻辑需根据实际情况调整
    """
    # TODO: 实现泛化验证逻辑
    pass
'''.replace('{{', '{').replace('}}', '}')

    def _save_poc_file(self, method_id: str, poc_code: str, context: VulnContext):
        """保存 POC 文件"""
        vuln_type = context.vuln_type
        type_dir = self.pocs_output_path / vuln_type
        type_dir.mkdir(parents=True, exist_ok=True)

        poc_file = type_dir / f"{method_id}.py"

        header = f'''#!/usr/bin/env python3
"""
POC 验证脚本 - {method_id}

漏洞类型: {vuln_type}
文件位置: {context.file_path}:{context.line_number}
生成时间: 自动生成

注意: 此文件由 AIPOCGenerator 自动生成
      如需调整，请修改 dynamic_code/methods/ 中的方法定义
"""

'''

        with open(poc_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(poc_code)

    def list_generated_pocs(self, vuln_type: str = None) -> List[Dict[str, str]]:
        """
        列出已生成的 POC

        Args:
            vuln_type: 漏洞类型过滤（可选）

        Returns:
            POC 信息列表
        """
        pocs = []

        if vuln_type:
            type_dir = self.pocs_output_path / vuln_type
            if type_dir.exists():
                for poc_file in type_dir.glob("*.py"):
                    pocs.append({
                        'method_id': poc_file.stem,
                        'file_path': str(poc_file),
                        'vuln_type': vuln_type
                    })
        else:
            for type_dir in self.pocs_output_path.iterdir():
                if type_dir.is_dir():
                    for poc_file in type_dir.glob("*.py"):
                        pocs.append({
                            'method_id': poc_file.stem,
                            'file_path': str(poc_file),
                            'vuln_type': type_dir.name
                        })

        return pocs
