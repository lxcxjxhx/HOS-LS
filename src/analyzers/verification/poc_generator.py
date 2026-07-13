from pathlib import Path
from typing import Dict, List, Optional, Any
import json
import re
import importlib.util
import sys
import subprocess
import tempfile
import os

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
            r'dangerouslySetInnerHTML',
            r'directive[:\s]*v-html',
            r'\[innerHTML\]',
            r'\$sce\.trustAsHtml',
            r'bypassSecurityTrustHtml',
        ],
        'command_injection': [
            r'Runtime\.exec\(',
            r'ProcessBuilder',
            r'system\(',
            r'exec\(',
            r'ProcessImpl',
            r'java\.lang\.Process',
        ],
        'xxe': [
            r'DocumentBuilder',
            r'SAXParser',
            r'XMLStreamReader',
            r'javax\.xml\.parsers',
            r'SAXBuilder',
            r'XMLReader',
            r'Digester',
            r'Unmarshaller',
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

    BASE_POC_TEMPLATE_PATH = Path(__file__).parent.parent.parent.parent / 'dynamic_code' / 'pocs' / 'templates' / 'base_poc_template.py'

    def __init__(self, method_storage: MethodStorage, pocs_output_path: str):
        self.method_storage = method_storage
        self.pocs_output_path = Path(pocs_output_path)
        self.pocs_output_path.mkdir(parents=True, exist_ok=True)
        self._poc_classes_cache: Dict[str, type] = {}

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
        elif vuln_type == 'command_injection':
            steps.extend([
                f"1. 检查 {context.file_path}:{context.line_number} 处的命令执行代码",
                "2. 确认命令参数是否来自用户输入",
                "3. 检查是否有输入验证或命令白名单",
                "4. 评估系统命令执行风险",
                "5. 测试是否存在命令注入绕过"
            ])
        elif vuln_type == 'xxe':
            steps.extend([
                f"1. 检查 {context.file_path}:{context.line_number} 处的 XML 解析器配置",
                "2. 确认是否禁用了外部实体",
                "3. 检查 XML 输入来源是否可信",
                "4. 评估文件读取和内网探测风险",
                "5. 测试是否存在 XXE 注入利用"
            ])
        elif vuln_type == 'xss':
            steps.extend([
                f"1. 检查 {context.file_path}:{context.line_number} 处的输出编码",
                "2. 确认是否有输入验证或内容安全策略",
                "3. 识别 XSS 上下文（HTML、JS、CSS、URL）",
                "4. 评估会话劫持和钓鱼攻击风险",
                "5. 测试是否存在 XSS 绕过"
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

    def execute_poc(self, poc_method_id: str, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        执行生成的 POC

        Args:
            poc_method_id: POC 方法ID
            target: 目标 URL
            params: 额外参数

        Returns:
            执行结果
        """
        method = self.method_storage.load_method(poc_method_id)
        if method is None:
            return {'error': f'Method not found: {poc_method_id}'}

        vuln_type = method.vuln_type
        poc_code = method.poc_template

        if params is None:
            params = {}

        try:
            result = self._execute_poc_code(poc_code, vuln_type, target, params)
            return result
        except Exception as e:
            return {
                'error': str(e),
                'executed': False,
                'poc_method_id': poc_method_id,
                'target': target
            }

    def _execute_poc_code(self, poc_code: str, vuln_type: str, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        动态执行 POC 代码

        Args:
            poc_code: POC 代码字符串
            vuln_type: 漏洞类型
            target: 目标 URL
            params: 额外参数

        Returns:
            执行结果
        """
        poc_classes = self._load_poc_classes()
        poc_class = poc_classes.get(vuln_type)

        if not poc_class:
            return {'error': f'Unknown vulnerability type: {vuln_type}'}

        context_data = {
            'target': target,
            'vuln_type': vuln_type,
            'additional_params': params
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(poc_code)
            temp_file = f.name

        try:
            result = subprocess.run(
                [sys.executable, temp_file, '--target', target, '--vuln-type', vuln_type],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {
                        'output': result.stdout,
                        'executed': True,
                        'returncode': result.returncode
                    }
            else:
                return {
                    'error': result.stderr,
                    'executed': False,
                    'returncode': result.returncode
                }
        except subprocess.TimeoutExpired:
            return {'error': 'POC execution timeout', 'executed': False}
        except Exception as e:
            return {'error': str(e), 'executed': False}
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def _load_poc_classes(self) -> Dict[str, type]:
        """
        加载 POC 类

        Returns:
            POC 类字典 {vuln_type: class}
        """
        if self._poc_classes_cache:
            return self._poc_classes_cache

        if not self.BASE_POC_TEMPLATE_PATH.exists():
            return {}

        spec = importlib.util.spec_from_file_location(
            "base_poc_template",
            self.BASE_POC_TEMPLATE_PATH
        )

        if spec is None or spec.loader is None:
            return {}

        module = importlib.util.module_from_spec(spec)
        sys.modules['base_poc_template'] = module
        spec.loader.exec_module(module)

        self._poc_classes_cache = {
            'sql_injection': module.SQLInjectionPOC,
            'auth_bypass': module.AuthBypassPOC,
            'ssrf': module.SSrfPOC,
            'deserialization': module.DeserializationPOC,
            'command_injection': getattr(module, 'CommandInjectionPOC', None),
            'xxe': getattr(module, 'XXEPOC', None),
            'xss': getattr(module, 'XSSPOC', None),
        }

        return self._poc_classes_cache

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
            'command_injection': r'Runtime\.exec\(|ProcessBuilder|system\(',
            'xxe': r'DocumentBuilder|SAXParser|XMLStreamReader',
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
            'command_injection': [
                'identify_command_source',
                'extract_command_parameters',
                'check_input_validation',
                'verify_command_execution_context',
                'test_command_injection_payload'
            ],
            'xxe': [
                'identify_xml_parser_type',
                'check_xml_feature_configuration',
                'verify_external_entity_protection',
                'test_xxe_payload',
                'assess_impact_scope'
            ],
            'xss': [
                'identify_sanitization_location',
                'check_output_encoding',
                'verify_content_security_policy',
                'test_xss_payload',
                'assess_impact_scope'
            ],
        }

        return steps_map.get(vuln_type, ['analyze_context', 'evaluate_exploitability'])

    def _get_generalized_steps(self, vuln_type: str) -> List[str]:
        """获取泛化验证步骤"""
        return self._generate_validation_steps(
            VulnContext('', 0, '', vuln_type, ''),
            self._get_default_pattern(vuln_type)
        )

    def _extract_params_from_code(self, code_snippet: str, vuln_type: str) -> Dict[str, Any]:
        """
        从代码片段中提取参数信息

        Args:
            code_snippet: 代码片段
            vuln_type: 漏洞类型

        Returns:
            提取的参数信息
        """
        params = {}

        if vuln_type == 'sql_injection':
            param_patterns = [
                r'\$\{([^}]+)\}',
                r'params?\s*[=:]\s*["\']([^"\']+)["\']',
                r'param\[(["\'])([^\1]+)\1\]',
            ]
            for pattern in param_patterns:
                matches = re.findall(pattern, code_snippet)
                if matches:
                    params['injection_params'] = matches

            if 'createQuery' in code_snippet:
                params['query_type'] = 'jpql'
            elif 'createNativeQuery' in code_snippet:
                params['query_type'] = 'native'

        elif vuln_type == 'ssrf':
            url_param_patterns = [
                r'url\s*[=:]\s*["\']([^"\']+)["\']',
                r'url\[(["\'])([^\1]+)\1\]',
                r'getParameter\(["\']([^"\']+)["\']\)',
            ]
            for pattern in url_param_patterns:
                matches = re.findall(pattern, code_snippet)
                if matches:
                    params['url_params'] = matches

        elif vuln_type == 'deserialization':
            if 'ObjectInputStream' in code_snippet:
                params['serialization_type'] = 'java'
            elif 'pickle' in code_snippet.lower():
                params['serialization_type'] = 'python'
            elif 'json_decode' in code_snippet or 'JSON.parse' in code_snippet:
                params['serialization_type'] = 'json'

        elif vuln_type == 'command_injection':
            cmd_param_patterns = [
                r'(?:Runtime\.exec|ProcessBuilder|system)\s*\(\s*["\']([^"\']+)["\']',
                r'cmd\s*[=:]\s*["\']([^"\']+)["\']',
                r'command\s*[=:]\s*["\']([^"\']+)["\']',
                r'getParameter\(["\']([^"\']+)["\']\)',
            ]
            for pattern in cmd_param_patterns:
                matches = re.findall(pattern, code_snippet)
                if matches:
                    params['command_param'] = matches[0] if matches else 'cmd'

            if 'Runtime.exec' in code_snippet:
                params['command_type'] = 'java_runtime'
            elif 'ProcessBuilder' in code_snippet:
                params['command_type'] = 'process_builder'
            elif 'system(' in code_snippet:
                params['command_type'] = 'system_call'
            elif 'exec(' in code_snippet:
                params['command_type'] = 'exec_call'

        elif vuln_type == 'xxe':
            xml_param_patterns = [
                r'(?:DocumentBuilder|SAXParser|XMLStreamReader).*?\(\s*["\']([^"\']+)["\']',
                r'xml\s*[=:]\s*["\']([^"\']+)["\']',
                r'data\s*[=:]\s*["\']([^"\']+)["\']',
                r'getParameter\(["\']([^"\']+)["\']\)',
            ]
            for pattern in xml_param_patterns:
                matches = re.findall(pattern, code_snippet)
                if matches:
                    params['xml_param'] = matches[0] if matches else 'data'

            if 'DocumentBuilder' in code_snippet:
                params['xml_parser_type'] = 'document_builder'
            elif 'SAXParser' in code_snippet:
                params['xml_parser_type'] = 'sax_parser'
            elif 'XMLStreamReader' in code_snippet:
                params['xml_parser_type'] = 'stream_reader'
            elif 'javax.xml.parsers' in code_snippet:
                params['xml_parser_type'] = 'javax_xml'

        elif vuln_type == 'xss':
            xss_param_patterns = [
                r'(?:innerHTML|outerHTML|write)\s*=\s*["\']([^"\']+)["\']',
                r'v-html\s*=\s*["\']([^"\']+)["\']',
                r'dangerouslySetInnerHTML\s*=\s*\{{[^}]+}}',
                r'input\s*[=:]\s*["\']([^"\']+)["\']',
                r'getParameter\(["\']([^"\']+)["\']\)',
            ]
            for pattern in xss_param_patterns:
                matches = re.findall(pattern, code_snippet)
                if matches:
                    params['xss_param'] = matches[0] if matches else 'input'

            if 'dangerouslySetInnerHTML' in code_snippet:
                params['xss_type'] = 'react'
            elif 'v-html' in code_snippet:
                params['xss_type'] = 'vue'
            elif 'innerHTML' in code_snippet or 'outerHTML' in code_snippet:
                params['xss_type'] = 'dom'
            elif '$sce.trustAsHtml' in code_snippet or 'bypassSecurityTrustHtml' in code_snippet:
                params['xss_type'] = 'angular'
            else:
                params['xss_type'] = 'generic'

        return params

    def _generate_poc_code(self, context: VulnContext, pattern: str) -> str:
        """
        生成 POC 代码 - 基于上下文生成实际可执行代码

        Args:
            context: 漏洞上下文
            pattern: 检测到的模式

        Returns:
            实际可执行的 POC Python 代码
        """
        vuln_type = context.vuln_type
        file_path = context.file_path
        line_number = context.line_number
        code_snippet = context.code_snippet
        extracted_params = self._extract_params_from_code(code_snippet, vuln_type)

        base_imports = '''#!/usr/bin/env python3
"""
POC 验证脚本 - 自动生成
漏洞类型: {vuln_type}
文件位置: {file_path}:{line_number}
生成时间: 自动生成
"""

import sys
import json
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'dynamic_code' / 'pocs' / 'templates'))

from base_poc_template import POCContext, SQLInjectionPOC, AuthBypassPOC, SSrfPOC, DeserializationPOC, CommandInjectionPOC, XXEPOC, XSSPOC

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('POC')

'''

        if vuln_type == 'sql_injection':
            param = extracted_params.get('injection_params', ['id'])[0] if extracted_params.get('injection_params') else 'id'
            query_type = extracted_params.get('query_type', 'unknown')

            return base_imports + f'''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/endpoint'

    context = POCContext(
        target=target,
        vuln_type='sql_injection',
        file_path='{file_path}',
        line_number={line_number},
        code_snippet=\'\'\'{code_snippet[:500]}...\'\'\',
        additional_params={{'query_type': '{query_type}'}}
    )

    poc = SQLInjectionPOC(context, param='{param}')
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'auth_bypass':
            return base_imports + f'''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/endpoint'

    context = POCContext(
        target=target,
        vuln_type='auth_bypass',
        file_path='{file_path}',
        line_number={line_number},
        code_snippet=\'\'\'{code_snippet[:500]}...\'\'\'
    )

    poc = AuthBypassPOC(context)
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'ssrf':
            url_params = extracted_params.get('url_params', ['url'])
            param = url_params[0] if url_params else 'url'

            return base_imports + f'''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/fetch'

    context = POCContext(
        target=target,
        vuln_type='ssrf',
        file_path='{file_path}',
        line_number={line_number},
        code_snippet=\'\'\'{code_snippet[:500]}...\'\'\',
        additional_params={{'url_param': '{param}'}}
    )

    poc = SSrfPOC(context, param='{param}')
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'deserialization':
            ser_type = extracted_params.get('serialization_type', 'java')
            param = 'data'

            return base_imports + f'''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/deserialize'

    context = POCContext(
        target=target,
        vuln_type='deserialization',
        file_path='{file_path}',
        line_number={line_number},
        code_snippet=\'\'\'{code_snippet[:500]}...\'\'\',
        additional_params={{'serialization_type': '{ser_type}'}}
    )

    poc = DeserializationPOC(context, param='{param}')
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'command_injection':
            cmd_type = extracted_params.get('command_type', 'unknown')
            param = extracted_params.get('command_param', 'cmd')

            return base_imports + f'''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/exec'

    context = POCContext(
        target=target,
        vuln_type='command_injection',
        file_path='{file_path}',
        line_number={line_number},
        code_snippet=\'\'\'{code_snippet[:500]}...\'\'\',
        additional_params={{'command_type': '{cmd_type}'}}
    )

    poc = CommandInjectionPOC(context, param='{param}')
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'xxe':
            xml_type = extracted_params.get('xml_parser_type', 'unknown')
            param = extracted_params.get('xml_param', 'data')

            return base_imports + f'''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/xml'

    context = POCContext(
        target=target,
        vuln_type='xxe',
        file_path='{file_path}',
        line_number={line_number},
        code_snippet=\'\'\'{code_snippet[:500]}...\'\'\',
        additional_params={{'xml_parser_type': '{xml_type}'}}
    )

    poc = XXEPOC(context, param='{param}')
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'xss':
            xss_type = extracted_params.get('xss_type', 'unknown')
            param = extracted_params.get('xss_param', 'input')

            return base_imports + f'''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/input'

    context = POCContext(
        target=target,
        vuln_type='xss',
        file_path='{file_path}',
        line_number={line_number},
        code_snippet=\'\'\'{code_snippet[:500]}...\'\'\',
        additional_params={{'xss_type': '{xss_type}'}}
    )

    poc = XSSPOC(context, param='{param}')
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'command_injection':
            return base_imports + '''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/exec'
    param = sys.argv[2] if len(sys.argv) > 2 else 'cmd'

    context = POCContext(
        target=target,
        vuln_type='command_injection',
        file_path='generalized',
        line_number=0,
        code_snippet='Generic command injection test'
    )

    poc = CommandInjectionPOC(context, param=param)
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    logger.info(f"Command Injection POC completed: exploitable={result.get('is_exploitable', False)}")

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'xxe':
            return base_imports + '''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/xml'
    param = sys.argv[2] if len(sys.argv) > 2 else 'data'

    context = POCContext(
        target=target,
        vuln_type='xxe',
        file_path='generalized',
        line_number=0,
        code_snippet='Generic XXE test'
    )

    poc = XXEPOC(context, param=param)
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    logger.info(f"XXE POC completed: exploitable={result.get('is_exploitable', False)}")

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'xss':
            return base_imports + '''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/input'
    param = sys.argv[2] if len(sys.argv) > 2 else 'input'

    context = POCContext(
        target=target,
        vuln_type='xss',
        file_path='generalized',
        line_number=0,
        code_snippet='Generic XSS test'
    )

    poc = XSSPOC(context, param=param)
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    logger.info(f"XSS POC completed: exploitable={result.get('is_exploitable', False)}")

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        else:
            return base_imports + f'''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080'

    context = POCContext(
        target=target,
        vuln_type='{vuln_type}',
        file_path='{file_path}',
        line_number={line_number},
        code_snippet=\'\'\'{code_snippet[:500]}...\'\'\'
    )

    logger.info(f"Generic POC for {{context.vuln_type}} at {{target}}")
    result = {{
        'is_exploitable': False,
        'target': target,
        'vuln_type': '{vuln_type}',
        'message': 'Generic POC - manual verification required'
    }}

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1

if __name__ == '__main__':
    sys.exit(main())
'''

    def _generate_generalized_poc_code(self, vuln_type: str, pattern: str) -> str:
        """
        生成泛化 POC 代码 - 实际可执行代码

        Args:
            vuln_type: 漏洞类型
            pattern: 漏洞模式

        Returns:
            实际可执行的 POC Python 代码
        """
        base_imports = '''#!/usr/bin/env python3
"""
泛化 POC 验证脚本 - 自动生成
漏洞类型: {vuln_type}
模式: {pattern}
生成时间: 自动生成
"""

import sys
import json
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'dynamic_code' / 'pocs' / 'templates'))

from base_poc_template import POCContext, SQLInjectionPOC, AuthBypassPOC, SSrfPOC, DeserializationPOC

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('POC')

'''

        if vuln_type == 'sql_injection':
            return base_imports + '''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/query'
    param = sys.argv[2] if len(sys.argv) > 2 else 'q'

    context = POCContext(
        target=target,
        vuln_type='sql_injection',
        file_path='generalized',
        line_number=0,
        code_snippet='Generic SQL injection test'
    )

    poc = SQLInjectionPOC(context, param=param)
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    logger.info(f"SQL Injection POC completed: exploitable={result.get('is_exploitable', False)}")

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'auth_bypass':
            return base_imports + '''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/protected'

    context = POCContext(
        target=target,
        vuln_type='auth_bypass',
        file_path='generalized',
        line_number=0,
        code_snippet='Generic authentication bypass test'
    )

    poc = AuthBypassPOC(context)
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    logger.info(f"Auth Bypass POC completed: exploitable={result.get('is_exploitable', False)}")

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'ssrf':
            return base_imports + '''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/fetch'
    param = sys.argv[2] if len(sys.argv) > 2 else 'url'

    context = POCContext(
        target=target,
        vuln_type='ssrf',
        file_path='generalized',
        line_number=0,
        code_snippet='Generic SSRF test'
    )

    poc = SSrfPOC(context, param=param)
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    logger.info(f"SSRF POC completed: exploitable={result.get('is_exploitable', False)}")

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        elif vuln_type == 'deserialization':
            return base_imports + '''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/api/deserialize'
    param = sys.argv[2] if len(sys.argv) > 2 else 'data'

    context = POCContext(
        target=target,
        vuln_type='deserialization',
        file_path='generalized',
        line_number=0,
        code_snippet='Generic deserialization test'
    )

    poc = DeserializationPOC(context, param=param)
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    logger.info(f"Deserialization POC completed: exploitable={result.get('is_exploitable', False)}")

    return 0 if result.get('is_exploitable', False) else 1

if __name__ == '__main__':
    sys.exit(main())
'''
        else:
            return base_imports + f'''
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080'

    context = POCContext(
        target=target,
        vuln_type='{vuln_type}',
        file_path='generalized',
        line_number=0,
        code_snippet='Generic {{vuln_type}} test'
    )

    result = {{
        'is_exploitable': False,
        'target': target,
        'vuln_type': '{vuln_type}',
        'pattern': '{pattern}',
        'message': 'Generic POC for {{vuln_type}} - manual verification required'
    }}

    print(json.dumps(result, indent=2, ensure_ascii=False))
    logger.warning(f"Generic POC for {{context.vuln_type}} - no specific handler implemented")

    return 1

if __name__ == '__main__':
    sys.exit(main())
'''

    def _save_poc_file(self, method_id: str, poc_code: str, context: VulnContext):
        """保存 POC 文件"""
        vuln_type = context.vuln_type
        type_dir = self.pocs_output_path / vuln_type
        type_dir.mkdir(parents=True, exist_ok=True)

        poc_file = type_dir / f"{method_id}.py"

        with open(poc_file, 'w', encoding='utf-8') as f:
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

    def get_poc_script(self, poc_method_id: str) -> Optional[str]:
        """
        获取 POC 脚本内容

        Args:
            poc_method_id: POC 方法ID

        Returns:
            POC 脚本内容
        """
        method = self.method_storage.load_method(poc_method_id)
        if method is None:
            return None
        return method.poc_template

    def run_poc_direct(self, poc_method_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """
        直接运行 POC（不使用子进程）

        Args:
            poc_method_id: POC 方法ID
            target: 目标 URL
            **kwargs: 额外参数

        Returns:
            运行结果
        """
        method = self.method_storage.load_method(poc_method_id)
        if method is None:
            return {'error': f'Method not found: {poc_method_id}'}

        vuln_type = method.vuln_type
        poc_classes = self._load_poc_classes()
        poc_class = poc_classes.get(vuln_type)

        if not poc_class:
            return {'error': f'Unknown vulnerability type: {vuln_type}'}

        try:
            from base_poc_template import POCContext as BasePOCContext

            context = BasePOCContext(
                target=target,
                vuln_type=vuln_type,
                file_path=method.metadata.get('file_path', ''),
                line_number=method.metadata.get('line_number', 0),
                code_snippet='',
                additional_params=kwargs
            )

            param = kwargs.get('param')
            poc = poc_class(context, param=param)
            result = poc.verify()

            return {
                'executed': True,
                'poc_method_id': poc_method_id,
                'target': target,
                'result': result
            }
        except Exception as e:
            return {
                'error': str(e),
                'executed': False,
                'poc_method_id': poc_method_id,
                'target': target
            }
