"""AI 发现验证模块

对 AI 生成的漏洞发现进行验证，包括：
- 文件路径真实性核查
- 代码片段存在性验证
- CWE/NVD 模式匹配
- 置信度计算
"""

import os
import re
from typing import Dict, Any, Optional, List, Set
from pathlib import Path


class FindingVerifier:
    """AI 发现验证器"""

    CWE_PATTERNS = {
        'path_traversal': {
            'cwe_id': 'CWE-22',
            'cwe_name': 'Path Traversal',
            'keywords': ['path', 'traversal', '../', '..\\', 'new File', 'FileInputStream', 'FileOutputStream', ' Paths.get', 'Path.of'],
            'risk_patterns': [
                r'new File\s*\([^)]*\+',
                r'FileInputStream\s*\([^)]*\+',
                r'Paths\.get\s*\([^)]*\+',
                r'Path\.of\s*\([^)]*\+',
            ]
        },
        'sql_injection': {
            'cwe_id': 'CWE-89',
            'cwe_name': 'SQL Injection',
            'keywords': ['sql', 'select', 'insert', 'update', 'delete', 'query', 'execute', 'statement', 'jdbc'],
            'risk_patterns': [
                r'executeQuery\s*\([^)]*\+',
                r'createStatement\s*\([^)]*\+',
                r'\.query\s*\([^)]*\+',
                r'\${[^}]+\}',  # MyBatis ${} pattern
            ]
        },
        'xss': {
            'cwe_id': 'CWE-79',
            'cwe_name': 'Cross-site Scripting',
            'keywords': ['html', 'innerHTML', 'outerHTML', 'script', 'eval', 'document.write', 'response.getWriter'],
            'risk_patterns': [
                r'innerHTML\s*=',
                r'document\.write\s*\(',
                r'eval\s*\(',
                r'response\.getWriter\(\)\.write',
            ]
        },
        'command_injection': {
            'cwe_id': 'CWE-78',
            'cwe_name': 'OS Command Injection',
            'keywords': ['runtime', 'exec', 'process', 'command', 'shell'],
            'risk_patterns': [
                r'Runtime\.getRuntime\(\)\.exec',
                r'ProcessBuilder\s*\(',
            ]
        },
        'sensitive_data_exposure': {
            'cwe_id': 'CWE-200',
            'cwe_name': 'Exposure of Sensitive Information',
            'keywords': ['password', 'secret', 'token', 'key', 'credential', 'api_key', 'apikey', 'access_token'],
            'risk_patterns': [
                r'password\s*=\s*["\'][^"\']{8,}["\']',
                r'api_?key\s*=\s*["\'][^"\']{16,}["\']',
                r'secret\s*=\s*["\'][^"\']{16,}["\']',
            ]
        },
        'xxe': {
            'cwe_id': 'CWE-611',
            'cwe_name': 'XML External Entity',
            'keywords': ['xml', 'documentbuilder', 'saxparser', 'xmlreader', 'transform'],
            'risk_patterns': [
                r'DocumentBuilderFactory',
                r'SAXParserFactory',
                r'XMLReaderFactory',
            ]
        },
        'deserialization': {
            'cwe_id': 'CWE-502',
            'cwe_name': 'Deserialization of Untrusted Data',
            'keywords': ['objectinputstream', 'readobject', 'deserialize', 'yaml.load', 'pickle.load'],
            'risk_patterns': [
                r'ObjectInputStream',
                r'readObject\s*\(',
                r'yaml\.load\s*\(',
            ]
        },
        'ssrf': {
            'cwe_id': 'CWE-918',
            'cwe_name': 'Server-Side Request Forgery',
            'keywords': ['url', 'http', 'request', 'fetch', 'client', 'httpclient', 'resttemplate', 'webclient'],
            'risk_patterns': [
                r'RestTemplate',
                r'WebClient',
                r'HttpClient',
                r'URL\s*\(',
            ]
        },
        'csrf': {
            'cwe_id': 'CWE-352',
            'cwe_name': 'Cross-Site Request Forgery',
            'keywords': ['csrf', 'token', 'samesite', 'csrf_token'],
            'risk_patterns': [
                r'@CsrfFilter',
                r'csrf',
            ]
        },
        'weak_crypto': {
            'cwe_id': 'CWE-327',
            'cwe_name': 'Use of Weak Cryptographic Algorithm',
            'keywords': ['md5', 'sha1', 'des', 'rc4', 'crypto', 'cipher', 'encrypt', 'decrypt'],
            'risk_patterns': [
                r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
                r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']',
                r'Cipher\.getInstance\s*\(\s*["\']DES["\']',
            ]
        },
        'hardcoded_password': {
            'cwe_id': 'CWE-259',
            'cwe_name': 'Hard-coded Password',
            'keywords': ['password', 'passwd', 'pwd', 'secret'],
            'risk_patterns': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'passwd\s*=\s*["\'][^"\']+["\']',
            ]
        },
        'insecure_random': {
            'cwe_id': 'CWE-338',
            'cwe_name': 'Use of Cryptographically Weak PRNG',
            'keywords': ['random', 'math.random', 'java.util.random'],
            'risk_patterns': [
                r'Math\.random\s*\(',
                r'new Random\s*\(',
            ]
        },
        'missing_auth': {
            'cwe_id': 'CWE-306',
            'cwe_name': 'Missing Authentication',
            'keywords': ['@GetMapping', '@PostMapping', '@RequestMapping', '@RestController', 'permitAll', 'authorize'],
            'risk_patterns': [
                r'@RequestMapping\s*\([^)]*\)',
                r'\.permitAll\s*\(',
            ]
        },
        'debug_enabled': {
            'cwe_id': 'CWE-11',
            'cwe_name': 'Compiler Removal of Code to Prevent Debugging',
            'keywords': ['debug', 'debugger', 'development'],
            'risk_patterns': [
                r'debug\s*=\s*true',
                r'enableDebug\s*\(',
            ]
        }
    }

    def __init__(self, project_root: str = ""):
        self.project_root = project_root

    def verify_finding_path(self, finding) -> bool:
        """验证漏洞报告中的文件路径是否真实存在

        Args:
            finding: Finding 对象

        Returns:
            文件路径是否存在
        """
        if not hasattr(finding, 'location'):
            return False

        file_path = finding.location.file
        if not file_path:
            return False

        if self.project_root and not os.path.isabs(file_path):
            full_path = os.path.join(self.project_root, file_path)
        else:
            full_path = file_path

        return os.path.exists(full_path)

    def verify_finding_code(self, finding, project_root: Optional[str] = None) -> bool:
        """验证漏洞报告中的代码片段是否在文件中

        Args:
            finding: Finding 对象
            project_root: 项目根目录

        Returns:
            代码片段是否在文件中
        """
        root = project_root or self.project_root

        if not hasattr(finding, 'location'):
            return False

        file_path = finding.location.file
        if not file_path:
            return False

        if root and not os.path.isabs(file_path):
            full_path = os.path.join(root, file_path)
        else:
            full_path = file_path

        if not os.path.exists(full_path):
            return False

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return False

        code_snippet = getattr(finding, 'code_snippet', '')
        if code_snippet and code_snippet.strip():
            if code_snippet.strip() in content:
                return True

        rule_name = getattr(finding, 'rule_name', '') or ''
        if rule_name:
            for pattern_name, pattern_info in self.CWE_PATTERNS.items():
                if any(kw.lower() in rule_name.lower() for kw in pattern_info['keywords']):
                    for risk_pattern in pattern_info['risk_patterns']:
                        if re.search(risk_pattern, content):
                            return True

        return False

    def match_cwe(self, finding) -> Dict[str, Any]:
        """将 AI 发现与 CWE 模式匹配

        Args:
            finding: Finding 对象

        Returns:
            匹配的 CWE 信息，包含:
            - matched_cwes: 匹配的 CWE 列表
            - confidence: 置信度
            - matched_patterns: 匹配的模式列表
        """
        matched_cwes = []
        matched_patterns = []
        rule_name = getattr(finding, 'rule_name', '') or ''
        description = getattr(finding, 'description', '') or ''
        code_snippet = getattr(finding, 'code_snippet', '') or ''

        combined_text = f"{rule_name} {description} {code_snippet}".lower()

        for pattern_name, pattern_info in self.CWE_PATTERNS.items():
            score = 0
            matched_kws = []

            for kw in pattern_info['keywords']:
                if kw.lower() in combined_text:
                    score += 1
                    matched_kws.append(kw)

            if score > 0:
                for risk_pattern in pattern_info['risk_patterns']:
                    if code_snippet and re.search(risk_pattern, code_snippet):
                        score += 2
                        matched_patterns.append(risk_pattern)

                confidence = min(1.0, score / 5.0)

                matched_cwes.append({
                    'cwe_id': pattern_info['cwe_id'],
                    'cwe_name': pattern_info['cwe_name'],
                    'pattern_name': pattern_name,
                    'confidence': confidence,
                    'matched_keywords': matched_kws,
                    'matched_patterns': matched_patterns
                })

        if matched_cwes:
            best_match = max(matched_cwes, key=lambda x: x['confidence'])
            return {
                'matched_cwes': matched_cwes,
                'best_match': best_match,
                'confidence': best_match['confidence']
            }

        return {
            'matched_cwes': [],
            'best_match': None,
            'confidence': 0.0
        }

    def calculate_confidence(self, finding, project_root: Optional[str] = None) -> float:
        """计算 AI 发现的最终置信度

        Args:
            finding: Finding 对象
            project_root: 项目根目录

        Returns:
            置信度分数 (0.0 - 1.0)
        """
        root = project_root or self.project_root

        path_valid = self.verify_finding_path(finding)
        code_valid = self.verify_finding_code(finding, root)
        cwe_match = self.match_cwe(finding)

        confidence = 0.0

        if path_valid:
            confidence += 0.2

        if code_valid:
            confidence += 0.3

        if cwe_match['confidence'] > 0:
            confidence += cwe_match['confidence'] * 0.5

        existing_confidence = getattr(finding, 'confidence', 1.0)
        confidence = confidence * 0.7 + existing_confidence * 0.3

        return min(1.0, max(0.0, confidence))

    def verify_and_annotate(self, finding, project_root: Optional[str] = None) -> Dict[str, Any]:
        """对发现进行全面验证并注解

        Args:
            finding: Finding 对象
            project_root: 项目根目录

        Returns:
            验证结果字典
        """
        root = project_root or self.project_root

        path_valid = self.verify_finding_path(finding)
        code_valid = self.verify_finding_code(finding, root)
        cwe_match = self.match_cwe(finding)
        confidence = self.calculate_confidence(finding, root)

        if confidence >= 0.9 and path_valid and code_valid and cwe_match['best_match']:
            verification_level = 'triple_verified'
        elif confidence >= 0.7 and path_valid and cwe_match['best_match']:
            verification_level = 'double_verified'
        elif confidence >= 0.5 and path_valid:
            verification_level = 'single_verified'
        elif confidence >= 0.3 and path_valid:
            verification_level = 'needs_review'
        else:
            verification_level = 'potential_hallucination'

        return {
            'path_verified': path_valid,
            'code_verified': code_valid,
            'cwe_match': cwe_match,
            'confidence': confidence,
            'verification_level': verification_level,
            'is_hallucination': confidence < 0.3
        }


def verify_ai_findings(findings: List, project_root: str, nvd_vulnerabilities: List = None) -> List[Dict[str, Any]]:
    """批量验证 AI 发现

    Args:
        findings: Finding 对象列表
        project_root: 项目根目录
        nvd_vulnerabilities: NVD 漏洞列表（可选）

    Returns:
        验证结果列表
    """
    verifier = FindingVerifier(project_root)
    results = []

    for finding in findings:
        verification = verifier.verify_and_annotate(finding, project_root)
        results.append(verification)

        if hasattr(finding, 'metadata'):
            finding.metadata['verification'] = verification
            finding.metadata['path_verified'] = verification['path_verified']
            finding.metadata['code_verified'] = verification['code_verified']
            finding.metadata['confidence_score'] = verification['confidence']
            finding.metadata['verification_level'] = verification['verification_level']
            finding.metadata['is_hallucination'] = verification['is_hallucination']

            if verification['cwe_match']['best_match']:
                finding.metadata['matched_cwe'] = verification['cwe_match']['best_match']

    return results
