"""攻击链分析增强模块

实现针对HOS-LS的攻击链分析增强功能，包括：
1. 漏洞 → 代码模式映射
2. 攻击链RAG
3. exploit知识注入
"""

from typing import Dict, List, Optional, Any
from pathlib import Path

from src.utils.logger import get_logger
from src.storage.hybrid_store import HybridStore
from src.core.hybrid_retriever import HybridRetriever

logger = get_logger(__name__)


class AttackChainAnalyzer:
    """攻击链分析器"""

    def __init__(self, hybrid_store: HybridStore, hybrid_retriever: HybridRetriever):
        """初始化攻击链分析器

        Args:
            hybrid_store: 混合存储实例
            hybrid_retriever: 混合检索器实例
        """
        self.hybrid_store = hybrid_store
        self.hybrid_retriever = hybrid_retriever
        self.pattern_mappings = self._load_pattern_mappings()

    def _load_pattern_mappings(self) -> Dict[str, List[str]]:
        """加载漏洞到代码模式的映射

        Returns:
            漏洞类型到代码模式的映射
        """
        # 这里可以从文件或数据库加载映射
        # 暂时使用硬编码的示例映射
        return {
            'SQL Injection': [
                'execute\(.*input.*\)',
                'query\(.*user.*\)',
                'raw.*sql',
                'sql.*string.*format'
            ],
            'Cross-Site Scripting': [
                'innerHTML.*=',
                'document\.write.*',
                'eval\(.*user.*\)',
                'dangerouslySetInnerHTML'
            ],
            'Remote Code Execution': [
                'exec\(.*',
                'eval\(.*',
                'system\(.*',
                'shell_exec\(.*'
            ],
            'Buffer Overflow': [
                'strcpy\(.*',
                'memcpy\(.*',
                'gets\(.*',
                'fgets\(.*'
            ],
            'Authentication Bypass': [
                'password.*==',
                'auth.*==.*true',
                'login.*bypass',
                'authentication.*skip'
            ]
        }

    def analyze_code(self, code: str) -> List[Dict[str, Any]]:
        """分析代码中的潜在漏洞

        Args:
            code: 代码文本

        Returns:
            漏洞分析结果
        """
        results = []
        
        # 分析代码中的模式
        for vulnerability_type, patterns in self.pattern_mappings.items():
            for pattern in patterns:
                import re
                matches = re.findall(pattern, code, re.IGNORECASE)
                if matches:
                    # 搜索相关的CVE
                    cves = self.hybrid_retriever.search_semantic(
                        f"{vulnerability_type} vulnerability",
                        top_k=5
                    )
                    
                    results.append({
                        'vulnerability_type': vulnerability_type,
                        'pattern': pattern,
                        'matches': len(matches),
                        'related_cves': [cve.get('metadata', {}).get('cve_id') for cve in cves]
                    })
        
        return results

    def build_attack_chain(self, code: str) -> Dict[str, Any]:
        """构建攻击链

        Args:
            code: 代码文本

        Returns:
            攻击链分析结果
        """
        # 1. 分析代码中的漏洞
        vulnerabilities = self.analyze_code(code)
        
        # 2. 搜索相关的攻击链信息
        attack_chain = {
            'entry_points': [],
            'exploit_paths': [],
            'impact': []
        }
        
        # 提取入口点
        for vuln in vulnerabilities:
            if 'SQL Injection' in vuln['vulnerability_type']:
                attack_chain['entry_points'].append('Database Input')
            elif 'Cross-Site Scripting' in vuln['vulnerability_type']:
                attack_chain['entry_points'].append('Web Input')
            elif 'Remote Code Execution' in vuln['vulnerability_type']:
                attack_chain['entry_points'].append('Network Interface')
            elif 'Buffer Overflow' in vuln['vulnerability_type']:
                attack_chain['entry_points'].append('Memory Input')
            elif 'Authentication Bypass' in vuln['vulnerability_type']:
                attack_chain['entry_points'].append('Authentication')
        
        # 构建攻击路径
        for vuln in vulnerabilities:
            cve_ids = vuln['related_cves'][:2]  # 取前2个相关CVE
            for cve_id in cve_ids:
                cve = self.hybrid_retriever.get_cve(cve_id)
                if cve:
                    attack_chain['exploit_paths'].append({
                        'vulnerability': vuln['vulnerability_type'],
                        'cve_id': cve_id,
                        'description': cve.description,
                        'cvss_score': cve.cvss_score
                    })
        
        # 分析影响
        max_score = max([vuln.get('cvss_score', 0) for vuln in attack_chain['exploit_paths']], default=0)
        if max_score >= 9.0:
            attack_chain['impact'] = ['System Compromise', 'Data Breach', 'Service Disruption']
        elif max_score >= 7.0:
            attack_chain['impact'] = ['Data Breach', 'Service Disruption']
        elif max_score >= 4.0:
            attack_chain['impact'] = ['Service Disruption']
        else:
            attack_chain['impact'] = ['Minimal Impact']
        
        return attack_chain

    def enhance_with_exploit_knowledge(self, cve_id: str) -> Dict[str, Any]:
        """增强CVE的exploit知识

        Args:
            cve_id: CVE ID

        Returns:
            增强后的CVE信息
        """
        cve = self.hybrid_retriever.get_cve(cve_id)
        if not cve:
            return {}
        
        # 搜索相关的exploit信息
        exploit_info = self.hybrid_retriever.search_semantic(
            f"{cve_id} exploit payload",
            top_k=3
        )
        
        # 构建增强信息
        enhanced_info = {
            'cve_id': cve.cve_id,
            'description': cve.description,
            'cvss_score': cve.cvss_score,
            'exploit_techniques': [],
            'payload_examples': [],
            'mitigation': []
        }
        
        # 提取exploit技术
        for info in exploit_info:
            content = info.get('content', '')
            if 'exploit' in content.lower():
                enhanced_info['exploit_techniques'].append(content)
            if 'payload' in content.lower():
                enhanced_info['payload_examples'].append(content)
        
        # 根据漏洞类型生成缓解措施
        if cve.cwe_id:
            cwe = cve.cwe_id
            if 'SQL' in cwe:
                enhanced_info['mitigation'] = [
                    'Use parameterized queries',
                    'Implement input validation',
                    'Use ORM frameworks'
                ]
            elif 'XSS' in cwe:
                enhanced_info['mitigation'] = [
                    'Implement output encoding',
                    'Use Content-Security-Policy',
                    'Validate user input'
                ]
            elif 'RCE' in cwe:
                enhanced_info['mitigation'] = [
                    'Implement sandboxing',
                    'Use least privilege principle',
                    'Validate all input'
                ]
        
        return enhanced_info

    def generate_attack_surface(self, code: str) -> Dict[str, Any]:
        """生成攻击面分析

        Args:
            code: 代码文本

        Returns:
            攻击面分析结果
        """
        # 分析代码中的漏洞
        vulnerabilities = self.analyze_code(code)
        
        # 生成攻击面
        attack_surface = {
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerability_types': {},
            'attack_vectors': [],
            'risk_score': 0
        }
        
        # 统计漏洞类型
        for vuln in vulnerabilities:
            vuln_type = vuln['vulnerability_type']
            if vuln_type not in attack_surface['vulnerability_types']:
                attack_surface['vulnerability_types'][vuln_type] = 0
            attack_surface['vulnerability_types'][vuln_type] += 1
        
        # 分析攻击向量
        for vuln in vulnerabilities:
            if 'SQL Injection' in vuln['vulnerability_type']:
                attack_surface['attack_vectors'].append('Database')
            elif 'Cross-Site Scripting' in vuln['vulnerability_type']:
                attack_surface['attack_vectors'].append('Web')
            elif 'Remote Code Execution' in vuln['vulnerability_type']:
                attack_surface['attack_vectors'].append('Network')
            elif 'Buffer Overflow' in vuln['vulnerability_type']:
                attack_surface['attack_vectors'].append('Memory')
            elif 'Authentication Bypass' in vuln['vulnerability_type']:
                attack_surface['attack_vectors'].append('Authentication')
        
        # 计算风险分数
        risk_score = 0
        for vuln in vulnerabilities:
            cve_ids = vuln['related_cves'][:1]  # 取第一个相关CVE
            for cve_id in cve_ids:
                cve = self.hybrid_retriever.get_cve(cve_id)
                if cve and cve.cvss_score:
                    risk_score += cve.cvss_score
        
        attack_surface['risk_score'] = min(risk_score, 10.0)  # 最大风险分数为10
        
        return attack_surface

    def provide_mitigation_advice(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """提供缓解建议

        Args:
            vulnerabilities: 漏洞列表

        Returns:
            缓解建议列表
        """
        advice = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln['vulnerability_type']
            
            if 'SQL Injection' in vuln_type:
                advice.append({
                    'vulnerability': vuln_type,
                    'advice': [
                        'Use parameterized queries instead of string concatenation',
                        'Implement input validation and sanitization',
                        'Use ORM frameworks to abstract database operations',
                        'Apply least privilege principle to database users'
                    ],
                    'priority': 'high'
                })
            elif 'Cross-Site Scripting' in vuln_type:
                advice.append({
                    'vulnerability': vuln_type,
                    'advice': [
                        'Implement output encoding for all user-generated content',
                        'Use Content-Security-Policy headers',
                        'Implement input validation',
                        'Use safe HTML rendering methods'
                    ],
                    'priority': 'high'
                })
            elif 'Remote Code Execution' in vuln_type:
                advice.append({
                    'vulnerability': vuln_type,
                    'advice': [
                        'Implement sandboxing for untrusted code',
                        'Use least privilege principle',
                        'Validate and sanitize all user input',
                        'Keep software up to date'
                    ],
                    'priority': 'critical'
                })
            elif 'Buffer Overflow' in vuln_type:
                advice.append({
                    'vulnerability': vuln_type,
                    'advice': [
                        'Use safe memory handling functions',
                        'Implement input validation',
                        'Use compiler security flags',
                        'Apply address space layout randomization (ASLR)'
                    ],
                    'priority': 'high'
                })
            elif 'Authentication Bypass' in vuln_type:
                advice.append({
                    'vulnerability': vuln_type,
                    'advice': [
                        'Implement strong authentication mechanisms',
                        'Use multi-factor authentication',
                        'Regularly audit authentication code',
                        'Apply principle of least privilege'
                    ],
                    'priority': 'high'
                })
        
        return advice


def create_attack_chain_analyzer(hybrid_store: HybridStore, hybrid_retriever: HybridRetriever) -> AttackChainAnalyzer:
    """创建攻击链分析器

    Args:
        hybrid_store: 混合存储实例
        hybrid_retriever: 混合检索器实例

    Returns:
        攻击链分析器实例
    """
    return AttackChainAnalyzer(hybrid_store, hybrid_retriever)