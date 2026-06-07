"""攻击链分析增强模块

实现针对HOS-LS的攻击链分析增强功能，包括：
1. 漏洞 → 代码模式映射
2. 攻击链RAG
3. exploit知识注入
"""

from typing import Dict, List, Optional, Any
from pathlib import Path

from src.utils.logger import get_logger
try:
    from src.storage.hybrid_store import HybridStore
except ImportError:
    from src.ai.pure_ai.rag.hybrid_store import HybridStore
from src.core.hybrid_retriever import HybridRetriever

try:
    from src.core.call_graph_analyzer import CallGraphAnalyzer
except ImportError:
    CallGraphAnalyzer = None

logger = get_logger(__name__)


class AttackChainAnalyzer:
    """攻击链分析器"""

    def __init__(self, hybrid_store: HybridStore, hybrid_retriever: HybridRetriever, code_graph_engine=None):
        """初始化攻击链分析器

        Args:
            hybrid_store: 混合存储实例
            hybrid_retriever: 混合检索器实例
            code_graph_engine: 代码调用图引擎实例（可选）
        """
        self.hybrid_store = hybrid_store
        self.hybrid_retriever = hybrid_retriever
        self.pattern_mappings = self._load_pattern_mappings()
        
        self.code_graph_engine = code_graph_engine
        self.call_graph_analyzer = None
        if code_graph_engine is not None and CallGraphAnalyzer is not None:
            try:
                self.call_graph_analyzer = CallGraphAnalyzer(code_graph_engine)
                logger.info("攻击链分析器已启用调用图增强")
            except Exception as e:
                logger.warning(f"调用图分析器初始化失败，将使用 AI 推理: {e}")
                self.call_graph_analyzer = None

    def _load_pattern_mappings(self) -> Dict[str, List[str]]:
        """加载漏洞到代码模式的映射

        Returns:
            漏洞类型到代码模式的映射
        """
        # 这里可以从文件或数据库加载映射
        # 暂时使用硬编码的示例映射
        return {
            'SQL Injection': [
                r'execute\(.*input.*\)',
                r'query\(.*user.*\)',
                r'raw.*sql',
                r'sql.*string.*format'
            ],
            'Cross-Site Scripting': [
                r'innerHTML.*=',
                r'document\.write.*',
                r'eval\(.*user.*\)',
                r'dangerouslySetInnerHTML'
            ],
            'Remote Code Execution': [
                r'exec\(.*',
                r'eval\(.*',
                r'system\(.*',
                r'shell_exec\(.*'
            ],
            'Buffer Overflow': [
                r'strcpy\(.*',
                r'memcpy\(.*',
                r'gets\(.*',
                r'fgets\(.*'
            ],
            'Authentication Bypass': [
                r'password.*==',
                r'auth.*==.*true',
                r'login.*bypass',
                r'authentication.*skip'
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
        vulnerabilities = self.analyze_code(code)
        
        attack_chain = {
            'entry_points': [],
            'exploit_paths': [],
            'impact': [],
            'verified_paths': [],
            'path_verified': False,
            'graph_enhanced': self.call_graph_analyzer is not None
        }
        
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
        
        if self.call_graph_analyzer is not None and vulnerabilities:
            enhanced_paths = self.get_attack_paths_with_graph(vulnerabilities, attack_chain['entry_points'])
            attack_chain['verified_paths'] = enhanced_paths
            
            verified_count = sum(1 for p in enhanced_paths if p.get('path_verified'))
            attack_chain['path_verified'] = verified_count > 0
            
            for path_info in enhanced_paths:
                cve_ids = []
                for vuln in vulnerabilities:
                    if vuln['vulnerability_type'] == path_info['vulnerability']:
                        cve_ids = vuln['related_cves'][:2]
                        break
                
                for cve_id in cve_ids:
                    cve = self.hybrid_retriever.get_cve(cve_id)
                    if cve:
                        attack_chain['exploit_paths'].append({
                            'vulnerability': path_info['vulnerability'],
                            'entry_point': path_info['entry_point'],
                            'cve_id': cve_id,
                            'description': cve.description,
                            'cvss_score': cve.cvss_score,
                            'path_verified': path_info['path_verified'],
                            'graph_path': path_info['graph_path'],
                            'ai_inferred': path_info['ai_inferred'],
                            'confidence': path_info['confidence']
                        })
        else:
            for vuln in vulnerabilities:
                cve_ids = vuln['related_cves'][:2]
                for cve_id in cve_ids:
                    cve = self.hybrid_retriever.get_cve(cve_id)
                    if cve:
                        attack_chain['exploit_paths'].append({
                            'vulnerability': vuln['vulnerability_type'],
                            'cve_id': cve_id,
                            'description': cve.description,
                            'cvss_score': cve.cvss_score,
                            'path_verified': False,
                            'graph_path': [],
                            'ai_inferred': True,
                            'confidence': 'low'
                        })
        
        max_score = max([p.get('cvss_score', 0) for p in attack_chain['exploit_paths']], default=0)
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

    def verify_path_reachability(self, entry_point: str, vulnerability_point: str) -> Dict[str, Any]:
        """使用调用图验证从入口点到漏洞点的路径是否可达

        Args:
            entry_point: 入口点符号名称
            vulnerability_point: 漏洞点符号名称

        Returns:
            验证结果，包含 path_reachable、graph_path 等字段
        """
        result = {
            'path_reachable': False,
            'graph_path': [],
            'path_length': 0,
            'error': None
        }
        
        if self.call_graph_analyzer is None:
            result['error'] = '调用图分析器不可用'
            return result
        
        try:
            call_chain = self.call_graph_analyzer.get_call_chain(
                entry_point, vulnerability_point, max_depth=5
            )
            
            if call_chain is not None:
                result['path_reachable'] = True
                result['path_length'] = call_chain.depth
                result['graph_path'] = [
                    {
                        'symbol': node.symbol_name,
                        'file': str(node.file_path),
                        'line': node.start_line,
                        'type': node.symbol_type
                    }
                    for node in call_chain.path
                ]
                logger.debug(f"攻击路径验证成功: {entry_point} -> {vulnerability_point}, 深度={call_chain.depth}")
            else:
                logger.debug(f"攻击路径验证失败: {entry_point} -> {vulnerability_point} 无调用链")
        except Exception as e:
            result['error'] = str(e)
            logger.warning(f"调用图路径验证异常: {e}")
        
        return result

    def get_attack_paths_with_graph(self, vulnerabilities: List[Dict], entry_points: List[str]) -> List[Dict[str, Any]]:
        """结合调用图构建攻击路径

        优先使用确定性调用图构建路径，如果不可用则回退到 AI 推理

        Args:
            vulnerabilities: 漏洞列表
            entry_points: 入口点列表

        Returns:
            攻击路径列表，每个路径包含 path_verified、graph_path、ai_inferred 等字段
        """
        attack_paths = []
        
        if self.call_graph_analyzer is None:
            for vuln in vulnerabilities:
                vuln_symbol = vuln.get('symbol_name', vuln.get('vulnerability_type', ''))
                for entry in entry_points:
                    attack_paths.append({
                        'entry_point': entry,
                        'vulnerability': vuln.get('vulnerability_type', ''),
                        'path_verified': False,
                        'graph_path': [],
                        'ai_inferred': True,
                        'confidence': 'low'
                    })
            return attack_paths
        
        for vuln in vulnerabilities:
            vuln_symbol = vuln.get('symbol_name', vuln.get('function', ''))
            vuln_type = vuln.get('vulnerability_type', '')
            
            if not vuln_symbol:
                for entry in entry_points:
                    attack_paths.append({
                        'entry_point': entry,
                        'vulnerability': vuln_type,
                        'path_verified': False,
                        'graph_path': [],
                        'ai_inferred': True,
                        'confidence': 'low'
                    })
                continue
            
            for entry in entry_points:
                verification = self.verify_path_reachability(entry, vuln_symbol)
                
                if verification['path_reachable']:
                    attack_paths.append({
                        'entry_point': entry,
                        'vulnerability': vuln_type,
                        'path_verified': True,
                        'graph_path': verification['graph_path'],
                        'ai_inferred': False,
                        'confidence': 'high'
                    })
                else:
                    attack_paths.append({
                        'entry_point': entry,
                        'vulnerability': vuln_type,
                        'path_verified': False,
                        'graph_path': [],
                        'ai_inferred': True,
                        'confidence': 'medium'
                    })
        
        return attack_paths

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


def create_attack_chain_analyzer(hybrid_store: HybridStore, hybrid_retriever: HybridRetriever, code_graph_engine=None) -> AttackChainAnalyzer:
    """创建攻击链分析器

    Args:
        hybrid_store: 混合存储实例
        hybrid_retriever: 混合检索器实例
        code_graph_engine: 代码调用图引擎实例（可选）

    Returns:
        攻击链分析器实例
    """
    return AttackChainAnalyzer(hybrid_store, hybrid_retriever, code_graph_engine)