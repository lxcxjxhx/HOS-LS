"""攻击链分析增强模块

实现针对HOS-LS的攻击链分析增强功能，包括：
1. 漏洞 → 代码模式映射
2. 攻击链RAG（可选，需外部基础设施）
3. exploit知识注入（可选）
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path

from src.utils.logger import get_logger

# 可选导入：RAG 基础设施
HybridStore = None
HybridRetriever = None
try:
    from src.storage.hybrid_store import HybridStore
except ImportError:
    try:
        from src.ai.pure_ai.rag.hybrid_store import HybridStore
    except ImportError:
        pass

try:
    from src.core.hybrid_retriever import HybridRetriever
except ImportError:
    try:
        from src.ai.pure_ai.rag.hybrid_retriever import HybridRetriever
    except ImportError:
        pass

try:
    from src.core.call_graph_analyzer import CallGraphAnalyzer
except ImportError:
    CallGraphAnalyzer = None

logger = get_logger(__name__)


@dataclass
class AttackChainStep:
    """攻击链步骤"""
    finding: Any  # AggregatedFinding
    description: str


@dataclass
class AttackChain:
    """攻击链"""
    description: str
    risk_level: str
    status: str
    steps: List[AttackChainStep] = field(default_factory=list)


@dataclass
class AttackChainResult:
    """攻击链分析结果"""
    summary: str
    critical_chains: List[AttackChain] = field(default_factory=list)
    total_findings: int = 0
    chains_found: int = 0


class AttackChainAnalyzer:
    """攻击链分析器

    支持两种模式：
    1. 独立模式：无需外部依赖，基于规则进行攻击链推断
    2. RAG 增强模式：需要 HybridStore/HybridRetriever，支持 CVE 关联和语义检索
    """

    def __init__(self, hybrid_store=None, hybrid_retriever=None, code_graph_engine=None):
        """初始化攻击链分析器

        Args:
            hybrid_store: 混合存储实例（可选）
            hybrid_retriever: 混合检索器实例（可选）
            code_graph_engine: 代码调用图引擎实例（可选）
        """
        self.hybrid_store = hybrid_store
        self.hybrid_retriever = hybrid_retriever
        self.rag_enabled = hybrid_store is not None and hybrid_retriever is not None
        self.pattern_mappings = self._load_pattern_mappings()
        self.chain_templates = self._load_chain_templates()

        self.code_graph_engine = code_graph_engine
        self.call_graph_analyzer = None
        if code_graph_engine is not None and CallGraphAnalyzer is not None:
            try:
                self.call_graph_analyzer = CallGraphAnalyzer(code_graph_engine)
                logger.info("攻击链分析器已启用调用图增强")
            except Exception as e:
                logger.warning(f"调用图分析器初始化失败，将使用 AI 推理: {e}")
                self.call_graph_analyzer = None

        if self.rag_enabled:
            logger.info("攻击链分析器已启用 RAG 增强模式")
        else:
            logger.info("攻击链分析器使用独立模式（无 RAG）")

    def _load_chain_templates(self) -> List[Dict[str, Any]]:
        """加载攻击链模板（基于已知攻击模式）

        Returns:
            攻击链模板列表
        """
        return [
            {
                "name": "Web 输入 → SQL 注入 → 数据泄露",
                "entry_patterns": ["request", "input", "query", "param"],
                "vuln_patterns": ["SQL Injection", "sql_injection"],
                "impact": "数据泄露/篡改",
                "risk": "critical",
            },
            {
                "name": "Web 输入 → XSS → 会话劫持",
                "entry_patterns": ["request", "input", "render", "template"],
                "vuln_patterns": ["Cross-Site Scripting", "xss", "XSS"],
                "impact": "会话劫持/钓鱼",
                "risk": "high",
            },
            {
                "name": "网络接口 → RCE → 系统接管",
                "entry_patterns": ["api", "endpoint", "route", "request"],
                "vuln_patterns": ["Remote Code Execution", "rce", "command_injection"],
                "impact": "系统接管",
                "risk": "critical",
            },
            {
                "name": "文件上传 → 路径遍历 → 任意文件读取",
                "entry_patterns": ["upload", "file", "open", "read"],
                "vuln_patterns": ["Path Traversal", "path_traversal", "file_read"],
                "impact": "敏感文件泄露",
                "risk": "high",
            },
            {
                "name": "认证绕过 → 权限提升 → 数据访问",
                "entry_patterns": ["login", "auth", "token", "session"],
                "vuln_patterns": ["Authentication Bypass", "auth_bypass", "privilege"],
                "impact": "未授权访问",
                "risk": "critical",
            },
            {
                "name": "不安全的反序列化 → RCE → 系统接管",
                "entry_patterns": ["deserialize", "pickle", "yaml", "load"],
                "vuln_patterns": ["Insecure Deserialization", "deserialization"],
                "impact": "远程代码执行",
                "risk": "critical",
            },
            {
                "name": "SSRF → 内网探测 → 服务接管",
                "entry_patterns": ["request", "url", "http", "fetch"],
                "vuln_patterns": ["SSRF", "ssrf"],
                "impact": "内网暴露",
                "risk": "high",
            },
            {
                "name": "硬编码凭证 → 认证绕过 → 系统入侵",
                "entry_patterns": ["password", "secret", "key", "token", "credential"],
                "vuln_patterns": ["hardcoded", "credential", "secret", "password", "api_key"],
                "impact": "凭据泄露/系统入侵",
                "risk": "critical",
            },
            {
                "name": "命令注入 + 硬编码凭证 → 完整系统接管",
                "entry_patterns": ["os.system", "subprocess", "exec", "eval"],
                "vuln_patterns": ["command_injection", "hardcoded", "credential"],
                "impact": "系统完全接管",
                "risk": "critical",
                "multi_vuln": True,
            },
            {
                "name": "SQL注入 + 硬编码凭证 → 数据库完全控制",
                "entry_patterns": ["execute", "cursor", "query"],
                "vuln_patterns": ["sql_injection", "hardcoded", "credential", "password"],
                "impact": "数据库完全控制",
                "risk": "critical",
                "multi_vuln": True,
            },
        ]

    def analyze(self, findings) -> AttackChainResult:
        """分析发现列表，识别攻击链

        Args:
            findings: AggregatedFinding 列表或字典列表

        Returns:
            AttackChainResult: 攻击链分析结果
        """
        if not findings:
            return AttackChainResult(
                summary="未发现安全漏洞，无攻击链",
                critical_chains=[],
                total_findings=0,
            )

        # 兼容 dict 和 object 类型的发现
        def _getattr(f, key, default=''):
            if isinstance(f, dict):
                return f.get(key, default)
            return getattr(f, key, default)

        def _severity_val(f) -> str:
            sev = _getattr(f, 'severity', '')
            if hasattr(sev, 'value'):
                return sev.value.lower()
            return str(sev).lower()

        # 按文件分组发现
        findings_by_file: Dict[str, list] = {}
        for f in findings:
            fp = _getattr(f, 'file_path', _getattr(f, 'location', {}).get('file_path', 'unknown') if isinstance(_getattr(f, 'location', {}), dict) else 'unknown')
            findings_by_file.setdefault(fp, []).append(f)

        critical_findings = [f for f in findings if _severity_val(f) in ('critical', 'high')]
        medium_findings = [f for f in findings if _severity_val(f) == 'medium']
        low_findings = [f for f in findings if _severity_val(f) in ('low', 'info')]

        chains = []

        # 尝试匹配攻击链模板
        all_rule_names = " ".join(_getattr(f, 'rule_name', '') for f in findings).lower()
        all_messages = " ".join(_getattr(f, 'message', _getattr(f, 'description', '')) for f in findings).lower()
        combined_text = all_rule_names + " " + all_messages

        for template in self.chain_templates:
            vuln_patterns = template["vuln_patterns"]
            
            # 对于 multi_vuln 模板，需要多个不同类型的漏洞同时存在
            if template.get("multi_vuln", False):
                matched_groups = self._match_multi_vuln_chain(findings, template, _getattr)
                for group in matched_groups:
                    chains.append(AttackChain(
                        description=template["name"],
                        risk_level=template["risk"],
                        status="confirmed",
                        steps=[AttackChainStep(
                            finding=f,
                            description=f"攻击链步骤: {_getattr(f, 'rule_name', 'unknown')}",
                        ) for f in group],
                    ))
            else:
                # 单类型漏洞链（原有逻辑）
                vuln_matches = any(
                    p.lower() in combined_text for p in vuln_patterns
                )
                if vuln_matches:
                    matched_steps = []
                    for f in findings:
                        rule_name = _getattr(f, 'rule_name', '').lower()
                        message = _getattr(f, 'message', _getattr(f, 'description', '')).lower()
                        if any(p.lower() in rule_name or p.lower() in message
                               for p in vuln_patterns):
                            matched_steps.append(AttackChainStep(
                                finding=f,
                                description=f"发现 {template['name']} 相关漏洞: {_getattr(f, 'rule_name', 'unknown')}",
                            ))

                    if matched_steps:
                        chains.append(AttackChain(
                            description=template["name"],
                            risk_level=template["risk"],
                            status="confirmed" if len(matched_steps) >= 2 else "potential",
                            steps=matched_steps,
                        ))

        # 基于文件共现的攻击链推断（同一文件中的多个漏洞可能形成链）
        chains.extend(self._infer_file_cooccurrence_chains(findings_by_file, _getattr))

        # 如果没有匹配到模板，为每个高危发现创建单步链
        if not chains and critical_findings:
            for f in critical_findings:
                chains.append(AttackChain(
                    description=f"独立漏洞: {_getattr(f, 'rule_name', 'unknown')}",
                    risk_level=_severity_val(f) or 'high',
                    status="isolated",
                    steps=[AttackChainStep(
                        finding=f,
                        description=_getattr(f, 'message', _getattr(f, 'description', '')),
                    )],
                ))

        # 去重攻击链
        chains = self._dedup_chains(chains)

        # 构建摘要
        critical_count = len([c for c in chains if c.risk_level in ('critical', 'high')])
        total_count = len(chains)

        if total_count == 0:
            summary = f"共发现 {len(findings)} 个安全问题，未识别出完整攻击链"
        elif critical_count > 0:
            summary = (f"识别出 {total_count} 条攻击链，其中 {critical_count} 条为高危/严重级别。"
                      f"涉及 {len(findings_by_file)} 个文件，建议优先修复关键路径。")
        else:
            summary = f"识别出 {total_count} 条攻击链，均为中低危级别。"

        return AttackChainResult(
            summary=summary,
            critical_chains=chains,
            total_findings=len(findings),
            chains_found=total_count,
        )

    def _match_multi_vuln_chain(self, findings, template, _getattr) -> List[List]:
        """匹配多漏洞组合攻击链

        当模板标记为 multi_vuln 时，查找不同类型的漏洞组合。
        """
        vuln_patterns = template["vuln_patterns"]
        matched_groups = []

        # 按漏洞类型分组
        vuln_groups: Dict[str, List] = {}
        for f in findings:
            rule_name = _getattr(f, 'rule_name', '').lower()
            message = _getattr(f, 'message', _getattr(f, 'description', '')).lower()
            
            for pattern in vuln_patterns:
                if pattern.lower() in rule_name or pattern.lower() in message:
                    vuln_groups.setdefault(pattern, []).append(f)

        # 检查是否存在至少2种不同类型的漏洞
        if len(vuln_groups) >= 2:
            # 选择置信度最高的漏洞形成攻击链
            group = []
            for pattern, vulns in vuln_groups.items():
                best = max(vulns, key=lambda f: _getattr(f, 'confidence', 0))
                group.append(best)
            
            if group:
                matched_groups.append(group)

        return matched_groups

    def _infer_file_cooccurrence_chains(self, findings_by_file, _getattr) -> List[AttackChain]:
        """基于文件共现推断攻击链

        当同一文件中存在多个漏洞时，推断可能的攻击链。
        """
        chains = []

        for file_path, file_findings in findings_by_file.items():
            if len(file_findings) < 2:
                continue

            # 识别漏洞类型组合
            vuln_types = set()
            for f in file_findings:
                rule_name = _getattr(f, 'rule_name', '').lower()
                message = _getattr(f, 'message', _getattr(f, 'description', '')).lower()
                combined = rule_name + ' ' + message
                if 'sql' in combined:
                    vuln_types.add('sql_injection')
                if 'xss' in combined or 'cross-site' in combined:
                    vuln_types.add('xss')
                if 'command' in combined or 'rce' in combined or 'eval' in combined or 'exec' in combined:
                    vuln_types.add('command_injection')
                if 'hardcod' in combined or 'credential' in combined or 'secret' in combined or 'password' in combined:
                    vuln_types.add('hardcoded_secret')
                if 'path' in combined or 'traversal' in combined:
                    vuln_types.add('path_traversal')

            # 推断攻击链 - 精确过滤漏洞类型
            if 'sql_injection' in vuln_types and 'hardcoded_secret' in vuln_types:
                sql_findings = [f for f in file_findings if 'sql' in (_getattr(f, 'rule_name', '') + ' ' + _getattr(f, 'message', '')).lower()]
                secret_findings = [f for f in file_findings if any(k in (_getattr(f, 'rule_name', '') + ' ' + _getattr(f, 'message', '')).lower() for k in ['hardcod', 'credential', 'secret', 'password'])]
                if sql_findings and secret_findings:
                    chains.append(AttackChain(
                        description=f"文件共现攻击链: SQL注入 + 硬编码凭证 → 数据库完全控制 ({file_path})",
                        risk_level="critical",
                        status="confirmed",
                        steps=[AttackChainStep(
                            finding=f,
                            description=f"漏洞: {_getattr(f, 'rule_name', 'unknown')}",
                        ) for f in sql_findings[:2] + secret_findings[:2]],  # 限制步骤数量避免过于冗长
                    ))

            if 'command_injection' in vuln_types and 'hardcoded_secret' in vuln_types:
                cmd_findings = [f for f in file_findings if any(k in (_getattr(f, 'rule_name', '') + ' ' + _getattr(f, 'message', '')).lower() for k in ['command', 'rce', 'eval', 'exec', 'os.system', 'os.popen', 'subprocess'])]
                secret_findings = [f for f in file_findings if any(k in (_getattr(f, 'rule_name', '') + ' ' + _getattr(f, 'message', '')).lower() for k in ['hardcod', 'credential', 'secret', 'password'])]
                if cmd_findings and secret_findings:
                    chains.append(AttackChain(
                        description=f"文件共现攻击链: 命令注入 + 硬编码凭证 → 完整系统接管 ({file_path})",
                        risk_level="critical",
                        status="confirmed",
                        steps=[AttackChainStep(
                            finding=f,
                            description=f"漏洞: {_getattr(f, 'rule_name', 'unknown')}",
                        ) for f in cmd_findings[:2] + secret_findings[:2]],
                    ))

            if 'sql_injection' in vuln_types and 'command_injection' in vuln_types:
                sql_findings = [f for f in file_findings if 'sql' in (_getattr(f, 'rule_name', '') + ' ' + _getattr(f, 'message', '')).lower()]
                cmd_findings = [f for f in file_findings if any(k in (_getattr(f, 'rule_name', '') + ' ' + _getattr(f, 'message', '')).lower() for k in ['command', 'rce', 'eval', 'exec', 'os.system', 'os.popen', 'subprocess'])]
                if sql_findings and cmd_findings:
                    chains.append(AttackChain(
                        description=f"文件共现攻击链: SQL注入 + 命令注入 → 多重攻击面 ({file_path})",
                        risk_level="critical",
                        status="confirmed",
                        steps=[AttackChainStep(
                            finding=f,
                            description=f"漏洞: {_getattr(f, 'rule_name', 'unknown')}",
                        ) for f in sql_findings[:2] + cmd_findings[:2]],
                    ))

        return chains

    def _dedup_chains(self, chains: List[AttackChain]) -> List[AttackChain]:
        """去重攻击链 - 移除重复或包含关系的链"""
        deduped = []
        seen_descriptions = set()

        for chain in chains:
            desc_key = chain.description.lower()
            if desc_key not in seen_descriptions:
                seen_descriptions.add(desc_key)
                deduped.append(chain)

        return deduped

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


def create_attack_chain_analyzer(hybrid_store=None, hybrid_retriever=None, code_graph_engine=None) -> AttackChainAnalyzer:
    """创建攻击链分析器

    Args:
        hybrid_store: 混合存储实例（可选）
        hybrid_retriever: 混合检索器实例（可选）
        code_graph_engine: 代码调用图引擎实例（可选）

    Returns:
        攻击链分析器实例
    """
    return AttackChainAnalyzer(hybrid_store, hybrid_retriever, code_graph_engine)