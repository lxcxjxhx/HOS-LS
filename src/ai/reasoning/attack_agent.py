"""攻击链生成 Agent

基于污点分析结果生成攻击链。
"""

from typing import Dict, List, Any, Optional

from src.attack.chain_analyzer import AttackChainAnalyzer


class AttackAgent:
    """攻击链生成 Agent
    
    基于污点分析结果生成攻击链。
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化攻击链生成 Agent
        
        Args:
            config: 配置参数
        """
        self.config = config or {}
        self.chain_analyzer = AttackChainAnalyzer()

    def generate_attack_chains(self, taint_paths: List[Dict[str, Any]], evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """生成攻击链
        
        Args:
            taint_paths: 污点路径列表
            evidence: 证据列表
            
        Returns:
            攻击链列表
        """
        attack_chains = []
        
        # 处理每个污点路径
        for taint_path in taint_paths:
            chain = self._generate_chain(taint_path, evidence)
            if chain:
                attack_chains.append(chain)
        
        return attack_chains

    def _generate_chain(self, taint_path: Dict[str, Any], evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成单个攻击链
        
        Args:
            taint_path: 污点路径
            evidence: 证据列表
            
        Returns:
            攻击链
        """
        # 提取信息
        source = taint_path.get('source', 'unknown')
        sink = taint_path.get('function', 'unknown')
        location = taint_path.get('location', 'unknown')
        vulnerability_type = taint_path.get('metadata', {}).get('vulnerability_type', 'Unknown')
        
        # 构建攻击链路径
        path = self._build_attack_path(taint_path)
        
        # 评估影响
        impact = self._evaluate_impact(vulnerability_type)
        
        # 构建攻击链
        chain = {
            "type": "attack_chain",
            "path": path,
            "impact": impact,
            "vulnerability_type": vulnerability_type,
            "location": location,
            "evidence": taint_path.get('evidence', []),
            "source_agent": "Attack-Agent",
            "confidence": taint_path.get('confidence', 0.8),
            "metadata": {
                "source": source,
                "sink": sink,
                "severity": taint_path.get('metadata', {}).get('severity', 'medium')
            }
        }
        
        return chain

    def _build_attack_path(self, taint_path: Dict[str, Any]) -> List[str]:
        """构建攻击路径
        
        Args:
            taint_path: 污点路径
            
        Returns:
            攻击路径列表
        """
        # 从污点路径中提取路径信息
        path_info = taint_path.get('path', [])
        
        if isinstance(path_info, list):
            return path_info
        elif isinstance(path_info, str):
            # 如果是字符串，尝试解析
            return path_info.split(' → ')
        else:
            # 默认路径
            source = taint_path.get('source', 'input')
            sink = taint_path.get('function', 'dangerous_function')
            return [source, sink]

    def _evaluate_impact(self, vulnerability_type: str) -> str:
        """评估漏洞影响
        
        Args:
            vulnerability_type: 漏洞类型
            
        Returns:
            影响级别
        """
        impact_map = {
            "Code Injection": "RCE",
            "Command Injection": "RCE",
            "SQL Injection": "Data Breach",
            "XSS": "Client-Side Attack",
            "Path Traversal": "File Access",
            "Authentication Bypass": "Privilege Escalation",
            "Authorization Bypass": "Privilege Escalation",
            "Information Disclosure": "Data Leak",
            "Denial of Service": "DoS",
            "Buffer Overflow": "RCE"
        }
        
        return impact_map.get(vulnerability_type, "Unknown")

    def get_standardized_output(self, attack_chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """获取标准化的输出格式
        
        Args:
            attack_chains: 攻击链列表
            
        Returns:
            标准化的输出列表
        """
        return attack_chains