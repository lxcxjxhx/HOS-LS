"""Fusion Agent

证据融合 Agent，将所有 Agent 的输出整合为统一的证据格式。
"""

from typing import Dict, List, Any, Optional


class FusionAgent:
    """Fusion Agent
    
    证据融合 Agent，将所有 Agent 的输出整合为统一的证据格式。
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化 Fusion Agent
        
        Args:
            config: 配置参数
        """
        self.config = config or {}

    def fuse_evidence(self, cst_results: List[Dict[str, Any]], ast_results: List[Dict[str, Any]], taint_results: List[Dict[str, Any]], rag_results: List[Dict[str, Any]], semantic_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """融合所有证据
        
        Args:
            cst_results: CST 分析结果
            ast_results: AST 分析结果
            taint_results: 污点分析结果
            rag_results: RAG 检索结果
            semantic_results: 语义分析结果
            
        Returns:
            融合后的证据列表
        """
        # 收集所有结果
        all_results = []
        all_results.extend(cst_results)
        all_results.extend(ast_results)
        all_results.extend(taint_results)
        all_results.extend(rag_results)
        all_results.extend(semantic_results)
        
        # 按位置和类型分组
        grouped_results = self._group_results_by_location(all_results)
        
        # 融合每组结果
        fused_evidence = []
        for location, results in grouped_results.items():
            evidence = self._fuse_group(results, location)
            if evidence:
                fused_evidence.append(evidence)
        
        return fused_evidence

    def _group_results_by_location(self, results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """按位置分组结果
        
        Args:
            results: 所有结果
            
        Returns:
            按位置分组的结果
        """
        groups = {}
        
        for result in results:
            # 获取位置信息
            location = self._get_location_key(result)
            if location not in groups:
                groups[location] = []
            groups[location].append(result)
        
        return groups

    def _get_location_key(self, result: Dict[str, Any]) -> str:
        """获取位置键
        
        Args:
            result: 结果
            
        Returns:
            位置键
        """
        location = result.get('location', {})
        if isinstance(location, dict):
            return f"{location.get('file', 'unknown')}:{location.get('line', 0)}"
        elif isinstance(location, str):
            return location
        else:
            return 'unknown:0'

    def _fuse_group(self, results: List[Dict[str, Any]], location: str) -> Dict[str, Any]:
        """融合一组结果
        
        Args:
            results: 一组结果
            location: 位置
            
        Returns:
            融合后的证据
        """
        # 提取信息
        evidence_list = []
        severity = 'low'
        confidence = 0.0
        vulnerability_types = set()
        sources = set()
        
        # 收集信息
        for result in results:
            # 收集证据
            if 'evidence' in result:
                evidence_list.extend(result['evidence'])
            else:
                evidence_list.append(f"{result.get('source_agent', 'Unknown')}: {result.get('message', '发现潜在问题')}")
            
            # 确定最高严重性
            result_severity = result.get('severity', 'low')
            severity_order = ['info', 'low', 'medium', 'high', 'critical']
            if severity_order.index(result_severity) > severity_order.index(severity):
                severity = result_severity
            
            # 计算平均置信度
            confidence += result.get('confidence', 0.0)
            
            # 收集漏洞类型
            vuln_type = result.get('metadata', {}).get('vulnerability_type') or result.get('vulnerability_type')
            if vuln_type:
                vulnerability_types.add(vuln_type)
            
            # 收集源 Agent
            sources.add(result.get('source_agent', 'Unknown'))
        
        # 计算平均置信度
        if results:
            confidence /= len(results)
        
        # 构建融合证据
        fused = {
            "type": "evidence",
            "location": location,
            "evidence": list(set(evidence_list)),  # 去重
            "severity": severity,
            "confidence": confidence,
            "vulnerability_types": list(vulnerability_types),
            "sources": list(sources),
            "source_agent": "Fusion-Agent",
            "metadata": {
                "result_count": len(results),
                "unique_sources": len(sources)
            }
        }
        
        return fused

    def get_standardized_output(self, fused_evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """获取标准化的输出格式
        
        Args:
            fused_evidence: 融合后的证据列表
            
        Returns:
            标准化的输出列表
        """
        return fused_evidence