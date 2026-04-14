"""验证 Agent

对分析结果进行校验，支持回流机制。
"""

from typing import Dict, List, Any, Optional, Tuple

from src.ai.evaluation import get_evaluator


class ValidationAgent:
    """验证 Agent
    
    对分析结果进行校验，支持回流机制。
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化验证 Agent
        
        Args:
            config: 配置参数
        """
        self.config = config or {}
        self.evaluator = get_evaluator()

    def validate(self, findings: List[Dict[str, Any]], attack_chains: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], bool, Dict[str, Any]]:
        """验证分析结果
        
        Args:
            findings: 发现的漏洞列表
            attack_chains: 攻击链列表
            
        Returns:
            (验证后的结果, 是否需要回流, 回流信息)
        """
        # 去重
        unique_findings = self._deduplicate_findings(findings)
        
        # 降误报
        validated_findings = self._reduce_false_positives(unique_findings, attack_chains)
        
        # 计算整体置信度
        confidence = self._calculate_overall_confidence(validated_findings)
        
        # 判断是否需要回流
        needs_reflow, reflow_info = self._determine_reflow_needs(validated_findings, confidence)
        
        return validated_findings, needs_reflow, reflow_info

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """去重发现的漏洞
        
        Args:
            findings: 发现的漏洞列表
            
        Returns:
            去重后的漏洞列表
        """
        seen = set()
        unique = []
        
        for finding in findings:
            # 基于规则ID和位置生成唯一键
            key_parts = [
                finding.get('rule_id', ''),
                str(finding.get('location', {}).get('file', '')),
                str(finding.get('location', {}).get('line', 0))
            ]
            key = '|'.join(key_parts)
            
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique

    def _reduce_false_positives(self, findings: List[Dict[str, Any]], attack_chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """降低误报
        
        Args:
            findings: 发现的漏洞列表
            attack_chains: 攻击链列表
            
        Returns:
            降低误报后的漏洞列表
        """
        validated = []
        
        for finding in findings:
            # 检查置信度
            confidence = finding.get('confidence', 0.0)
            if confidence < 0.5:
                continue
            
            # 检查是否有对应的攻击链
            has_attack_chain = False
            for chain in attack_chains:
                if finding.get('location') == chain.get('location'):
                    has_attack_chain = True
                    break
            
            # 对于高严重性的漏洞，即使没有攻击链也保留
            severity = finding.get('severity', 'low')
            if has_attack_chain or severity in ['critical', 'high']:
                validated.append(finding)
        
        return validated

    def _calculate_overall_confidence(self, findings: List[Dict[str, Any]]) -> float:
        """计算整体置信度
        
        Args:
            findings: 发现的漏洞列表
            
        Returns:
            整体置信度
        """
        if not findings:
            return 0.0
        
        total_confidence = sum(finding.get('confidence', 0.0) for finding in findings)
        return total_confidence / len(findings)

    def _determine_reflow_needs(self, findings: List[Dict[str, Any]], confidence: float) -> Tuple[bool, Dict[str, Any]]:
        """判断是否需要回流
        
        Args:
            findings: 发现的漏洞列表
            confidence: 整体置信度
            
        Returns:
            (是否需要回流, 回流信息)
        """
        reflow_info = {}
        
        # 置信度低于阈值需要回流
        if confidence < 0.6:
            reflow_info['action'] = 'rerun_rag'
            reflow_info['reason'] = f'整体置信度低于阈值: {confidence:.2f}'
            reflow_info['target'] = 'RAG-Agent'
            return True, reflow_info
        
        # 检查是否有需要进一步分析的漏洞
        for finding in findings:
            if finding.get('confidence', 0.0) < 0.5:
                reflow_info['action'] = 'reanalyze_function'
                reflow_info['reason'] = f'漏洞置信度低于阈值: {finding.get("confidence", 0.0):.2f}'
                reflow_info['target'] = 'AST-Agent'
                reflow_info['function'] = finding.get('metadata', {}).get('function', '')
                return True, reflow_info
        
        return False, reflow_info

    def get_standardized_output(self, validated_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """获取标准化的输出格式
        
        Args:
            validated_findings: 验证后的漏洞列表
            
        Returns:
            标准化的输出列表
        """
        return validated_findings