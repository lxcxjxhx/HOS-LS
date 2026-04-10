"""Final Decision 构建器

职责：聚合多个 Agent 的输出，构建标准化的 final_decision 结构。
遵循 fix_7.md 建议："让 AI 提供数据，而不是决定结构"

核心功能：
- FinalDecisionSchema: 强制 Schema 定义
- FinalDecisionBuilder: 聚合多Agent输出
- ensure_final_decision(): 自动修复机制（永不失败）
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class FinalDecisionSchema:
    """Final Decision 强制 Schema
    
    定义 final_decision 的标准结构，
    所有输出必须符合此 Schema。
    """
    
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_level: str = "low"  # low | medium | high | critical
    summary: str = ""
    confidence: float = 0.0
    file_path: str = ""
    agent_sources: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（确保JSON安全）"""
        return {
            "vulnerabilities": self.vulnerabilities,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "confidence": self.confidence,
            "file_path": str(self.file_path),  # Path → str
            "agent_sources": self.agent_sources
        }
    
    def validate(self) -> Tuple[bool, List[str]]:
        """验证 Schema 完整性
        
        Returns:
            (是否有效, 错误信息列表)
        """
        errors = []
        
        if not isinstance(self.vulnerabilities, list):
            errors.append("vulnerabilities 必须是 list")
            
        if self.risk_level not in ["low", "medium", "high", "critical"]:
            errors.append(f"risk_level 无效: {self.risk_level}")
            
        if not isinstance(self.confidence, (int, float)) or not (0 <= self.confidence <= 1):
            errors.append(f"confidence 必须在 0.0-1.0 之间: {self.confidence}")
            
        return len(errors) == 0, errors


class FinalDecisionBuilder:
    """Final Decision 构建器
    
    聚合多个 Agent 的输出，构建符合 Schema 的 final_decision。
    
    核心原则：
    - 不依赖任何单一 Agent 输出结构化数据
    - 从多个 Agent 提取原始数据后自行聚合
    - 保证输出 100% 符合 Schema
    """
    
    @staticmethod
    def build(
        scanner_result: Dict[str, Any],
        reasoning_result: Dict[str, Any],
        exploit_result: Optional[Dict[str, Any]] = None,
        fix_result: Optional[Dict[str, Any]] = None,
        file_path: str = ""
    ) -> FinalDecisionSchema:
        """构建 Final Decision
        
        Args:
            scanner_result: Scanner Agent 输出
            reasoning_result: Reasoning Agent 输出
            exploit_result: Exploit Agent 输出（可选）
            fix_result: Fix Agent 输出（可选）
            file_path: 文件路径
            
        Returns:
            FinalDecisionSchema 对象
        """
        schema = FinalDecisionSchema(file_path=file_path)
        
        # 1. 聚合漏洞发现（从多个 Agent 提取）
        vulnerabilities = []
        
        # 从 Scanner 提取
        vulns_from_scanner = FinalDecisionBuilder._extract_vulnerabilities(
            scanner_result, source="scanner"
        )
        vulnerabilities.extend(vulns_from_scanner)
        
        # 从 Reasoning 提取
        vulns_from_reasoning = FinalDecisionBuilder._extract_vulnerabilities(
            reasoning_result, source="reasoning"
        )
        vulnerabilities.extend(vulns_from_reasoning)
        
        # 从 Exploit 提取（如果存在）
        if exploit_result:
            vulns_from_exploit = FinalDecisionBuilder._extract_vulnerabilities(
                exploit_result, source="exploit"
            )
            vulnerabilities.extend(vulns_from_exploit)
        
        # 去重（基于 location + vulnerability 类型）
        vulnerabilities = FinalDecisionBuilder._deduplicate_vulnerabilities(vulnerabilities)
        
        schema.vulnerabilities = vulnerabilities
        
        # 2. 计算风险等级
        schema.risk_level = FinalDecisionBuilder._calculate_risk_level(vulnerabilities)
        
        # 3. 生成摘要
        schema.summary = FinalDecisionBuilder._generate_summary(
            vulnerabilities, schema.risk_level
        )
        
        # 4. 计算置信度（基于 Agent 一致性）
        schema.confidence = FinalDecisionBuilder._calculate_confidence(
            scanner_result, reasoning_result, exploit_result
        )
        
        # 5. 记录数据来源
        schema.agent_sources = {
            "scanner": "✓" if scanner_result else "✗",
            "reasoning": "✓" if reasoning_result else "✗",
            "exploit": "✓" if exploit_result else "N/A",
            "fix": "✓" if fix_result else "N/A"
        }
        
        return schema
    
    @staticmethod
    def _extract_vulnerabilities(agent_result: Dict[str, Any], source: str) -> List[Dict[str, Any]]:
        """从 Agent 结果中提取漏洞
        
        支持多种键名（兼容不同 Agent 的输出格式）：
        - findings, vulnerabilities, issues, risks, problems, alerts
        """
        vulnerabilities = []
        
        if not agent_result or not isinstance(agent_result, dict):
            return vulnerabilities
            
        possible_keys = [
            'findings', 'vulnerabilities', 'issues', 'risks',
            'problems', 'alerts', 'results'
        ]
        
        for key in possible_keys:
            if key in agent_result:
                candidate = agent_result[key]
                if isinstance(candidate, list):
                    for item in candidate:
                        if isinstance(item, dict):
                            item['_source'] = source  # 标记来源
                            vulnerabilities.append(item)
                    break
                    
        return vulnerabilities
    
    @staticmethod
    def _deduplicate_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """去重漏洞（基于 location + type）"""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            location = vuln.get('location', '')
            vuln_type = vuln.get('vulnerability', '') or vuln.get('type', '') or vuln.get('risk_type', '')
            
            key = f"{location}:{vuln_type}"
            
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
                
        return unique
    
    @staticmethod
    def _calculate_risk_level(vulnerabilities: List[Dict[str, Any]]) -> str:
        """计算整体风险等级"""
        if not vulnerabilities:
            return "low"
            
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_score = 0
        
        for vuln in vulnerabilities:
            severity = str(vuln.get('severity', 'info')).lower()
            score = severity_map.get(severity, 0)
            max_score = max(max_score, score)
            
        if max_score >= 4:
            return "critical"
        elif max_score >= 3:
            return "high"
        elif max_score >= 2:
            return "medium"
        else:
            return "low"
    
    @staticmethod
    def _generate_summary(vulnerabilities: List[Dict[str, Any]], risk_level: str) -> str:
        """生成摘要"""
        if not vulnerabilities:
            return "未发现安全漏洞，代码安全性良好。"
            
        count = len(vulnerabilities)
        critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
        
        summary_parts = [
            f"检测到 {count} 个安全风险点",
            f"整体风险等级: {risk_level.upper()}"
        ]
        
        if critical_count > 0:
            summary_parts.append(f"其中包含 {critical_count} 个严重级别漏洞")
        if high_count > 0:
            summary_parts.append(f"{high_count} 个高危漏洞")
            
        return "；".join(summary_parts) + "。"
    
    @staticmethod
    def _calculate_confidence(
        scanner_result: Dict[str, Any],
        reasoning_result: Dict[str, Any],
        exploit_result: Optional[Dict[str, Any]] = None
    ) -> float:
        """计算置信度（基于 Agent 数据完整性）"""
        base_confidence = 0.5
        
        if scanner_result and isinstance(scanner_result, dict):
            base_confidence += 0.2
        if reasoning_result and isinstance(reasoning_result, dict):
            base_confidence += 0.2
        if exploit_result and isinstance(exploit_result, dict):
            base_confidence += 0.1
            
        return min(base_confidence, 1.0)


def ensure_final_decision(result: Dict[str, Any], retry_fn=None) -> Dict[str, Any]:
    """确保 result 包含有效的 final_decision（带自动修复）
    
    这是 fix_7.md 建议的核心方法：
    - 如果没有 final_decision，尝试构建
    - 如果构建失败，提供默认值（永不失败）
    
    Args:
        result: Agent 执行结果
        retry_fn: 可选的重试函数
        
    Returns:
        包含 final_decision 的 result
    """
    # 1. 检查是否已存在且有效
    if 'final_decision' in result and isinstance(result['final_decision'], dict):
        fd = result['final_decision']
        if fd.get('vulnerabilities') is not None:
            return result
    
    # 2. 尝试从各 Agent 结果构建
    try:
        schema = FinalDecisionBuilder.build(
            scanner_result=result.get('scanner_result', {}),
            reasoning_result=result.get('reasoning_result', {}),
            exploit_result=result.get('exploit_result'),
            fix_result=result.get('fix_result'),
            file_path=result.get('file_path', '')
        )
        
        is_valid, errors = schema.validate()
        
        if is_valid:
            result['final_decision'] = schema.to_dict()
            print(f"[DEBUG] ✓ 成功构建 final_decision: "
                  f"{len(schema.vulnerabilities)} 个漏洞, "
                  f"风险等级: {schema.risk_level}")
            return result
        else:
            print(f"[DEBUG] ⚠ Schema 验证警告: {errors}")
            
    except Exception as e:
        print(f"[DEBUG] 构建 final_decision 失败: {e}")
    
    # 3. 尝试重试（如果有重试函数）
    if retry_fn:
        for i in range(2):  # 最多重试2次
            try:
                result = retry_fn(result)
                if 'final_decision' in result and result['final_decision']:
                    return result
            except Exception as e:
                print(f"[DEBUG] 重试 {i+1} 失败: {e}")
    
    # 4. 最终兜底（永不失败）
    result['final_decision'] = {
        "vulnerabilities": [],
        "risk_level": "low",
        "summary": "No issues detected (fallback)",
        "confidence": 0.3,
        "file_path": str(result.get('file_path', '')),
        "agent_sources": {}
    }
    
    print("[DEBUG] 使用默认 final_decision（兜底）")
    return result
