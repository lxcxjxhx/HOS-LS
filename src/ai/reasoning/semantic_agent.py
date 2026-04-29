"""语义分析 Agent

基于 AI 的语义理解和漏洞分析，作为推理增强器。
"""

from typing import Dict, List, Any, Optional

from src.ai.client import AIClient
from src.ai.prompts import get_semantic_analysis_prompt
from src.ai.models import VulnerabilityFinding


class SemanticAgent:
    """语义分析 Agent
    
    基于 AI 对代码进行语义理解，分析潜在的安全漏洞。
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化语义分析 Agent
        
        Args:
            config: 配置参数
        """
        self.config = config or {}
        self.ai_client = AIClient()

    def analyze(self, code: str, evidence: List[Dict[str, Any]], taint_paths: List[Dict[str, Any]], cve_patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """执行语义分析
        
        Args:
            code: 代码内容
            evidence: 证据列表
            taint_paths: 污点路径列表
            cve_patterns: CVE 模式列表
            
        Returns:
            语义分析结果
        """
        # 构建分析输入
        analysis_input = {
            "code": code,
            "evidence": evidence,
            "taint_paths": taint_paths,
            "cve_patterns": cve_patterns
        }
        
        # 获取分析提示
        prompt = get_semantic_analysis_prompt(analysis_input)
        
        # 调用 AI 进行分析
        result = self.ai_client.generate(prompt)
        
        # 解析结果
        return self._parse_result(result, code)

    def _parse_result(self, result: str, code: str) -> List[Dict[str, Any]]:
        """解析 AI 分析结果
        
        Args:
            result: AI 生成的结果
            code: 原始代码
            
        Returns:
            标准化的分析结果
        """
        import json
        
        try:
            # 尝试解析 JSON 结果
            parsed_result = json.loads(result)
            return self._convert_to_standardized(parsed_result, code)
        except json.JSONDecodeError:
            # 如果不是 JSON，尝试解析文本结果
            return self._parse_text_result(result, code)

    def _convert_to_standardized(self, result: Dict[str, Any], code: str) -> List[Dict[str, Any]]:
        """将解析结果转换为标准化格式
        
        Args:
            result: 解析后的结果
            code: 原始代码
            
        Returns:
            标准化的分析结果
        """
        output = []
        
        if isinstance(result, dict):
            if "vulnerabilities" in result:
                for vuln in result["vulnerabilities"]:
                    output.append({
                        "type": "finding",
                        "rule_id": vuln.get("rule_id", "SEMANTIC-001"),
                        "message": vuln.get("message", "语义分析发现潜在漏洞"),
                        "severity": vuln.get("severity", "medium"),
                        "confidence": vuln.get("confidence", 0.8),
                        "location": vuln.get("location", {"file": "unknown", "line": 1}),
                        "evidence": [f"Semantic: {vuln.get('message', '语义分析发现潜在漏洞')}"],
                        "source_agent": "Semantic-Agent",
                        "metadata": {
                            "vulnerability_type": vuln.get("vulnerability_type", "Unknown"),
                            "exploitability": vuln.get("exploitability", "Medium"),
                            "reasoning": vuln.get("reasoning", "")
                        }
                    })
            else:
                # 单个漏洞结果
                output.append({
                    "type": "finding",
                    "rule_id": result.get("rule_id", "SEMANTIC-001"),
                    "message": result.get("message", "语义分析发现潜在漏洞"),
                    "severity": result.get("severity", "medium"),
                    "confidence": result.get("confidence", 0.8),
                    "location": result.get("location", {"file": "unknown", "line": 1}),
                    "evidence": [f"Semantic: {result.get('message', '语义分析发现潜在漏洞')}"],
                    "source_agent": "Semantic-Agent",
                    "metadata": {
                        "vulnerability_type": result.get("vulnerability_type", "Unknown"),
                        "exploitability": result.get("exploitability", "Medium"),
                        "reasoning": result.get("reasoning", "")
                    }
                })
        
        return output

    def _parse_text_result(self, result: str, code: str) -> List[Dict[str, Any]]:
        """解析文本格式的结果
        
        Args:
            result: 文本结果
            code: 原始代码
            
        Returns:
            标准化的分析结果
        """
        output = []
        
        # 简单解析文本结果
        lines = result.split('\n')
        finding = {
            "type": "finding",
            "rule_id": "SEMANTIC-001",
            "message": "语义分析发现潜在漏洞",
            "severity": "medium",
            "confidence": 0.7,
            "location": {"file": "unknown", "line": 1},
            "evidence": [f"Semantic: {result[:200]}..." if len(result) > 200 else result],
            "source_agent": "Semantic-Agent",
            "metadata": {
                "vulnerability_type": "Unknown",
                "exploitability": "Medium",
                "reasoning": result
            }
        }
        
        output.append(finding)
        return output

    def get_standardized_output(self, analysis_result: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """获取标准化的输出格式
        
        Args:
            analysis_result: 分析结果
            
        Returns:
            标准化的输出列表
        """
        return analysis_result