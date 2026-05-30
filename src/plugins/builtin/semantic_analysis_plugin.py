"""语义分析插件

将语义分析作为插件实现。
"""

from pathlib import Path
from typing import Any, Dict, List

from src.plugins.base import ScanPlugin, PluginMetadata, PluginPriority
from src.ai.local_semantic_analyzer import get_local_analyzer


class SemanticAnalysisPlugin(ScanPlugin):
    """语义分析扫描插件"""
    
    def __init__(self, config: Dict[str, Any] = None):
        metadata = PluginMetadata(
            name="semantic_analysis",
            version="2.0.0",
            description="基于语义的上下文感知安全分析",
            author="HOS-LS Team",
            priority=PluginPriority.HIGH,  # 高优先级
            enabled=True,
        )
        super().__init__(metadata, config)
        self._analyzer = get_local_analyzer()
    
    async def scan(self, file_path: Path, content: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """扫描文件
        
        Args:
            file_path: 文件路径
            content: 文件内容
            context: 扫描上下文
            
        Returns:
            发现的安全问题列表
        """
        findings = []
        
        try:
            # 执行语义分析
            result = self._analyzer.analyze(
                code=content,
                file_path=str(file_path)
            )
            
            # 如果检测到漏洞，添加到结果
            if result.is_vulnerable:
                findings.append({
                    'rule_id': f"SEMANTIC-{result.risk_level.value.upper()}",
                    'rule_name': f"语义分析: {result.reason[:50]}",
                    'message': result.reason,
                    'severity': result.risk_level.value,
                    'confidence': result.confidence,
                    'location': {
                        'file': str(file_path),
                        'line': 1,
                        'column': 0,
                    },
                    'code_snippet': content[:200] + "..." if len(content) > 200 else content,
                    'fix_suggestion': "; ".join(result.recommendations[:3]),
                    'attack_chain': result.attack_chain,
                    'plugin': self.name,
                })
        
        except Exception as e:
            # 分析失败，返回空列表
            pass
        
        return findings
