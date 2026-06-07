"""AST 分析插件

将 AST 分析作为插件实现。
"""

from pathlib import Path
from typing import Any, Dict, List

from src.plugins.base import ScanPlugin, PluginMetadata, PluginPriority
from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.base import AnalysisContext


class ASTAnalysisPlugin(ScanPlugin):
    """AST 分析扫描插件"""
    
    def __init__(self, config: Dict[str, Any] = None):
        metadata = PluginMetadata(
            name="ast_analysis",
            version="2.0.0",
            description="基于抽象语法树的安全分析",
            author="HOS-LS Team",
            priority=PluginPriority.HIGH,  # 高优先级
            enabled=True,
        )
        super().__init__(metadata, config)
        self._analyzer = ASTAnalyzer()
    
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
            # 创建分析上下文
            analysis_context = AnalysisContext(
                file_path=str(file_path),
                file_content=content,
                language=context.get('language', 'python')
            )
            
            # 执行 AST 分析
            result = self._analyzer.analyze(analysis_context)
            
            # 转换结果
            for issue in result.issues:
                findings.append({
                    'rule_id': issue.rule_id,
                    'rule_name': issue.message,
                    'message': issue.message,
                    'severity': issue.severity,
                    'confidence': issue.confidence,
                    'location': {
                        'file': issue.file_path,
                        'line': issue.line,
                        'column': issue.column,
                    },
                    'code_snippet': issue.code_snippet,
                    'fix_suggestion': issue.fix_suggestion if hasattr(issue, 'fix_suggestion') else '',
                    'plugin': self.name,
                })
        
        except Exception as e:
            # 分析失败，返回空列表
            pass
        
        return findings
