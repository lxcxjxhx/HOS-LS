"""正则规则插件

将正则规则作为插件实现。
"""

from pathlib import Path
from typing import Any, Dict, List

from src.plugins.base import ScanPlugin, PluginMetadata, PluginPriority
from src.rules.registry import get_registry


class RegexRulesPlugin(ScanPlugin):
    """正则规则扫描插件"""
    
    def __init__(self, config: Dict[str, Any] = None):
        metadata = PluginMetadata(
            name="regex_rules",
            version="2.0.0",
            description="基于正则表达式的安全规则扫描",
            author="HOS-LS Team",
            priority=PluginPriority.NORMAL,
            enabled=True,
        )
        super().__init__(metadata, config)
        self._registry = get_registry()
        self._registry.load_builtin_rules()
    
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
        
        # 获取适用于当前语言的规则
        language = context.get('language', 'python')
        rules = self._registry.get_rules_by_language(language)
        
        # 构建目标对象
        target = {
            'content': content,
            'file_path': str(file_path)
        }
        
        # 应用规则
        for rule in rules:
            if rule.is_enabled():
                try:
                    rule_findings = rule.check(target)
                    for finding in rule_findings:
                        findings.append({
                            'rule_id': finding.rule_id,
                            'rule_name': finding.rule_name,
                            'message': finding.message,
                            'severity': finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
                            'confidence': finding.confidence,
                            'location': finding.location,
                            'code_snippet': finding.code_snippet,
                            'fix_suggestion': finding.fix_suggestion,
                            'plugin': self.name,
                        })
                except Exception as e:
                    # 规则执行失败，继续下一个
                    pass
        
        return findings
