"""Prompt 模板管理器"""

class PromptTemplates:
    """Prompt 模板管理类（最小化实现）"""
    
    def __init__(self):
        """初始化模板管理器"""
        self.templates = {}
    
    def get_template(self, name: str) -> str:
        """获取指定名称的模板
        
        Args:
            name: 模板名称
            
        Returns:
            模板内容
        """
        return self.templates.get(name, "")
    
    def set_template(self, name: str, template: str):
        """设置模板
        
        Args:
            name: 模板名称
            template: 模板内容
        """
        self.templates[name] = template
