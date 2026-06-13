"""Prompt 模板管理器"""

class PromptTemplates:
    """Prompt 模板管理类"""
    
    # 模板文件名常量
    CONTEXT_BUILDER = "context_builder.jinja2"
    CODE_UNDERSTANDING = "code_understanding.jinja2"
    RISK_ENUMERATION = "risk_enumeration.jinja2"
    VULNERABILITY_VERIFICATION = "vulnerability_verification.jinja2"
    ATTACK_CHAIN = "attack_chain.jinja2"
    ADVERSARIAL_VALIDATION = "adversarial_validation.jinja2"
    FINAL_DECISION = "final_decision.jinja2"
    FILE_PRIORITIZATION = "file_prioritization.jinja2"
    DEEP_ANALYSIS = "deep_analysis.jinja2"
    FIX_SUGGESTION = "fix_suggestion.jinja2"
    CROSS_FILE_TAINT = "cross_file_taint.jinja2"
    
    # Prompt 优化器模板（内联模板字符串）
    PROMPT_OPTIMIZER = """你是一个专业的 Prompt 优化器。请优化以下 Prompt，使其更精确、更结构化、更少歧义。

原始 Prompt:
{original_prompt}

请输出优化后的版本，保持原意但提升清晰度。"""

    ANTI_HALLUCINATION_PROMPT_OPTIMIZER = """你是一个反幻觉 Prompt 优化器。请优化以下 Prompt，确保 AI 不会编造不存在的信息。

关键约束:
- 只基于提供的代码事实
- 禁止推测和假设
- 信息不足时使用占位符
- 所有结论必须有代码依据

原始 Prompt:
{original_prompt}

请输出强化反幻觉约束的优化版本。"""
    
    # 模板目录路径
    TEMPLATES_DIR = "prompts/templates"
    
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
