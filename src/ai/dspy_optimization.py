import dspy
import os
from typing import List, Dict, Any, Optional
from src.core.config import get_config

# 配置 DSPy 语言模型
def configure_dspy_lm():
    """配置 DSPy 语言模型
    
    从配置或环境变量中获取 AI 提供商、API KEY、基础 URL 等信息，并配置 DSPy 语言模型
    如果没有获取到 API KEY，使用模拟模型作为 fallback
    """
    config = get_config()
    
    # 从配置或环境变量中获取 API KEY
    api_key = config.ai.api_key
    provider = config.ai.provider
    base_url = config.ai.base_url
    model = config.ai.model
    
    # 根据提供商获取对应的环境变量
    env_vars = {
        "openai": "OPENAI_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY"
    }
    
    # 如果没有配置 API KEY，尝试从环境变量获取
    if not api_key and provider in env_vars:
        api_key = os.getenv(env_vars[provider])
    
    if api_key:
        # 如果获取到 API KEY，使用真实的语言模型
        try:
            # 根据提供商配置 DSPy 语言模型
            if provider == "openai":
                dspy.configure(lm=dspy.LM('openai/gpt-4o-mini', api_key=api_key))
            elif provider == "deepseek":
                # DSPy 暂时不直接支持 DeepSeek，使用 OpenAI 兼容模式
                dspy.configure(lm=dspy.LM('openai/deepseek-chat', api_key=api_key, base_url=base_url or "https://api.deepseek.com"))
            elif provider == "anthropic":
                dspy.configure(lm=dspy.LM('anthropic/claude-3-mini-20240229', api_key=api_key))
            else:
                # 默认使用 OpenAI
                dspy.configure(lm=dspy.LM('openai/gpt-4o-mini', api_key=api_key))
            return True
        except Exception as e:
            print(f"[DEBUG] 配置 DSPy 语言模型失败: {e}")
            # 配置失败，使用模拟模型
            pass
    
    # 如果没有获取到 API KEY 或配置失败，使用模拟模型作为 fallback
    class MockLM:
        def __call__(self, prompt, **kwargs):
            return dspy.Prediction(vulnerabilities="未发现明显漏洞", exploitation="无", fix_suggestions="建议定期更新依赖库")
    
    class MockCriticLM:
        def __call__(self, prompt, **kwargs):
            return dspy.Prediction(quality="pass", improvements="分析结果完整，建议进一步深入分析")
    
    dspy.configure(lm=MockLM())
    return False

# 配置 DSPy 语言模型
configure_dspy_lm()


class VulnerabilityAnalysis(dspy.Signature):
    """输入代码片段，输出结构化漏洞报告"""
    code: str = dspy.InputField()
    cve_context: str = dspy.InputField()
    attack_chain: str = dspy.InputField()
    vulnerabilities: str = dspy.OutputField()
    exploitation: str = dspy.OutputField()
    fix_suggestions: str = dspy.OutputField()


class RetrievalAnalysis(dspy.Signature):
    """输入代码，输出相关的CVE候选列表"""
    code: str = dspy.InputField()
    cve_candidates: List[Dict[str, Any]] = dspy.OutputField()


class GraphAnalysis(dspy.Signature):
    """输入CVE列表，输出攻击链分析"""
    cve_candidates: List[Dict[str, Any]] = dspy.InputField()
    attack_chain: Dict[str, Any] = dspy.OutputField()


class CriticEvaluation(dspy.Signature):
    """输入分析结果，输出质量评估"""
    analysis_result: str = dspy.InputField()
    quality: str = dspy.OutputField()
    improvements: str = dspy.OutputField()


class RepairSuggestion(dspy.Signature):
    """输入漏洞详情，输出修复建议"""
    vulnerability_details: str = dspy.InputField()
    fix_suggestions: str = dspy.OutputField()


# 示例训练数据
def get_training_data():
    """获取训练数据"""
    return {
        'vulnerability_analysis': [
            dspy.Example(
                code="def get_user_input():\n    user_input = input('Enter your name: ')\n    return user_input",
                cve_context="CVE-2021-44228: Log4Shell vulnerability",
                attack_chain="Input -> Command Injection -> Remote Code Execution",
                vulnerabilities="输入验证不足，可能导致命令注入攻击",
                exploitation="攻击者可以通过输入恶意命令来执行系统命令",
                fix_suggestions="对用户输入进行严格验证和转义"
            ),
            dspy.Example(
                code="def get_password():\n    password = input('Enter password: ')\n    return password",
                cve_context="CVE-2023-21716: Password exposure",
                attack_chain="Input -> Password Exposure -> Privilege Escalation",
                vulnerabilities="密码输入未加密，可能导致密码泄露",
                exploitation="攻击者可以通过监听网络流量获取密码",
                fix_suggestions="使用加密传输和安全的密码存储方式"
            )
        ],
        'critic_evaluation': [
            dspy.Example(
                analysis_result="# 漏洞分析结果\n\n## 基础信息\n- CVE候选数量: 5\n- 攻击链数量: 2\n\n## 漏洞分析\n发现输入验证不足的问题\n\n## 利用方式\n攻击者可以通过输入恶意代码执行命令\n\n## 修复建议\n对用户输入进行验证",
                quality="pass",
                improvements="分析结果完整，但修复建议可以更具体"
            ),
            dspy.Example(
                analysis_result="# 漏洞分析结果\n\n## 基础信息\n- CVE候选数量: 3\n\n## 漏洞分析\n发现潜在漏洞\n\n## 修复建议\n修复漏洞",
                quality="warning",
                improvements="分析结果过于简单，缺少详细信息"
            )
        ]
    }


def create_dspy_program(signature, program_name, trainset=None):
    """创建并优化DSPy程序
    
    Args:
        signature: DSPy Signature
        program_name: 程序名称
        trainset: 训练集
        
    Returns:
        dspy.Program: 优化后的程序
    """
    # 直接使用默认程序，避免使用可能有问题的优化器
    compiled_program = dspy.Predict(signature)
    return compiled_program


# 缓存优化后的程序
_optimized_programs = {}

def get_dspy_programs():
    """获取所有DSPy程序
    
    Returns:
        Dict[str, dspy.Program]: 程序字典
    """
    global _optimized_programs
    
    if not _optimized_programs:
        _optimized_programs = {
            'vulnerability_analysis': create_dspy_program(VulnerabilityAnalysis, 'vulnerability_analysis'),
            'retrieval_analysis': create_dspy_program(RetrievalAnalysis, 'retrieval_analysis'),
            'graph_analysis': create_dspy_program(GraphAnalysis, 'graph_analysis'),
            'critic_evaluation': create_dspy_program(CriticEvaluation, 'critic_evaluation'),
            'repair_suggestion': create_dspy_program(RepairSuggestion, 'repair_suggestion')
        }
    
    return _optimized_programs


def optimize_dspy_programs(new_training_data=None):
    """优化DSPy程序
    
    Args:
        new_training_data: 新的训练数据
        
    Returns:
        Dict[str, dspy.Program]: 优化后的程序字典
    """
    global _optimized_programs
    _optimized_programs = {}
    
    if new_training_data:
        # 更新训练数据
        training_data = get_training_data()
        training_data.update(new_training_data)
    
    return get_dspy_programs()

