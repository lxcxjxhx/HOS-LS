"""Prompt 管理器兼容层

保留旧接口以兼容现有代码，新代码应使用 prompt_engine。
"""

from typing import Dict, Any, Optional
from src.ai.prompt_engine import get_prompt_engine, PromptEngine

_prompt_manager: Optional['PromptManager'] = None


class PromptManager:
    """提示词管理器（兼容层）"""

    def __init__(self, config=None):
        self._engine = get_prompt_engine()

    def get_prompt(self, key: str, default: Optional[str] = None) -> str:
        return ""

    def set_prompt(self, key: str, value: str) -> None:
        pass

    def list_prompts(self) -> list:
        return []

    def render_template(self, key: str, variables: Dict[str, str]) -> str:
        return ""


def get_prompt_manager(config=None) -> PromptManager:
    """获取提示词管理器实例"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager(config)
    return _prompt_manager


def get_semantic_analysis_prompt(analysis_input: Dict[str, Any]) -> str:
    """获取语义分析提示词"""
    engine = get_prompt_engine()
    code = analysis_input.get('code', '')
    evidence = analysis_input.get('evidence', [])
    taint_paths = analysis_input.get('taint_paths', [])
    cve_patterns = analysis_input.get('cve_patterns', [])

    evidence_str = '\n'.join([str(item) for item in evidence])
    taint_paths_str = '\n'.join([str(item) for item in taint_paths])
    cve_patterns_str = '\n'.join([str(item) for item in cve_patterns])

    return f"""你是专业的语义安全分析专家，负责基于代码和现有证据进行深入的语义理解和漏洞分析。

[分析任务]
基于提供的代码、证据、污点路径和CVE模式，进行全面的语义分析，识别潜在的安全漏洞。

[分析输入]
代码:
{code}

现有证据:
{evidence_str}

污点路径:
{taint_paths_str}

CVE模式:
{cve_patterns_str}

[分析要求]
1. 深入理解代码的语义结构和逻辑流程
2. 结合现有证据和污点路径进行综合分析
3. 识别潜在的安全漏洞
4. 对每个发现的漏洞提供详细的分析和评估
5. 生成标准化的输出格式

[输出格式]
请以JSON格式输出分析结果。
"""
