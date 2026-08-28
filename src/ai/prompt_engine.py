"""Prompt 模板引擎模块

基于 Jinja2 的模板引擎，统一管理所有 Agent 的 Prompt 模板。
"""

from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.core.config_center import get_config_center
from src.utils.logger import get_logger

logger = get_logger(__name__)

# 所有 Agent 模板共享的稳定前缀（逐字节一致，命中供应商侧 prompt/context caching，
# 后续调用对相同前缀按缓存价计费；动态内容一律置于模板末尾）
GLOBAL_PREFIX = """[CHARACTER]
你不是聊天AI，而是一个"受约束的安全分析执行模块"。
你必须严格按照协议运行。

[CORE TRAITS]
- Precision First（精确优先）
- No Assumption（禁止假设）
- Evidence Driven（基于代码事实）
- Deterministic Output（稳定输出）

[HARD RULES]
- 禁止输出解释性文本
- 禁止输出推理过程
- 禁止偏离任务
- 禁止补充未提供的信息
- 禁止使用"可能/大概/推测"等词
- 禁止空洞的"Unknown"输出

"""


class PromptEngine:
    """Prompt 模板引擎"""

    _instance: Optional["PromptEngine"] = None

    def __init__(self, templates_dir: Optional[Path] = None):
        if templates_dir is None:
            project_root = Path(__file__).parent.parent.parent
            templates_dir = project_root / "prompts" / "templates"

        self.templates_dir = Path(templates_dir)
        self._env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )
        self._config_center = get_config_center()
        logger.info(f"PromptEngine initialized with templates: {self.templates_dir}")

    @classmethod
    def get_instance(cls) -> "PromptEngine":
        """获取单例实例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def render(self, template_name: str, **kwargs: Any) -> str:
        """渲染指定模板

        Args:
            template_name: 模板文件名（如 context_builder.jinja2）
            **kwargs: 模板变量

        Returns:
            渲染后的 Prompt 字符串
        """
        try:
            template = self._env.get_template(template_name)
            rendered = template.render(**kwargs)
            logger.debug(f"Rendered template: {template_name}")
            return rendered
        except Exception as e:
            logger.error(f"Failed to render template {template_name}: {e}")
            raise

    def render_agent_prompt(self, agent_name: str, **kwargs: Any) -> str:
        """渲染 Agent Prompt

        在模板内容前统一注入 GLOBAL_PREFIX（稳定前缀，跨 Agent/跨文件相同），
        使供应商侧上下文缓存可命中，降低后续调用的输入成本。

        Args:
            agent_name: Agent 名称（如 context_builder, vulnerability_verification）
            **kwargs: 模板变量

        Returns:
            渲染后的 Prompt 字符串
        """
        agent_config = self._config_center.get_agent_config(agent_name)
        template_name = agent_config.get("template", f"{agent_name}.jinja2")
        return GLOBAL_PREFIX + self.render(template_name, **kwargs)

    def get_available_templates(self) -> list:
        """获取所有可用的模板列表"""
        return self._env.list_templates()

    @staticmethod
    def format_related_files(related_files: Any) -> str:
        """格式化相关文件信息"""
        if not related_files:
            return "无"
        if isinstance(related_files, str):
            return related_files
        formatted = []
        for i, file_info in enumerate(related_files):
            if isinstance(file_info, dict):
                path = file_info.get("path", "未知路径")
                content = file_info.get("content", "").strip()[:500]
                formatted.append(f"文件 {i + 1}: {path}\n{content}\n")
            else:
                formatted.append(f"文件 {i + 1}: {str(file_info)}\n")
        return "\n".join(formatted)

    @staticmethod
    def format_imports(imports: Any) -> str:
        """格式化导入语句"""
        if not imports:
            return "无"
        if isinstance(imports, str):
            return imports
        if isinstance(imports, list):
            return "\n".join(imports)
        return str(imports)

    @staticmethod
    def format_function_calls(function_calls: Any) -> str:
        """格式化函数调用"""
        if not function_calls:
            return "无"
        if isinstance(function_calls, str):
            return function_calls
        if isinstance(function_calls, list):
            return "\n".join(function_calls)
        return str(function_calls)


def get_prompt_engine() -> PromptEngine:
    """获取 PromptEngine 实例"""
    return PromptEngine.get_instance()
