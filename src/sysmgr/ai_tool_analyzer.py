"""AI 工具分析器

使用 AI 分析工具描述，生成调用模板和 AI 编排配置。
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

CATALOG_PATH = Path(__file__).parent / "catalog.json"

TAG_CATEGORIES = {
    "recon": "信息收集",
    "scanner": "扫描器",
    "exploit": "漏洞利用",
    "fuzzer": "模糊测试",
    "enum": "枚举",
    "vulnerability": "漏洞",
    "port": "端口",
    "network": "网络",
    "web": "Web",
    "dns": "DNS",
    "http": "HTTP",
    "fingerprint": "指纹",
    "directory": "目录",
    "subdomain": "子域名",
    "crawler": "爬虫",
    "tls": "TLS/SSL",
    "certificate": "证书",
    "cidr": "CIDR",
    "host-discovery": "主机发现",
    "sqli": "SQL注入",
    "database": "数据库",
    "windows": "Windows",
    "protocol": "协议",
    "lateral-movement": "横向移动",
    "ipv6": "IPv6",
    "mitm": "中间人",
    "active-directory": "Active Directory",
    "attack-path": "攻击路径",
    "library": "库",
    "packet": "数据包",
    "bruteforce": "暴力破解",
    "auth": "认证",
    "crack": "破解",
    "password": "密码",
    "proxy": "代理",
    "analysis": "分析",
    "cve": "CVE",
}


@dataclass
class ToolAnalysis:
    """工具分析结果"""

    tool_name: str
    description: str
    category: str
    ai_capability: str
    ai_input_format: str
    ai_output_format: str
    tags: list[str] = field(default_factory=list)
    input_template: str = ""
    output_schema: dict[str, Any] = field(default_factory=dict)
    orchestration_config: dict[str, Any] = field(default_factory=dict)


@dataclass
class IntegrationConfig:
    """AI 集成配置"""

    tool_name: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    capability_tags: list[str]
    prompt_template: str
    validation_rules: list[str] = field(default_factory=list)
    error_handling: dict[str, str] = field(default_factory=dict)


class AIToolAnalyzer:
    """AI 工具分析器"""

    def __init__(
        self,
        catalog_path: Optional[str] = None,
        ai_model: Optional[str] = None,
        ai_callback: Optional[callable] = None,
    ):
        self.catalog_path = Path(catalog_path) if catalog_path else CATALOG_PATH
        self.ai_model = ai_model
        self.ai_callback = ai_callback
        self._catalog: dict[str, Any] = {}
        self._load_catalog()

    def _load_catalog(self) -> None:
        """加载工具目录"""
        if self.catalog_path.exists():
            with open(self.catalog_path, "r", encoding="utf-8") as f:
                self._catalog = json.load(f)
            logger.info(
                "[AI_ANALYZER] 目录已加载: %d 个工具",
                len(self._catalog.get("tools", [])),
            )
        else:
            logger.warning("[AI_ANALYZER] 目录文件不存在: %s", self.catalog_path)
            self._catalog = {"tools": []}

    def _find_tool(self, tool_name: str) -> Optional[dict]:
        """查找工具"""
        for tool in self._catalog.get("tools", []):
            if tool.get("name", "").lower() == tool_name.lower():
                return tool
        return None

    def analyze_tool(self, tool_name: str) -> Optional[ToolAnalysis]:
        """分析单个工具

        Args:
            tool_name: 工具名称

        Returns:
            工具分析结果，未找到时返回 None
        """
        tool = self._find_tool(tool_name)
        if not tool:
            logger.warning("[AI_ANALYZER] 未找到工具: %s", tool_name)
            return None

        logger.info("[AI_ANALYZER] 分析工具: %s", tool_name)

        if self.ai_callback:
            try:
                analysis = self._ai_analyze(tool)
                if analysis:
                    return analysis
            except Exception as e:
                logger.warning(
                    "[AI_ANALYZER] AI 分析失败，使用规则分析: %s",
                    e,
                )

        return self._rule_analyze(tool)

    def _ai_analyze(self, tool: dict) -> Optional[ToolAnalysis]:
        """使用 AI 分析工具"""
        if not self.ai_callback:
            return None

        prompt = self._build_analysis_prompt(tool)
        result = self.ai_callback(prompt)

        if result:
            try:
                if isinstance(result, str):
                    result = json.loads(result)

                return ToolAnalysis(
                    tool_name=tool.get("name", ""),
                    description=tool.get("description", ""),
                    category=tool.get("category", ""),
                    ai_capability=result.get("ai_capability", tool.get("ai_capability", "")),
                    ai_input_format=result.get("ai_input_format", tool.get("ai_input_format", "")),
                    ai_output_format=result.get("ai_output_format", tool.get("ai_output_format", "")),
                    tags=tool.get("tags", []),
                    input_template=result.get("input_template", ""),
                    output_schema=result.get("output_schema", {}),
                    orchestration_config=result.get("orchestration_config", {}),
                )
            except Exception as e:
                logger.warning("[AI_ANALYZER] 解析 AI 结果失败: %s", e)

        return None

    def _rule_analyze(self, tool: dict) -> ToolAnalysis:
        """使用规则分析工具"""
        tool_name = tool.get("name", "")
        description = tool.get("description", "")
        category = tool.get("category", "")
        tags = tool.get("tags", [])

        input_template = self._generate_input_template(tool)
        output_schema = self._generate_output_schema(tool)
        orchestration_config = self._generate_orchestration_config(tool)

        analysis = ToolAnalysis(
            tool_name=tool_name,
            description=description,
            category=category,
            ai_capability=tool.get("ai_capability", f"自动化{description}功能"),
            ai_input_format=tool.get("ai_input_format", ""),
            ai_output_format=tool.get("ai_output_format", ""),
            tags=tags,
            input_template=input_template,
            output_schema=output_schema,
            orchestration_config=orchestration_config,
        )

        logger.info("[AI_ANALYZER] 规则分析完成: %s", tool_name)
        return analysis

    def _generate_input_template(self, tool: dict) -> str:
        """生成输入模板"""
        name = tool.get("name", "")
        tags = tool.get("tags", [])
        category = tool.get("category", "")

        templates = {
            "recon": f"--targets <目标文件>\n--output <输出文件>",
            "scanner": f"--target <目标URL/IP>\n--port <端口范围>\n--output <输出文件>",
            "exploit": f"--target <目标>\n--payload <攻击载荷>\n--options <选项>",
            "fuzzer": f"--url <目标URL>\n--wordlist <字典文件>\n--extensions <扩展名>",
            "enum": f"--target <目标>\n--wordlist <字典文件>\n--output <输出文件>",
        }

        for tag in tags:
            if tag in templates:
                return templates[tag]

        return f"--help  # 查看 {name} 的可用选项"

    def _generate_output_schema(self, tool: dict) -> dict[str, Any]:
        """生成输出 Schema"""
        tags = tool.get("tags", [])

        schema = {
            "type": "object",
            "properties": {
                "tool": tool.get("name", ""),
                "timestamp": {"type": "string", "format": "date-time"},
                "status": {"type": "string", "enum": ["success", "error", "timeout"]},
            },
            "required": ["tool", "timestamp", "status"],
        }

        if "scanner" in tags or "vulnerability" in tags:
            schema["properties"]["findings"] = {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "target": {"type": "string"},
                        "evidence": {"type": "string"},
                    },
                },
            }

        if "recon" in tags or "enum" in tags:
            schema["properties"]["results"] = {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "status_code": {"type": "integer"},
                        "title": {"type": "string"},
                        "tech_stack": {"type": "array", "items": {"type": "string"}},
                    },
                },
            }

        if "exploit" in tags:
            schema["properties"]["exploit_result"] = {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "shell": {"type": "boolean"},
                    "data_extracted": {"type": "string"},
                },
            }

        return schema

    def _generate_orchestration_config(self, tool: dict) -> dict[str, Any]:
        """生成编排配置"""
        name = tool.get("name", "")
        tags = tool.get("tags", [])
        category = tool.get("category", "")
        version_cmd = tool.get("version_cmd", "--version")
        install_cmd = tool.get("install_cmd", {})

        install_str = ""
        if isinstance(install_cmd, dict):
            install_str = install_cmd.get("pip", install_cmd.get("go", install_cmd.get("apt", "")))
        elif isinstance(install_cmd, str):
            install_str = install_cmd

        config = {
            "tool_name": name,
            "category": category,
            "tags": tags,
            "install_command": install_str,
            "version_command": f"{name} {version_cmd}",
            "timeout": self._get_default_timeout(tags),
            "retry_count": 2,
            "parallel_safe": "recon" in tags or "enum" in tags,
            "requires_root": "scanner" in tags or "exploit" in tags,
        }

        if "scanner" in tags:
            config["rate_limit"] = True
            config["max_concurrent"] = 10
        elif "fuzzer" in tags:
            config["rate_limit"] = True
            config["max_concurrent"] = 5
            config["wordlist_required"] = True

        return config

    def _get_default_timeout(self, tags: list[str]) -> int:
        """获取默认超时时间（秒）"""
        if "exploit" in tags:
            return 300
        if "scanner" in tags:
            return 600
        if "fuzzer" in tags:
            return 900
        return 120

    def _build_analysis_prompt(self, tool: dict) -> str:
        """构建 AI 分析提示词"""
        return f"""分析以下安全工具，生成 AI 集成配置：

工具名称: {tool.get('name', '')}
描述: {tool.get('description', '')}
分类: {tool.get('category', '')}
标签: {', '.join(tool.get('tags', []))}

请返回 JSON 格式：
{{
  "ai_capability": "工具能做什么",
  "ai_input_format": "AI如何调用（输入格式）",
  "ai_output_format": "输出格式",
  "input_template": "命令行输入模板",
  "output_schema": {{...}},
  "orchestration_config": {{...}}
}}"""

    def generate_integration_config(self, tool_name: str) -> Optional[IntegrationConfig]:
        """生成工具的 AI 集成配置

        Args:
            tool_name: 工具名称

        Returns:
            集成配置，未找到时返回 None
        """
        analysis = self.analyze_tool(tool_name)
        if not analysis:
            return None

        tool = self._find_tool(tool_name)
        if not tool:
            return None

        prompt_template = self._generate_prompt_template(analysis)
        validation_rules = self._generate_validation_rules(analysis)
        error_handling = self._generate_error_handling(analysis)

        return IntegrationConfig(
            tool_name=analysis.tool_name,
            input_schema=analysis.output_schema,
            output_schema=analysis.output_schema,
            capability_tags=analysis.tags,
            prompt_template=prompt_template,
            validation_rules=validation_rules,
            error_handling=error_handling,
        )

    def _generate_prompt_template(self, analysis: ToolAnalysis) -> str:
        """生成 AI 提示词模板"""
        return f"""你是一个安全工具编排助手。使用以下工具执行任务：

工具: {analysis.tool_name}
能力: {analysis.ai_capability}
输入格式: {analysis.ai_input_format}
输出格式: {analysis.ai_output_format}

请按照以下步骤执行：
1. 验证输入参数
2. 构造命令行
3. 执行工具
4. 解析输出
5. 返回结构化结果

输入模板:
{analysis.input_template}"""

    def _generate_validation_rules(self, analysis: ToolAnalysis) -> list[str]:
        """生成验证规则"""
        rules = []

        if "recon" in analysis.tags or "scanner" in analysis.tags:
            rules.append("target_required: 必须指定目标URL或IP")
            rules.append("target_format: 目标必须是有效的URL或IP地址")

        if "exploit" in analysis.tags:
            rules.append("authorization_required: 必须有授权才能执行利用")
            rules.append("target_scope: 目标必须在授权范围内使用")

        if "fuzzer" in analysis.tags:
            rules.append("wordlist_required: 必须提供字典文件")
            rules.append("rate_limit: 必须设置请求速率限制")

        rules.append("timeout: 执行时间不能超过配置的限制")
        rules.append("output_format: 输出必须是有效的JSON格式")

        return rules

    def _generate_error_handling(self, analysis: ToolAnalysis) -> dict[str, str]:
        """生成错误处理策略"""
        return {
            "timeout": f"工具 {analysis.tool_name} 执行超时，尝试增加超时时间或减少目标范围",
            "permission_denied": f"需要更高权限执行 {analysis.tool_name}，尝试使用 sudo",
            "tool_not_found": f"工具 {analysis.tool_name} 未安装，请先安装",
            "invalid_input": f"输入参数无效，检查目标格式和参数值",
            "network_error": f"网络错误，检查代理设置和网络连接",
            "rate_limit": f"触发速率限制，降低请求频率",
        }

    def analyze_all_tools(self) -> list[ToolAnalysis]:
        """分析目录中的所有工具

        Returns:
            工具分析结果列表
        """
        tools = self._catalog.get("tools", [])
        analyses: list[ToolAnalysis] = []

        for tool in tools:
            tool_name = tool.get("name", "")
            analysis = self.analyze_tool(tool_name)
            if analysis:
                analyses.append(analysis)

        logger.info(
            "[AI_ANALYZER] 全部工具分析完成: %d/%d",
            len(analyses),
            len(tools),
        )
        return analyses

    def get_capability_map(self) -> dict[str, list[str]]:
        """获取能力到工具的映射

        Returns:
            {能力标签: [工具名列表]}
        """
        capability_map: dict[str, list[str]] = {}

        for tool in self._catalog.get("tools", []):
            tags = tool.get("tags", [])
            name = tool.get("name", "")

            for tag in tags:
                if tag not in capability_map:
                    capability_map[tag] = []
                capability_map[tag].append(name)

        logger.info(
            "[AI_ANALYZER] 能力映射生成完成: %d 个能力类别",
            len(capability_map),
        )
        return capability_map

    def export_analysis(
        self,
        analyses: Optional[list[ToolAnalysis]] = None,
        output_path: Optional[str] = None,
    ) -> str:
        """导出分析结果为 JSON

        Args:
            analyses: 分析结果列表，为 None 时分析所有工具
            output_path: 输出文件路径

        Returns:
            JSON 字符串
        """
        if analyses is None:
            analyses = self.analyze_all_tools()

        export_data = {
            "generated_at": __import__("datetime").datetime.now().isoformat(),
            "total_tools": len(analyses),
            "tools": [
                {
                    "tool_name": a.tool_name,
                    "description": a.description,
                    "category": a.category,
                    "ai_capability": a.ai_capability,
                    "ai_input_format": a.ai_input_format,
                    "ai_output_format": a.ai_output_format,
                    "tags": a.tags,
                    "input_template": a.input_template,
                    "output_schema": a.output_schema,
                    "orchestration_config": a.orchestration_config,
                }
                for a in analyses
            ],
        }

        json_str = json.dumps(export_data, indent=2, ensure_ascii=False)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_str)
            logger.info("[AI_ANALYZER] 分析结果已导出: %s", output_path)

        return json_str
