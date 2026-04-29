"""AI 决策引擎

提供 AI 辅助的目标分析、策略规划和结果分析能力。
集成现有 LLM Provider 实现智能决策。
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

try:
    from src.ai.providers.deepseek import DeepSeekProvider
    AI_PROVIDERS_AVAILABLE = True
except ImportError:
    AI_PROVIDERS_AVAILABLE = False

from src.utils.logger import get_logger

logger = get_logger(__name__)


class LLMProvider(Enum):
    """LLM提供商"""

    DEEPSEEK = "deepseek"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE = "azure"
    CUSTOM = "custom"


@dataclass
class ToolInfo:
    """工具信息"""

    name: str
    capability: List[str]
    confidence: float
    available: bool
    install_hint: str = ""
    priority: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "capability": self.capability,
            "confidence": self.confidence,
            "available": self.available,
            "install_hint": self.install_hint,
            "priority": self.priority,
        }


@dataclass
class TargetProfile:
    """目标画像"""

    type: str
    url: str
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    testability: Dict[str, Any] = field(default_factory=dict)
    recommended_tools: List[str] = field(default_factory=list)
    recommended_params: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "url": self.url,
            "fingerprint": self.fingerprint,
            "testability": self.testability,
            "recommended_tools": self.recommended_tools,
            "recommended_params": self.recommended_params,
            "confidence": self.confidence,
        }


@dataclass
class ScanStrategy:
    """扫描策略"""

    target: str
    selected_tools: List[str]
    execution_order: List[str]
    tool_params: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    timeout: int = 300
    parallel: bool = True
    fallback_enabled: bool = True
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "selected_tools": self.selected_tools,
            "execution_order": self.execution_order,
            "tool_params": self.tool_params,
            "timeout": self.timeout,
            "parallel": self.parallel,
            "fallback_enabled": self.fallback_enabled,
            "confidence": self.confidence,
        }


@dataclass
class AnalysisReport:
    """分析报告"""

    findings: List[Dict[str, Any]] = field(default_factory=list)
    aggregated_findings: List[Dict[str, Any]] = field(default_factory=list)
    high_confidence_findings: List[Dict[str, Any]] = field(default_factory=list)
    false_positive_candidates: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    confidence: float = 0.0
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": self.findings,
            "aggregated_findings": self.aggregated_findings,
            "high_confidence_findings": self.high_confidence_findings,
            "false_positive_candidates": self.false_positive_candidates,
            "recommendations": self.recommendations,
            "next_steps": self.next_steps,
            "confidence": self.confidence,
            "summary": self.summary,
        }


class ToolsRegistry:
    """工具注册表

    管理所有可用工具的元信息。
    """

    def __init__(self):
        self._tools: Dict[str, ToolInfo] = {}
        self._initialize_default_tools()

    def _initialize_default_tools(self) -> None:
        """初始化默认工具列表"""
        default_tools = [
            ToolInfo(
                name="semgrep",
                capability=["代码静态分析", "SAST", "最佳实践检查"],
                confidence=0.9,
                available=self._check_tool_available("semgrep"),
                install_hint="pip install semgrep",
                priority=1,
            ),
            ToolInfo(
                name="trivy",
                capability=["容器镜像扫描", "漏洞库扫描", "基础设施扫描"],
                confidence=0.85,
                available=self._check_tool_available("trivy"),
                install_hint="pip install trivy",
                priority=2,
            ),
            ToolInfo(
                name="gitleaks",
                capability=["密钥泄露检测", " secrets扫描", "git历史审计"],
                confidence=0.95,
                available=self._check_tool_available("gitleaks"),
                install_hint="pip install gitleaks",
                priority=1,
            ),
            ToolInfo(
                name="code_vuln_scanner",
                capability=["代码漏洞扫描", "IAST", "动态分析"],
                confidence=0.75,
                available=True,
                priority=2,
            ),
            ToolInfo(
                name="sqlmap",
                capability=["SQL注入检测", "数据库枚举", "权限提升"],
                confidence=0.9,
                available=self._check_tool_available("sqlmap"),
                install_hint="pip install sqlmap 或 git clone https://github.com/sqlmapproject/sqlmap.git",
                priority=1,
            ),
            ToolInfo(
                name="nuclei",
                capability=["漏洞扫描", "CVE检测", "模板扫描"],
                confidence=0.8,
                available=self._check_tool_available("nuclei"),
                install_hint="https://github.com/projectdiscovery/nuclei/releases",
                priority=1,
            ),
            ToolInfo(
                name="zap",
                capability=["Web漏洞扫描", "主动扫描", "被动扫描", "Spider"],
                confidence=0.8,
                available=self._check_zap_available(),
                install_hint="pip install python-owasp-zap-v2",
                priority=1,
            ),
            ToolInfo(
                name="http_security",
                capability=["HTTP安全测试", "头部检测", "SQL注入测试", "XSS测试"],
                confidence=0.7,
                available=True,
                priority=2,
            ),
            ToolInfo(
                name="api_security",
                capability=["REST API测试", "GraphQL测试", "OpenAPI测试"],
                confidence=0.8,
                available=True,
                priority=1,
            ),
            ToolInfo(
                name="fuzzing",
                capability=["模糊测试", "内容发现", "目录枚举", "参数 fuzzing"],
                confidence=0.6,
                available=True,
                priority=3,
            ),
        ]

        for tool in default_tools:
            self._tools[tool.name] = tool

    def _check_tool_available(self, tool_name: str) -> bool:
        """检查工具是否可用"""
        import subprocess
        import shutil

        if shutil.which(tool_name):
            return True

        try:
            result = subprocess.run(
                ["which", tool_name] if tool_name != "semgrep" else ["semgrep", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            pass

        return False

    def _check_zap_available(self) -> bool:
        """检查 ZAP 是否可用"""
        try:
            import zapv2
            return True
        except ImportError:
            return False

    def get_available_tools(self) -> List[ToolInfo]:
        """获取所有可用工具"""
        return [t for t in self._tools.values() if t.available]

    def get_tool(self, name: str) -> Optional[ToolInfo]:
        """获取工具信息"""
        return self._tools.get(name)

    def register_tool(self, tool: ToolInfo) -> None:
        """注册工具"""
        self._tools[tool.name] = tool

    def get_all_tools(self) -> List[ToolInfo]:
        """获取所有工具"""
        return list(self._tools.values())


class AIDecisionEngine:
    """AI 决策引擎

    整合 LLM 实现智能的目标分析、策略规划和结果分析。
    """

    PROMPTS = {
        "target_analysis": """【AI 目标分析】

## 目标信息
- URL: {target_url}
- 响应头: {headers}
- 页面标题: {title}
- 技术栈指纹: {fingerprint}
- 初步检测到的端点: {endpoints}

## 可用工具
{available_tools}

## 任务
请分析以上目标信息，判断目标类型和特征，并推荐合适的扫描工具组合。

请提供:
1. 目标类型 (web / api / service / source / mixed)
2. 技术栈识别 (框架、CMS、中间件等)
3. 可测试性评估 (0-1 分数和因素)
4. 推荐的扫描工具组合 (考虑工具可用性)
5. 推荐的扫描参数

请以JSON格式返回:
{{
    "type": "目标类型",
    "fingerprint": {{
        "framework": "识别的框架",
        "cms": "识别的CMS",
        "middleware": "识别的中间件",
        "languages": ["编程语言列表"]
    }},
    "testability": {{
        "score": 0.0-1.0,
        "factors": ["评估因素列表"]
    }},
    "recommended_tools": ["工具名称列表"],
    "recommended_params": {{"工具名": {{"参数": "值"}}}}
}}
""",

        "strategy_planning": """【AI 策略规划】

## 目标信息
- URL: {target_url}
- 目标类型: {target_type}
- 技术栈: {fingerprint}
- 可测试性评分: {testability_score}

## 工具能力矩阵
{tool_capabilities}

## 约束条件
- 超时时间: {timeout} 秒
- 并行执行: {parallel}
- 优先快速扫描: {prefer_fast}

## 任务
请为该目标规划最优的扫描策略，包括工具选择、执行顺序和参数配置。

请提供:
1. 选择的工具列表 (考虑工具可用性和目标适用性)
2. 执行顺序 (考虑依赖关系和效率)
3. 每个工具的具体参数
4. 是否启用并行执行
5. 超时时间建议

请以JSON格式返回:
{{
    "selected_tools": ["工具1", "工具2"],
    "execution_order": ["工具1", "工具2"],
    "tool_params": {{
        "工具1": {{"param1": "value1"}},
        "工具2": {{"param2": "value2"}}
    }},
    "timeout": 300,
    "parallel": true/false,
    "fallback_enabled": true/false,
    "confidence": 0.0-1.0
}}
""",

        "result_analysis": """【AI 结果分析】

## 扫描结果
{scan_results}

## 目标信息
- URL: {target_url}
- 目标类型: {target_type}
- 技术栈: {fingerprint}

## 上下文
- 使用的工具: {tools_used}
- 扫描时长: {scan_duration} 秒
- 发现的漏洞数: {finding_count}

## 任务
请分析以上扫描结果，识别高置信度发现，判断可能的误报，并提供后续建议。

请提供:
1. 高置信度发现 (置信度 > 0.8)
2. 需要进一步验证的发现
3. 可能的误报候选
4. 推荐的深入测试方向
5. 修复优先级建议

请以JSON格式返回:
{{
    "high_confidence_findings": [
        {{
            "description": "发现描述",
            "confidence": 0.0-1.0,
            "severity": "高/中/低",
            "evidence": "证据"
        }}
    ],
    "findings_needing_verification": [...],
    "false_positive_candidates": [...],
    "recommendations": ["建议列表"],
    "next_steps": ["后续步骤"],
    "summary": {{
        "total_findings": 数量,
        "high_confidence": 数量,
        "estimated_true_positives": 数量
    }}
}}
""",
    }

    def __init__(
        self,
        llm_provider: LLMProvider = LLMProvider.DEEPSEEK,
        api_key: Optional[str] = None,
        model: str = "deepseek-chat",
    ):
        """初始化 AI 决策引擎

        Args:
            llm_provider: LLM 提供商
            api_key: API 密钥
            model: 模型名称
        """
        self.llm_provider = llm_provider
        self.api_key = api_key
        self.model = model
        self._llm_client = None
        self.tools_registry = ToolsRegistry()

        if AI_PROVIDERS_AVAILABLE:
            self._initialize_llm()

    def _initialize_llm(self) -> None:
        """初始化 LLM 客户端"""
        try:
            if self.llm_provider == LLMProvider.DEEPSEEK:
                self._llm_client = DeepSeekProvider(
                    api_key=self.api_key or "",
                    model=self.model,
                )
                logger.info("LLM client initialized (DeepSeek)")
            else:
                logger.warning(f"LLM provider {self.llm_provider} not supported yet")
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}")
            self._llm_client = None

    def is_available(self) -> bool:
        """检查引擎是否可用"""
        return self._llm_client is not None

    async def analyze_target(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]] = None,
        title: str = "",
        fingerprint: Optional[Dict[str, Any]] = None,
        endpoints: Optional[List[str]] = None,
    ) -> TargetProfile:
        """分析目标

        Args:
            target_url: 目标URL
            headers: HTTP响应头
            title: 页面标题
            fingerprint: 技术栈指纹
            endpoints: 检测到的端点

        Returns:
            目标画像
        """
        available_tools = self.tools_registry.get_available_tools()
        tools_str = json.dumps(
            [t.to_dict() for t in available_tools],
            indent=2,
            ensure_ascii=False,
        )

        headers_str = json.dumps(headers or {}, indent=2, ensure_ascii=False)
        fingerprint_str = json.dumps(fingerprint or {}, indent=2, ensure_ascii=False)
        endpoints_str = ", ".join(endpoints or [])

        prompt = self.PROMPTS["target_analysis"].format(
            target_url=target_url,
            headers=headers_str,
            title=title,
            fingerprint=fingerprint_str,
            endpoints=endpoints_str or "无",
            available_tools=tools_str,
        )

        if self._llm_client:
            try:
                response = await self._generate(prompt)
                if response:
                    return self._parse_target_profile(response, target_url)
            except Exception as e:
                logger.error(f"AI target analysis failed: {e}")

        return self._fallback_target_analysis(
            target_url, headers, fingerprint, available_tools
        )

    def _fallback_target_analysis(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]],
        fingerprint: Optional[Dict[str, Any]],
        available_tools: List[ToolInfo],
    ) -> TargetProfile:
        """后备目标分析

        当AI不可用时使用规则进行分析。
        """
        target_type = "web"
        recommended_tools = ["zap", "nuclei", "api_security"]

        if fingerprint:
            if fingerprint.get("is_api"):
                target_type = "api"
                recommended_tools = ["api_security", "sqlmap"]
            elif fingerprint.get("is_docker"):
                recommended_tools = ["trivy", "nuclei"]

        web_indicators = ["text/html", "application/xhtml+xml"]
        if headers:
            content_type = headers.get("content-type", "")
            if any(ind in content_type for ind in web_indicators):
                target_type = "web"

        available_names = [t.name for t in available_tools]
        selected_tools = [t for t in recommended_tools if t in available_names]
        if not selected_tools:
            selected_tools = available_names[:3]

        return TargetProfile(
            type=target_type,
            url=target_url,
            fingerprint=fingerprint or {},
            testability={"score": 0.7, "factors": ["基础可测试"]},
            recommended_tools=selected_tools,
            recommended_params={},
            confidence=0.5,
        )

    async def plan_strategy(
        self,
        target: TargetProfile,
        available_tools: Optional[List[str]] = None,
        timeout: int = 300,
        parallel: bool = True,
        prefer_fast: bool = False,
    ) -> ScanStrategy:
        """规划扫描策略

        Args:
            target: 目标画像
            available_tools: 可用工具列表
            timeout: 超时时间
            parallel: 是否并行
            prefer_fast: 是否优先快速扫描

        Returns:
            扫描策略
        """
        tools = self.tools_registry.get_all_tools()
        if available_tools:
            tools = [t for t in tools if t.name in available_tools]

        tools_capabilities = "\n".join([
            f"- {t.name}: {', '.join(t.capability)} (可用: {t.available}, 置信度: {t.confidence})"
            for t in tools
        ])

        prompt = self.PROMPTS["strategy_planning"].format(
            target_url=target.url,
            target_type=target.type,
            fingerprint=json.dumps(target.fingerprint, ensure_ascii=False),
            testability_score=target.testability.get("score", 0.5),
            tool_capabilities=tools_capabilities,
            timeout=timeout,
            parallel=parallel,
            prefer_fast=prefer_fast,
        )

        if self._llm_client:
            try:
                response = await self._generate(prompt)
                if response:
                    return self._parse_strategy(response, target.url)
            except Exception as e:
                logger.error(f"AI strategy planning failed: {e}")

        return self._fallback_strategy(target, tools, timeout, parallel)

    def _fallback_strategy(
        self,
        target: TargetProfile,
        tools: List[ToolInfo],
        timeout: int,
        parallel: bool,
    ) -> ScanStrategy:
        """后备策略规划"""
        available = [t for t in tools if t.available]
        selected = target.recommended_tools or [t.name for t in available[:3]]

        tool_params = {}
        for tool_name in selected:
            if tool_name == "zap":
                tool_params["zap"] = {"risk": 1, "level": 2}
            elif tool_name == "nuclei":
                tool_params["nuclei"] = {"severity": "high,critical", "rate_limit": 150}
            elif tool_name == "sqlmap":
                tool_params["sqlmap"] = {"risk": 1, "level": 2, "batch": True}

        return ScanStrategy(
            target=target.url,
            selected_tools=selected,
            execution_order=selected,
            tool_params=tool_params,
            timeout=timeout,
            parallel=parallel,
            fallback_enabled=True,
            confidence=0.5,
        )

    async def analyze_results(
        self,
        results: List[Dict[str, Any]],
        target_url: str,
        target_type: str = "web",
        fingerprint: Optional[Dict[str, Any]] = None,
        tools_used: Optional[List[str]] = None,
        scan_duration: float = 0.0,
    ) -> AnalysisReport:
        """分析扫描结果

        Args:
            results: 扫描结果列表
            target_url: 目标URL
            target_type: 目标类型
            fingerprint: 技术指纹
            tools_used: 使用的工具
            scan_duration: 扫描时长

        Returns:
            分析报告
        """
        findings = []
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        findings_str = json.dumps(findings[:20], indent=2, ensure_ascii=False)

        prompt = self.PROMPTS["result_analysis"].format(
            scan_results=findings_str,
            target_url=target_url,
            target_type=target_type,
            fingerprint=json.dumps(fingerprint or {}, ensure_ascii=False),
            tools_used=", ".join(tools_used or []),
            scan_duration=scan_duration,
            finding_count=len(findings),
        )

        if self._llm_client:
            try:
                response = await self._generate(prompt)
                if response:
                    return self._parse_analysis_report(response, findings)
            except Exception as e:
                logger.error(f"AI result analysis failed: {e}")

        return self._fallback_analysis(findings, target_url)

    def _fallback_analysis(
        self,
        findings: List[Dict[str, Any]],
        target_url: str,
    ) -> AnalysisReport:
        """后备结果分析"""
        high_confidence = []
        other = []

        for f in findings:
            confidence = f.get("confidence", f.get("tool_confidence", 0.5))
            if confidence >= 0.8:
                high_confidence.append(f)
            else:
                other.append(f)

        summary = {
            "total_findings": len(findings),
            "high_confidence": len(high_confidence),
            "other": len(other),
        }

        return AnalysisReport(
            findings=findings,
            aggregated_findings=findings,
            high_confidence_findings=high_confidence,
            false_positive_candidates=[],
            recommendations=["进一步验证高置信度发现"],
            next_steps=["如需要，进行人工复核"],
            confidence=0.5,
            summary=summary,
        )

    async def _generate(self, prompt: str) -> Optional[str]:
        """生成响应

        Args:
            prompt: 提示词

        Returns:
            响应内容
        """
        if not self._llm_client:
            return None

        try:
            if hasattr(self._llm_client, "generate"):
                return self._llm_client.generate(
                    prompt=prompt,
                    temperature=0.3,
                    max_tokens=2000,
                )
            elif hasattr(self._llm_client, "chat"):
                return await self._llm_client.chat(
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                    max_tokens=2000,
                )
        except Exception as e:
            logger.error(f"LLM generation error: {e}")

        return None

    def _parse_target_profile(
        self,
        response: str,
        target_url: str,
    ) -> TargetProfile:
        """解析目标画像响应"""
        try:
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return TargetProfile(
                    type=data.get("type", "unknown"),
                    url=target_url,
                    fingerprint=data.get("fingerprint", {}),
                    testability=data.get("testability", {"score": 0.5}),
                    recommended_tools=data.get("recommended_tools", []),
                    recommended_params=data.get("recommended_params", {}),
                    confidence=0.8,
                )
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse target profile: {e}")

        return TargetProfile(type="unknown", url=target_url, confidence=0.0)

    def _parse_strategy(
        self,
        response: str,
        target_url: str,
    ) -> ScanStrategy:
        """解析策略响应"""
        try:
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return ScanStrategy(
                    target=target_url,
                    selected_tools=data.get("selected_tools", []),
                    execution_order=data.get("execution_order", []),
                    tool_params=data.get("tool_params", {}),
                    timeout=data.get("timeout", 300),
                    parallel=data.get("parallel", True),
                    fallback_enabled=data.get("fallback_enabled", True),
                    confidence=0.8,
                )
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse strategy: {e}")

        return ScanStrategy(target=target_url, selected_tools=[], execution_order=[])

    def _parse_analysis_report(
        self,
        response: str,
        findings: List[Dict[str, Any]],
    ) -> AnalysisReport:
        """解析分析报告响应"""
        try:
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return AnalysisReport(
                    findings=findings,
                    aggregated_findings=findings,
                    high_confidence_findings=data.get("high_confidence_findings", []),
                    false_positive_candidates=data.get("false_positive_candidates", []),
                    recommendations=data.get("recommendations", []),
                    next_steps=data.get("next_steps", []),
                    confidence=0.8,
                    summary=data.get("summary", {}),
                )
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse analysis report: {e}")

        return AnalysisReport(findings=findings, confidence=0.0)

    def get_tool_info(self) -> Dict[str, Any]:
        """获取引擎信息"""
        return {
            "name": "AI Decision Engine",
            "version": "1.0",
            "llm_provider": self.llm_provider.value,
            "model": self.model,
            "available": self.is_available(),
            "registered_tools": len(self.tools_registry.get_all_tools()),
            "available_tools": len(self.tools_registry.get_available_tools()),
        }


def create_ai_decision_engine(
    provider: str = "deepseek",
    api_key: Optional[str] = None,
) -> AIDecisionEngine:
    """创建 AI 决策引擎的便捷函数

    Args:
        provider: LLM 提供商
        api_key: API 密钥

    Returns:
        AIDecisionEngine 实例
    """
    try:
        llm_provider = LLMProvider(provider.lower())
    except ValueError:
        llm_provider = LLMProvider.DEEPSEEK

    return AIDecisionEngine(
        llm_provider=llm_provider,
        api_key=api_key,
    )
