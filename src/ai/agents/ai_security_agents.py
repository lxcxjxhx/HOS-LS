"""AI 动态安全分析 Agent 系统

替代所有硬编码 CWE_PATTERNS、SOURCE_PATTERNS、SINK_PATTERNS 等规则。
通过 AI 摘选 + NVD 数据源 + LangGraph 编排实现动态漏洞分析。
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 同步 LLM 包装器 — 桥接 LiteLLMClient 异步接口到同步接口
# ---------------------------------------------------------------------------

class SyncLLMWrapper:
    """将 LiteLLMClient 的异步 generate() 包装为同步 invoke() 接口

    解决 AIBaseAgent 期望同步 invoke() 但 LiteLLMClient 只提供异步 generate() 的问题。
    """

    def __init__(self, litellm_client):
        """
        Args:
            litellm_client: LiteLLMClient 实例
        """
        self._client = litellm_client
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """获取或创建事件循环"""
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    def invoke(self, prompt: str, system_prompt: str = "") -> str:
        """同步调用 LLM（内部执行异步请求）

        Args:
            prompt: 用户提示
            system_prompt: 系统提示（可选）

        Returns:
            LLM 响应文本
        """
        try:
            from src.ai.models import AIRequest

            request = AIRequest(
                prompt=prompt,
                system_prompt=system_prompt,
            )

            loop = self._get_loop()
            if not self._client._initialized:
                # 同步初始化
                loop.run_until_complete(self._client.initialize())

            response = loop.run_until_complete(self._client.generate(request))
            return response.content or ""
        except Exception as e:
            logger.error(f"SyncLLMWrapper.invoke 失败: {e}")
            return "{}"

    def chat(self, prompt: str) -> str:
        """同步聊天接口（兼容 LangChain 风格）"""
        return self.invoke(prompt)


# ---------------------------------------------------------------------------
# 数据类
# ---------------------------------------------------------------------------


@dataclass
class CWEClassification:
    """CWE 分类结果"""
    cwe_id: str = ""
    cwe_name: str = ""
    cwe_description: str = ""
    confidence: float = 0.0
    reasoning: str = ""
    matched_evidence: List[str] = field(default_factory=list)


@dataclass
class TaintAnalysisResult:
    """污点分析结果"""
    sources: List[Dict[str, Any]] = field(default_factory=list)
    sinks: List[Dict[str, Any]] = field(default_factory=list)
    sanitizers: List[Dict[str, Any]] = field(default_factory=list)
    taint_paths: List[Dict[str, Any]] = field(default_factory=list)
    vulnerability_type: str = ""
    confidence: float = 0.0


@dataclass
class ConfidenceEvaluation:
    """置信度评估结果"""
    score: float = 0.0
    verification_level: str = "none"
    reasoning: str = ""
    factors: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# AI Agent 基础类
# ---------------------------------------------------------------------------

class AIBaseAgent:
    """AI Agent 基类"""

    def __init__(self, llm, nvd_adapter=None):
        self.llm = llm
        self.nvd_adapter = nvd_adapter

    def _invoke_llm(self, prompt: str, system_prompt: str = "") -> str:
        """调用 LLM"""
        try:
            if hasattr(self.llm, 'invoke'):
                if system_prompt:
                    full_prompt = f"{system_prompt}\n\n{prompt}"
                else:
                    full_prompt = prompt
                response = self.llm.invoke(full_prompt)
                if hasattr(response, 'content'):
                    return response.content
                return str(response)
            elif hasattr(self.llm, 'chat'):
                return self.llm.chat(prompt)
            else:
                logger.warning("LLM 不支持 invoke 或 chat 方法")
                return "{}"
        except Exception as e:
            logger.error(f"LLM 调用失败: {e}")
            return "{}"

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """解析 JSON 响应"""
        try:
            # Try to find JSON in the response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                json_str = response[start:end]
                return json.loads(json_str)
            return {}
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"JSON 解析失败: {e}")
            return {}


# ---------------------------------------------------------------------------
# CWE 分类 Agent - 替代硬编码 CWE_PATTERNS
# ---------------------------------------------------------------------------

class CWEClassifierAgent(AIBaseAgent):
    """CWE 分类 Agent

    替代 FindingVerifier.CWE_PATTERNS 中 15 个硬编码 CWE 模式。
    通过 AI 分析代码上下文 + NVD 数据源动态匹配 CWE。
    """

    SYSTEM_PROMPT = """你是一个资深安全工程师，负责将代码漏洞分类到正确的 CWE (Common Weakness Enumeration)。

要求：
1. 仔细分析代码上下文和漏洞特征
2. 参考 NVD 提供的 CWE 描述进行匹配
3. 给出明确的 CWE ID 和置信度
4. 提供分类理由
5. 只返回 JSON 格式结果"""

    def classify(self, code_context: str, rule_name: str = "", description: str = "") -> CWEClassification:
        """AI 动态分类漏洞到 CWE

        Args:
            code_context: 代码上下文
            rule_name: 规则名称（可选）
            description: 漏洞描述（可选）

        Returns:
            CWE 分类结果
        """
        # Step 1: 从 NVD 获取相关 CWE 描述
        cwe_descriptions = self._get_relevant_cwes(rule_name, description)

        # Step 2: 构建 AI 分析 prompt
        prompt = self._build_classification_prompt(code_context, rule_name, description, cwe_descriptions)

        # Step 3: AI 分析
        response = self._invoke_llm(prompt, self.SYSTEM_PROMPT)
        result = self._parse_json_response(response)

        # Step 4: 解析结果
        return self._parse_classification_result(result, code_context)

    def _get_relevant_cwes(self, rule_name: str, description: str) -> List[Dict[str, str]]:
        """从 NVD 获取相关 CWE"""
        if not self.nvd_adapter or not self.nvd_adapter.is_available():
            return []

        # 提取关键词
        text = f"{rule_name} {description}".lower()
        keywords = [w for w in text.split() if len(w) > 3]
        keywords.extend(['sql', 'injection', 'xss', 'command', 'path', 'hardcoded', 'crypto'])

        # 从 NVD 匹配
        nvd_results = self.nvd_adapter.match_cwe(keywords, limit=10)
        return [
            {
                'cwe_id': r.get('cwe_id', ''),
                'cwe_name': r.get('cwe_name', ''),
                'cwe_description': r.get('cwe_description', ''),
            }
            for r in nvd_results
        ]

    def _build_classification_prompt(
        self, code_context: str, rule_name: str, description: str, cwe_descriptions: List[Dict]
    ) -> str:
        """构建分类 prompt"""
        cwe_ref = "\n".join([
            f"- {c['cwe_id']}: {c['cwe_name']}\n  {c['cwe_description']}"
            for c in cwe_descriptions
        ]) if cwe_descriptions else "（无 NVD 数据，请基于你的安全知识判断）"

        return f"""请分析以下代码并分类到最匹配的 CWE：

规则名称：{rule_name}
漏洞描述：{description}

代码上下文：
```
{code_context}
```

参考 CWE 列表（来自 NVD）：
{cwe_ref}

请以 JSON 格式返回：
{{
    "cwe_id": "CWE-XX",
    "cwe_name": "CWE 名称",
    "confidence": 0.0-1.0,
    "reasoning": "分类理由",
    "matched_evidence": ["代码中匹配的证据行或特征"]
}}"""

    def _parse_classification_result(self, result: Dict, code_context: str) -> CWEClassification:
        """解析分类结果"""
        return CWEClassification(
            cwe_id=result.get('cwe_id', ''),
            cwe_name=result.get('cwe_name', ''),
            cwe_description=result.get('cwe_description', ''),
            confidence=float(result.get('confidence', 0.0)),
            reasoning=result.get('reasoning', ''),
            matched_evidence=result.get('matched_evidence', []),
        )


# ---------------------------------------------------------------------------
# 污点分析 Agent - 替代硬编码 SOURCE_PATTERNS/SINK_PATTERNS
# ---------------------------------------------------------------------------

class TaintAnalyzerAgent(AIBaseAgent):
    """污点分析 Agent

    替代 SOURCE_PATTERNS (26个)、SINK_PATTERNS (44个)、SANITIZER_PATTERNS (18个)。
    通过 AI 动态识别污点源、sink 点和 sanitizer。
    """

    SYSTEM_PROMPT = """你是一个安全代码审计专家，负责进行污点分析。
你需要识别代码中的：
1. 污点源 (Taint Sources)：用户输入、文件读取、网络数据等不可信数据来源
2. 危险操作 (Taint Sinks)：SQL 执行、命令执行、HTML 输出等危险操作
3. 数据清理 (Sanitizers)：转义、验证、参数化查询等安全处理

请精确返回行号、变量名和置信度。只返回 JSON 格式结果。"""

    def analyze(self, code: str, language: str = "python") -> TaintAnalysisResult:
        """AI 动态污点分析

        Args:
            code: 代码内容
            language: 编程语言

        Returns:
            污点分析结果
        """
        prompt = self._build_taint_prompt(code, language)
        response = self._invoke_llm(prompt, self.SYSTEM_PROMPT)
        result = self._parse_json_response(response)

        return self._parse_taint_result(result)

    def _build_taint_prompt(self, code: str, language: str) -> str:
        """构建污点分析 prompt"""
        return f"""请分析以下 {language} 代码，识别所有污点路径：

```{language}
{code}
```

请以 JSON 格式返回：
{{
    "sources": [
        {{
            "line": 行号,
            "variable": "变量名",
            "type": "user_input|file_read|network|database|env",
            "code": "该行代码",
            "confidence": 0.0-1.0
        }}
    ],
    "sinks": [
        {{
            "line": 行号,
            "function": "危险函数名",
            "vulnerability_type": "SQL_INJECTION|COMMAND_INJECTION|XSS|CODE_INJECTION|PATH_TRAVERSAL|DESERIALIZATION|SSRF",
            "code": "该行代码",
            "confidence": 0.0-1.0
        }}
    ],
    "sanitizers": [
        {{
            "line": 行号,
            "function": "清理函数名",
            "type": "escape|validate|parameterize|encode",
            "code": "该行代码"
        }}
    ],
    "taint_paths": [
        {{
            "source_line": 污点源行号,
            "sink_line": 危险操作行号,
            "intermediate_variables": ["中间传播的变量名"],
            "has_sanitizer": true/false,
            "confidence": 0.0-1.0
        }}
    ]
}}"""

    def _parse_taint_result(self, result: Dict) -> TaintAnalysisResult:
        """解析污点分析结果"""
        sources = result.get('sources', [])
        sinks = result.get('sinks', [])
        sanitizers = result.get('sanitizers', [])
        taint_paths = result.get('taint_paths', [])

        # 确定主要漏洞类型
        vuln_types = [s.get('vulnerability_type', '') for s in sinks]
        primary_type = max(set(vuln_types), key=vuln_types.count) if vuln_types else ""

        # 计算整体置信度
        confidences = [s.get('confidence', 0.5) for s in sinks]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        return TaintAnalysisResult(
            sources=sources,
            sinks=sinks,
            sanitizers=sanitizers,
            taint_paths=taint_paths,
            vulnerability_type=primary_type,
            confidence=avg_confidence,
        )


# ---------------------------------------------------------------------------
# 置信度评估 Agent - 替代硬编码置信度公式
# ---------------------------------------------------------------------------

class ConfidenceEvaluatorAgent(AIBaseAgent):
    """置信度评估 Agent

    替代 finding_verifier.py 中所有硬编码置信度公式和阈值：
    - verification_score += 0.25 / 0.35
    - confidence >= 0.9 → triple_verified
    - confidence = min(1.0, score / 5.0)
    """

    SYSTEM_PROMPT = """你是一个安全审计置信度评估专家。
请综合评估漏洞发现的可信度，考虑以下因素：
1. 文件路径是否真实存在
2. 代码片段是否在文件中
3. CWE 匹配程度
4. Agent 是否已确认
5. 漏洞严重等级

请给出客观的置信度分数和验证等级。只返回 JSON 格式结果。"""

    def evaluate(self, finding: Dict, verification: Dict) -> ConfidenceEvaluation:
        """AI 动态评估置信度

        Args:
            finding: 漏洞发现信息
            verification: 验证结果（path_valid, code_valid, cwe_match, agent_confirmed 等）

        Returns:
            置信度评估结果
        """
        prompt = self._build_confidence_prompt(finding, verification)
        response = self._invoke_llm(prompt, self.SYSTEM_PROMPT)
        result = self._parse_json_response(response)

        return self._parse_confidence_result(result)

    def _build_confidence_prompt(self, finding: Dict, verification: Dict) -> str:
        """构建置信度评估 prompt"""
        return f"""请评估以下漏洞发现的置信度：

漏洞信息：
- 规则名称：{finding.get('rule_name', '')}
- 描述：{finding.get('description', '')}
- 严重等级：{finding.get('severity', '')}
- 代码片段：{finding.get('code_snippet', '')[:200]}

验证结果：
- 文件路径存在：{verification.get('path_valid', False)}
- 代码片段存在：{verification.get('code_valid', False)}
- CWE 匹配：{json.dumps(verification.get('cwe_match', {}), ensure_ascii=False)}
- Agent 确认状态：{verification.get('agent_confirmed', False)}

请以 JSON 格式返回：
{{
    "confidence": 0.0-1.0,
    "verification_level": "potential_hallucination|needs_review|single_verified|double_verified|triple_verified",
    "reasoning": "评估理由",
    "factors": {{
        "path_weight": 0.0-1.0,
        "code_weight": 0.0-1.0,
        "cwe_weight": 0.0-1.0,
        "agent_weight": 0.0-1.0
    }}
}}"""

    def _parse_confidence_result(self, result: Dict) -> ConfidenceEvaluation:
        """解析置信度结果"""
        return ConfidenceEvaluation(
            score=float(result.get('confidence', 0.0)),
            verification_level=result.get('verification_level', 'none'),
            reasoning=result.get('reasoning', ''),
            factors=result.get('factors', {}),
        )


# ---------------------------------------------------------------------------
# 攻击链构建 Agent
# ---------------------------------------------------------------------------

class AttackChainBuilderAgent(AIBaseAgent):
    """攻击链构建 Agent

    AI 动态构建完整的攻击链，替代简单的行号距离启发式匹配。
    """

    SYSTEM_PROMPT = """你是一个安全攻击链分析专家。
请分析代码中的污点传播路径，构建完整的攻击链。
需要识别：入口点 → 传播路径 → 执行点 → 影响范围。只返回 JSON 格式结果。"""

    def build_attack_chain(self, taint_result: TaintAnalysisResult, code: str) -> Dict[str, Any]:
        """AI 动态构建攻击链

        Args:
            taint_result: 污点分析结果
            code: 完整代码

        Returns:
            攻击链信息
        """
        prompt = self._build_chain_prompt(taint_result, code)
        response = self._invoke_llm(prompt, self.SYSTEM_PROMPT)
        return self._parse_json_response(response)

    def _build_chain_prompt(self, taint_result: TaintAnalysisResult, code: str) -> str:
        """构建攻击链 prompt"""
        return f"""请基于以下污点分析结果，构建完整的攻击链：

污点源：
{json.dumps(taint_result.sources, ensure_ascii=False, indent=2)}

危险操作：
{json.dumps(taint_result.sinks, ensure_ascii=False, indent=2)}

数据清理：
{json.dumps(taint_result.sanitizers, ensure_ascii=False, indent=2)}

代码：
```
{code[:3000]}
```

请以 JSON 格式返回攻击链：
{{
    "attack_chain": [
        {{
            "step": 1,
            "type": "entry|propagation|execution|impact",
            "line": 行号,
            "description": "步骤描述",
            "risk_level": "low|medium|high|critical"
        }}
    ],
    "overall_risk": "low|medium|high|critical",
    "exploitability": "easy|moderate|difficult",
    "summary": "攻击链总结"
}}"""


# ---------------------------------------------------------------------------
# 统一 AI 安全分析器 - LangGraph 节点
# ---------------------------------------------------------------------------

class AISecurityAnalyzer:
    """统一 AI 安全分析器

    整合所有 Agent，提供统一的分析接口。
    替代所有硬编码规则，完全由 AI 动态决策。
    """

    def __init__(self, llm, nvd_adapter=None):
        self.llm = llm
        self.nvd_adapter = nvd_adapter

        # 初始化所有 Agent
        self.cwe_classifier = CWEClassifierAgent(llm, nvd_adapter)
        self.taint_analyzer = TaintAnalyzerAgent(llm, nvd_adapter)
        self.confidence_evaluator = ConfidenceEvaluatorAgent(llm, nvd_adapter)
        self.attack_chain_builder = AttackChainBuilderAgent(llm, nvd_adapter)

    def analyze_code(self, code: str, language: str = "python", finding: Dict = None) -> Dict[str, Any]:
        """完整的安全分析流水线

        Args:
            code: 代码内容
            language: 编程语言
            finding: 已有的漏洞发现信息（可选）

        Returns:
            完整分析结果
        """
        result = {
            'taint_analysis': None,
            'cwe_classification': None,
            'confidence': None,
            'attack_chain': None,
        }

        # Step 1: AI 污点分析（替代 SOURCE_PATTERNS/SINK_PATTERNS）
        taint_result = self.taint_analyzer.analyze(code, language)
        result['taint_analysis'] = {
            'sources': taint_result.sources,
            'sinks': taint_result.sinks,
            'sanitizers': taint_result.sanitizers,
            'taint_paths': taint_result.taint_paths,
            'vulnerability_type': taint_result.vulnerability_type,
        }

        # Step 2: AI CWE 分类（替代 CWE_PATTERNS）
        finding_data = finding or {}
        cwe_result = self.cwe_classifier.classify(
            code_context=code,
            rule_name=finding_data.get('rule_name', ''),
            description=finding_data.get('description', ''),
        )
        result['cwe_classification'] = {
            'cwe_id': cwe_result.cwe_id,
            'cwe_name': cwe_result.cwe_name,
            'confidence': cwe_result.confidence,
            'reasoning': cwe_result.reasoning,
            'matched_evidence': cwe_result.matched_evidence,
        }

        # Step 3: AI 置信度评估（替代硬编码置信度公式）
        verification = {
            'path_valid': finding_data.get('path_valid', True),
            'code_valid': finding_data.get('code_valid', True),
            'cwe_match': {'cwe_id': cwe_result.cwe_id, 'confidence': cwe_result.confidence},
            'agent_confirmed': finding_data.get('agent_confirmed', False),
        }
        confidence_result = self.confidence_evaluator.evaluate(finding_data, verification)
        result['confidence'] = {
            'score': confidence_result.score,
            'verification_level': confidence_result.verification_level,
            'reasoning': confidence_result.reasoning,
        }

        # Step 4: 攻击链构建（如果有污点路径）
        if taint_result.taint_paths:
            chain = self.attack_chain_builder.build_attack_chain(taint_result, code)
            result['attack_chain'] = chain

        return result


# ---------------------------------------------------------------------------
# 高级 AI 安全分析器 — 自动管理 LiteLLMClient + SyncLLMWrapper
# ---------------------------------------------------------------------------

class AISecurityAnalyzerWithLLM:
    """高级 AI 安全分析器

    自动初始化 LiteLLMClient 和 SyncLLMWrapper，无需手动传入 llm 参数。
    解决原 AISecurityAnalyzer 需要外部传入已初始化 LLM 的问题。
    """

    _instance: Optional["AISecurityAnalyzerWithLLM"] = None
    _lock = __import__('threading').Lock()

    def __init__(self, config=None):
        from src.core.config import get_config
        from src.ai.providers.litellm_client import LiteLLMClient
        from src.nvd.nvd_query_adapter import NVDQueryAdapter

        self.config = config or get_config()
        self._llm_client = None
        self._sync_llm = None
        self._nvd = NVDQueryAdapter()
        self._initialized = False

        # Agent 实例
        self._analyzer: Optional[AISecurityAnalyzer] = None

    @classmethod
    def get_instance(cls, config=None) -> "AISecurityAnalyzerWithLLM":
        """获取单例实例"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(config)
            return cls._instance

    @classmethod
    def reset_instance(cls):
        """重置单例（用于测试）"""
        with cls._lock:
            if cls._instance is not None:
                cls._instance = None

    def initialize(self):
        """初始化 LLM 客户端和所有 Agent"""
        if self._initialized:
            return

        try:
            # 1. 初始化 LiteLLMClient
            from src.ai.providers.litellm_client import LiteLLMClient
            self._llm_client = LiteLLMClient(config=self.config)

            # 同步初始化
            loop = asyncio.new_event_loop()
            loop.run_until_complete(self._llm_client.initialize())
            loop.close()

            # 2. 创建同步包装器
            self._sync_llm = SyncLLMWrapper(self._llm_client)

            # 3. 初始化 AISecurityAnalyzer（使用同步包装的 LLM）
            self._analyzer = AISecurityAnalyzer(self._sync_llm, self._nvd)

            self._initialized = True
            logger.info("AISecurityAnalyzerWithLLM initialized successfully")
        except Exception as e:
            logger.error(f"AISecurityAnalyzerWithLLM initialization failed: {e}")
            raise

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def nvd(self):
        return self._nvd

    @property
    def analyzer(self) -> AISecurityAnalyzer:
        if not self._initialized:
            self.initialize()
        return self._analyzer

    def analyze_code(self, code: str, language: str = "python", finding: Dict = None) -> Dict[str, Any]:
        """完整的安全分析流水线（自动初始化）"""
        if not self._initialized:
            self.initialize()
        return self._analyzer.analyze_code(code, language, finding)
