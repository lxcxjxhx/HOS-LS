"""Agent 选择器 — 增强版

根据漏洞类型和上下文选择合适的 Agent 组合。
新增 Agent：
- SemgrepAgent：硬性前置筛选（规则命中直接出结果，0 LLM 成本）
- DiffAnalysisAgent：差分分析（AI patch 风险路径检测）
- ContractViolationAgent：跨文件安全契约违背检测
- CounterfactualAgent：反事实验证
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from src.core.config import Config

# ============================================================
# 漏洞类型 → Agent 映射表
# ============================================================

VULN_TYPE_AGENT_MAP = {
    # SQL 注入：Semgrep 硬筛 + 语义分析 + 验证 + 攻击测试 + 反事实验证
    "SQL_INJECTION": [
        "SemgrepAgent",       # 硬性前置筛选（Semgrep 规则命中直接出结果）
        "DiffAnalysisAgent",  # 差分分析（AI patch 场景）
        "SemanticAgent",
        "ValidationAgent",
        "AttackAgent",
        "CounterfactualAgent", # 反事实验证（提升 Pair-Correct）
    ],
    # XSS：同上
    "XSS": [
        "SemgrepAgent",
        "DiffAnalysisAgent",
        "SemanticAgent",
        "ValidationAgent",
        "AttackAgent",
        "CounterfactualAgent",
    ],
    # 命令注入
    "COMMAND_INJECTION": [
        "SemgrepAgent",
        "DiffAnalysisAgent",
        "SemanticAgent",
        "ValidationAgent",
        "AttackAgent",
        "CounterfactualAgent",
    ],
    # 路径穿越：不需要攻击测试
    "PATH_TRAVERSAL": [
        "SemgrepAgent",
        "DiffAnalysisAgent",
        "SemanticAgent",
        "ValidationAgent",
        "CounterfactualAgent",
    ],
    # 权限绕过：需要跨文件契约检测
    "AUTH_BYPASS": [
        "SemgrepAgent",
        "ContractViolationAgent",  # 跨文件安全契约违背
        "SemanticAgent",
        "ValidationAgent",
        "FinalDecision",
        "CounterfactualAgent",
    ],
    # 硬编码密钥：简单规则匹配即可
    "HARDCODED_SECRET": [
        "SemgrepAgent",
        "ValidationAgent",
    ],
    # 配置敏感：Semgrep 规则 + 验证
    "CONFIG_SENSITIVE": [
        "SemgrepAgent",
        "ValidationAgent",
    ],
    # 反序列化
    "DESERIALIZATION": [
        "SemgrepAgent",
        "DiffAnalysisAgent",
        "SemanticAgent",
        "ValidationAgent",
        "AttackAgent",
        "CounterfactualAgent",
    ],
    # SSRF
    "SSRF": [
        "SemgrepAgent",
        "DiffAnalysisAgent",
        "SemanticAgent",
        "ValidationAgent",
        "AttackAgent",
        "CounterfactualAgent",
    ],
    # XXE
    "XXE": [
        "SemgrepAgent",
        "SemanticAgent",
        "ValidationAgent",
    ],
}

# ============================================================
# 跳过某些 Agent 的漏洞类型
# ============================================================

SKIP_SEMANTIC_AGENT_VULN_TYPES = {"HARDCODED_SECRET", "CONFIG_SENSITIVE"}
SKIP_ATTACK_AGENT_VULN_TYPES = {"PATH_TRAVERSAL", "AUTH_BYPASS", "XXE"}
SKIP_CONTRACT_VIOLATION_VULN_TYPES = {"HARDCODED_SECRET", "CONFIG_SENSITIVE", "SQL_INJECTION"}
SKIP_COUNTERFACTUAL_VULN_TYPES = {"HARDCODED_SECRET", "CONFIG_SENSITIVE", "XXE"}

# ============================================================
# 各 Agent 预估耗时（秒）
# ============================================================

TIME_ESTIMATES = {
    "SemgrepAgent": 2.0,           # 本地运行，几乎无耗时
    "DiffAnalysisAgent": 1.0,      # 本地 diff 分析
    "ContractViolationAgent": 1.5, # 本地的跨文件分析
    "CounterfactualAgent": 3.0,    # 可能调 Semgrep CLI
    "ContextBuilder": 2.0,
    "SemanticAgent": 5.0,
    "ValidationAgent": 4.0,
    "AttackAgent": 6.0,
    "FinalDecision": 3.0,
}


@dataclass
class AgentExecutionPlan:
    ordered_agents: List[str] = field(default_factory=list)
    parallel_groups: List[List[str]] = field(default_factory=list)
    estimated_time: float = 0.0
    skip_reasons: Dict[str, str] = field(default_factory=dict)


class AgentSelector:
    def __init__(self, config: Optional[Config] = None, use_diff_context: bool = False):
        self.config = config
        self.use_diff_context = use_diff_context  # AI patch 场景

    def select_agents(self, vuln_type: str, context: Dict) -> List[str]:
        base_agents = VULN_TYPE_AGENT_MAP.get(vuln_type, ["SemgrepAgent", "SemanticAgent", "ValidationAgent"])

        # 非 AI-diff 场景跳过 DiffAnalysisAgent
        if not self.use_diff_context and "DiffAnalysisAgent" in base_agents:
            # 保留但标记为可跳过
            pass

        selected = []
        for agent in base_agents:
            if self.should_skip_agent(agent, context):
                continue
            selected.append(agent)

        return selected

    def should_skip_agent(self, agent_name: str, context: Dict) -> bool:
        if agent_name == "ContextBuilder":
            return self._should_skip_context_builder(context)
        elif agent_name == "SemgrepAgent":
            return self._should_skip_semgrep_agent(context)
        elif agent_name == "DiffAnalysisAgent":
            return self._should_skip_diff_analysis(context)
        elif agent_name == "ContractViolationAgent":
            return self._should_skip_contract_violation(context)
        elif agent_name == "CounterfactualAgent":
            return self._should_skip_counterfactual(context)
        elif agent_name == "SemanticAgent":
            return self._should_skip_semantic_agent(context)
        elif agent_name == "AttackAgent":
            return self._should_skip_attack_agent(context)
        elif agent_name == "FinalDecision":
            return self._should_skip_final_decision(context)
        return False

    # ---- 各 Agent 跳过逻辑 ----

    def _should_skip_context_builder(self, context: Dict) -> bool:
        if context.get("has_sufficient_context"):
            return True
        if context.get("file_content") and len(context.get("file_content", "")) < 100:
            return True
        return False

    def _should_skip_semgrep_agent(self, context: Dict) -> bool:
        """SemgrepAgent 跳过条件：
        - 已通过其他 SAST 工具（CodeQL）硬检出
        - 配置禁用 Semgrep
        """
        if context.get("sast_codeql_hard_hit"):
            return True
        if context.get("skip_semgrep"):
            return True
        return False

    def _should_skip_diff_analysis(self, context: Dict) -> bool:
        """DiffAnalysisAgent 跳过条件：
        - 非 AI-diff 场景
        - 无 diff 上下文
        """
        if not self.use_diff_context:
            return True
        if not context.get("diff_content") and not context.get("has_diff"):
            return True
        return False

    def _should_skip_contract_violation(self, context: Dict) -> bool:
        """ContractViolationAgent 跳过条件：
        - 漏洞类型不涉及跨文件安全契约
        - 单文件分析
        """
        vuln_type = context.get("vuln_type", "")
        if vuln_type in SKIP_CONTRACT_VIOLATION_VULN_TYPES:
            return True
        if not context.get("has_related_files"):
            return True
        return False

    def _should_skip_counterfactual(self, context: Dict) -> bool:
        """CounterfactualAgent 跳过条件：
        - 对不需要反事实验证的漏洞类型
        - 发现已通过其他方式充分验证
        """
        vuln_type = context.get("vuln_type", "")
        if vuln_type in SKIP_COUNTERFACTUAL_VULN_TYPES:
            return True
        if context.get("exploitability_proven") and context.get("confidence", 0) >= 0.9:
            return True
        return False

    def _should_skip_semantic_agent(self, context: Dict) -> bool:
        vuln_type = context.get("vuln_type", "")
        if vuln_type in SKIP_SEMANTIC_AGENT_VULN_TYPES:
            return True
        if context.get("is_simple_vuln"):
            return True
        if context.get("semantic_data"):
            return True
        return False

    def _should_skip_attack_agent(self, context: Dict) -> bool:
        vuln_type = context.get("vuln_type", "")
        if vuln_type in SKIP_ATTACK_AGENT_VULN_TYPES:
            return True
        if context.get("exploitability_proven"):
            return True
        if context.get("skip_attack_analysis"):
            return True
        return False

    def _should_skip_final_decision(self, context: Dict) -> bool:
        if context.get("final_decision_ready"):
            return True
        if context.get("low_confidence"):
            return False
        return False

    # ---- 执行计划 ----

    def create_execution_plan(self, vuln_type: str, context: Dict) -> AgentExecutionPlan:
        selected_agents = self.select_agents(vuln_type, context)
        skip_reasons = {}

        for agent in [
            "SemgrepAgent",
            "DiffAnalysisAgent",
            "ContractViolationAgent",
            "CounterfactualAgent",
            "ContextBuilder",
            "SemanticAgent",
            "ValidationAgent",
            "AttackAgent",
            "FinalDecision",
        ]:
            if agent not in selected_agents:
                reason = ""
                if agent == "SemgrepAgent":
                    reason = "sast_codeql_hard_hit_or_disabled"
                elif agent == "DiffAnalysisAgent":
                    reason = "non_diff_context"
                elif agent == "ContractViolationAgent":
                    reason = "no_related_files"
                elif agent == "CounterfactualAgent":
                    reason = "vuln_type_not_applicable"
                elif agent == "ContextBuilder":
                    reason = "context_already_sufficient"
                elif agent == "SemanticAgent":
                    reason = "simple_vuln_type"
                elif agent == "AttackAgent":
                    reason = "exploitability_previously_proven"
                elif agent == "FinalDecision":
                    reason = "decision_already_reached"
                skip_reasons[agent] = reason

        ordered_agents = selected_agents
        parallel_groups = []

        # 并行分组设计：
        # 第一组：SemgrepAgent（独立运行，作为硬筛选）
        # 第二组：DiffAnalysisAgent + ContractViolationAgent + CounterfactualAgent + SemanticAgent + ValidationAgent + AttackAgent
        # 第三组：FinalDecision（汇总）
        semgrep_candidates = ["SemgrepAgent"]
        first_stage = [a for a in semgrep_candidates if a in ordered_agents]

        parallel_candidates = [
            "DiffAnalysisAgent",
            "ContractViolationAgent",
            "CounterfactualAgent",
            "SemanticAgent",
            "ValidationAgent",
            "AttackAgent",
        ]
        final_agents = ["FinalDecision"]

        if first_stage:
            parallel_groups.append(first_stage)

        remaining_parallel = [a for a in parallel_candidates if a in ordered_agents]
        if remaining_parallel:
            parallel_groups.append(remaining_parallel)

        if "ContextBuilder" in ordered_agents:
            parallel_groups.insert(0, ["ContextBuilder"])

        if final_agents and "FinalDecision" in ordered_agents:
            parallel_groups.append(final_agents)

        estimated_time = sum(TIME_ESTIMATES.get(agent, 5.0) for agent in ordered_agents)

        return AgentExecutionPlan(
            ordered_agents=ordered_agents,
            parallel_groups=parallel_groups,
            estimated_time=estimated_time,
            skip_reasons=skip_reasons,
        )

    # ---- 依赖关系 ----

    def get_agent_dependencies(self, agent_name: str) -> List[str]:
        dependencies = {
            "SemgrepAgent": [],
            "DiffAnalysisAgent": ["SemgrepAgent"],
            "ContractViolationAgent": ["SemgrepAgent"],
            "CounterfactualAgent": ["SemgrepAgent", "SemanticAgent", "ValidationAgent"],
            "ContextBuilder": [],
            "SemanticAgent": ["SemgrepAgent", "ContextBuilder"],
            "ValidationAgent": ["SemgrepAgent", "ContextBuilder", "SemanticAgent"],
            "AttackAgent": ["SemgrepAgent", "ContextBuilder", "SemanticAgent", "ValidationAgent"],
            "FinalDecision": [
                "SemgrepAgent", "DiffAnalysisAgent", "ContractViolationAgent",
                "CounterfactualAgent", "ContextBuilder",
                "SemanticAgent", "ValidationAgent", "AttackAgent",
            ],
        }
        return dependencies.get(agent_name, [])

    def can_run_parallel(self, agent1: str, agent2: str) -> bool:
        """判断两个 Agent 是否可以并行执行"""
        # SemgrepAgent 先独立执行
        if "SemgrepAgent" in (agent1, agent2):
            return False
        # 其他 Agent 可以并行
        parallel_sets = [
            {"DiffAnalysisAgent", "ContractViolationAgent", "CounterfactualAgent",
             "SemanticAgent", "ValidationAgent", "AttackAgent"},
        ]
        for pset in parallel_sets:
            if agent1 in pset and agent2 in pset:
                return True
        return False
