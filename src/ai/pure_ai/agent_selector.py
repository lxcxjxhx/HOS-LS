from dataclasses import dataclass, field
from typing import Dict, List, Optional

from src.core.config import Config


VULN_TYPE_AGENT_MAP = {
    "SQL_INJECTION": ["SemanticAgent", "ValidationAgent", "AttackAgent"],
    "XSS": ["SemanticAgent", "ValidationAgent", "AttackAgent"],
    "COMMAND_INJECTION": ["SemanticAgent", "ValidationAgent", "AttackAgent"],
    "PATH_TRAVERSAL": ["SemanticAgent", "ValidationAgent"],
    "AUTH_BYPASS": ["SemanticAgent", "ValidationAgent", "FinalDecision"],
    "HARDCODED_SECRET": ["ValidationAgent"],
    "CONFIG_SENSITIVE": ["ValidationAgent"],
}

SKIP_SEMANTIC_AGENT_VULN_TYPES = {"HARDCODED_SECRET", "CONFIG_SENSITIVE"}

SKIP_ATTACK_AGENT_VULN_TYPES = {"PATH_TRAVERSAL", "AUTH_BYPASS"}

TIME_ESTIMATES = {
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
    def __init__(self, config: Optional[Config] = None):
        self.config = config

    def select_agents(self, vuln_type: str, context: Dict) -> List[str]:
        base_agents = VULN_TYPE_AGENT_MAP.get(vuln_type, ["SemanticAgent", "ValidationAgent"])

        selected = []
        for agent in base_agents:
            if self.should_skip_agent(agent, context):
                continue
            selected.append(agent)

        return selected

    def should_skip_agent(self, agent_name: str, context: Dict) -> bool:
        if agent_name == "ContextBuilder":
            return self._should_skip_context_builder(context)
        elif agent_name == "SemanticAgent":
            return self._should_skip_semantic_agent(context)
        elif agent_name == "AttackAgent":
            return self._should_skip_attack_agent(context)
        elif agent_name == "FinalDecision":
            return self._should_skip_final_decision(context)
        return False

    def _should_skip_context_builder(self, context: Dict) -> bool:
        if context.get("has_sufficient_context"):
            return True
        if context.get("file_content") and len(context.get("file_content", "")) < 100:
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

    def create_execution_plan(self, vuln_type: str, context: Dict) -> AgentExecutionPlan:
        selected_agents = self.select_agents(vuln_type, context)
        skip_reasons = {}

        for agent in ["ContextBuilder", "SemanticAgent", "ValidationAgent", "AttackAgent", "FinalDecision"]:
            if agent not in selected_agents:
                if agent == "ContextBuilder" and self._should_skip_context_builder(context):
                    skip_reasons[agent] = "context_already_sufficient"
                elif agent == "SemanticAgent" and self._should_skip_semantic_agent(context):
                    skip_reasons[agent] = "simple_vuln_type"
                elif agent == "AttackAgent" and self._should_skip_attack_agent(context):
                    skip_reasons[agent] = "exploitability_previously_proven"
                elif agent == "FinalDecision" and self._should_skip_final_decision(context):
                    skip_reasons[agent] = "decision_already_reached"

        ordered_agents = selected_agents

        parallel_groups = []
        sequential_agents = ["ContextBuilder"]
        parallel_candidates = ["SemanticAgent", "ValidationAgent", "AttackAgent"]
        final_agents = ["FinalDecision"]

        remaining_parallel = [a for a in parallel_candidates if a in ordered_agents]

        if "ContextBuilder" in ordered_agents:
            parallel_groups.append(["ContextBuilder"])

        if remaining_parallel:
            parallel_groups.append(remaining_parallel)

        if "FinalDecision" in ordered_agents:
            parallel_groups.append(["FinalDecision"])

        estimated_time = sum(TIME_ESTIMATES.get(agent, 5.0) for agent in ordered_agents)

        return AgentExecutionPlan(
            ordered_agents=ordered_agents,
            parallel_groups=parallel_groups,
            estimated_time=estimated_time,
            skip_reasons=skip_reasons,
        )

    def get_agent_dependencies(self, agent_name: str) -> List[str]:
        dependencies = {
            "ContextBuilder": [],
            "SemanticAgent": ["ContextBuilder"],
            "ValidationAgent": ["ContextBuilder", "SemanticAgent"],
            "AttackAgent": ["ContextBuilder", "SemanticAgent", "ValidationAgent"],
            "FinalDecision": ["ContextBuilder", "SemanticAgent", "ValidationAgent", "AttackAgent"],
        }
        return dependencies.get(agent_name, [])

    def can_run_parallel(self, agent1: str, agent2: str) -> bool:
        parallel_sets = [
            {"SemanticAgent", "ValidationAgent", "AttackAgent"},
        ]
        for pset in parallel_sets:
            if agent1 in pset and agent2 in pset:
                return True
        return False
