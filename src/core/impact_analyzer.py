from typing import List, Dict, Set
from dataclasses import dataclass


@dataclass
class ImpactResult:
    symbol_name: str
    file_path: str
    direct_callers: List[str]
    indirect_callers: List[str]
    total_affected: int
    risk_level: str


class ImpactAnalyzer:

    def __init__(self, code_graph_engine, call_graph_analyzer):
        self.engine = code_graph_engine
        self.call_graph = call_graph_analyzer

    def analyze_impact(self, symbol_name: str) -> ImpactResult:
        node_info = self._find_node(symbol_name)
        file_path = node_info.get("file_path", "") if node_info else ""

        direct_paths = self.call_graph.get_callers(symbol_name, max_depth=1)
        direct_callers = list(set(
            p.path[0].symbol_name for p in direct_paths if len(p.path) > 1
        ))

        indirect_paths = self.call_graph.get_callers(symbol_name, max_depth=3)
        all_callers = set()
        for p in indirect_paths:
            if len(p.path) > 1:
                for n in p.path[:-1]:
                    all_callers.add(n.symbol_name)
        indirect_callers = list(all_callers - set(direct_callers))

        total_affected = len(direct_callers) + len(indirect_callers)
        is_cross_module = self._is_cross_module_call(symbol_name, direct_callers)

        if total_affected >= 10 or is_cross_module:
            risk_level = "critical"
        elif total_affected >= 5:
            risk_level = "high"
        elif total_affected >= 2:
            risk_level = "medium"
        else:
            risk_level = "low"

        return ImpactResult(
            symbol_name=symbol_name,
            file_path=str(file_path),
            direct_callers=direct_callers,
            indirect_callers=indirect_callers,
            total_affected=total_affected,
            risk_level=risk_level,
        )

    def get_impact_summary(self, symbol_name: str) -> str:
        result = self.analyze_impact(symbol_name)
        lines = [
            f"影响分析报告: {symbol_name}",
            f"文件路径: {result.file_path}",
            f"风险等级: {result.risk_level.upper()}",
            f"直接影响: {len(result.direct_callers)} 个调用者",
            f"间接影响: {len(result.indirect_callers)} 个调用者",
            f"总影响范围: {result.total_affected} 个符号",
        ]
        if result.direct_callers:
            lines.append("直接调用者: " + ", ".join(result.direct_callers[:10]))
        if result.indirect_callers:
            lines.append("间接调用者: " + ", ".join(result.indirect_callers[:10]))
        return "\n".join(lines)

    def _find_node(self, symbol_name: str):
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                return asyncio.get_event_loop().run_until_complete(
                    self.engine.get_node(symbol_name)
                )
            return loop.run_until_complete(self.engine.get_node(symbol_name))
        except RuntimeError:
            return None

    def _is_cross_module_call(self, symbol_name: str, callers: List[str]) -> bool:
        if not callers:
            return False
        node_info = self._find_node(symbol_name)
        if not node_info:
            return False
        symbol_file = node_info.get("file_path", "")
        for caller in callers:
            caller_info = self._find_node(caller)
            if caller_info and caller_info.get("file_path", "") != symbol_file:
                return True
        return False
