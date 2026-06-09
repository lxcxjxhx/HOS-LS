"""ImpactAnalyzer 单元测试

验证影响半径分析、风险等级评估和人类可读摘要。
"""
import asyncio
from unittest.mock import MagicMock, AsyncMock

from src.core.impact_analyzer import ImpactAnalyzer, ImpactResult
from src.core.call_graph_analyzer import CallGraphNode, CallPath


def _build_mock_engine_and_graph(callers_depth1, callers_depth3, node_info=None):
    mock_engine = MagicMock()
    if node_info is None:
        node_info = {"file_path": "/app.py", "name": "target_func"}
    mock_engine.get_node = AsyncMock(return_value=node_info)

    mock_call_graph = MagicMock()
    mock_call_graph.get_callers = MagicMock(side_effect=lambda symbol, max_depth=3: (
        callers_depth1 if max_depth <= 1 else callers_depth3
    ))

    analyzer = ImpactAnalyzer(mock_engine, mock_call_graph)
    return analyzer, mock_engine


class TestImpactAnalyzerInit:

    def test_init_sets_dependencies(self):
        mock_engine = MagicMock()
        mock_call_graph = MagicMock()
        analyzer = ImpactAnalyzer(mock_engine, mock_call_graph)
        assert analyzer.engine is mock_engine
        assert analyzer.call_graph is mock_call_graph


class TestImpactAnalyzerLowRisk:

    def test_low_risk_no_callers(self):
        analyzer, _ = _build_mock_engine_and_graph([], [])
        result = analyzer.analyze_impact("target_func")
        assert result.symbol_name == "target_func"
        assert result.total_affected == 0
        assert result.risk_level == "low"
        assert result.direct_callers == []
        assert result.indirect_callers == []

    def test_low_risk_single_caller(self):
        caller_path = CallPath(path=[
            CallGraphNode("caller_a", "/a.py", 1, 5, "function"),
            CallGraphNode("target_func", "/app.py", 10, 20, "function"),
        ], depth=1)
        analyzer, _ = _build_mock_engine_and_graph([caller_path], [caller_path])
        result = analyzer.analyze_impact("target_func")
        assert result.total_affected == 1
        assert result.risk_level == "low"


class TestImpactAnalyzerMediumRisk:

    def test_medium_risk_two_callers(self):
        paths = [
            CallPath(path=[
                CallGraphNode("a", "/a.py", 1, 5, "function"),
                CallGraphNode("target_func", "/app.py", 10, 20, "function"),
            ], depth=1),
            CallPath(path=[
                CallGraphNode("b", "/b.py", 1, 5, "function"),
                CallGraphNode("target_func", "/app.py", 10, 20, "function"),
            ], depth=1),
        ]
        analyzer, _ = _build_mock_engine_and_graph(paths, paths)
        result = analyzer.analyze_impact("target_func")
        assert result.total_affected == 2
        assert result.risk_level == "medium"


class TestImpactAnalyzerHighRisk:

    def test_high_risk_five_callers(self):
        paths_depth1 = []
        paths_depth3 = []
        for i in range(5):
            p = CallPath(path=[
                CallGraphNode(f"caller_{i}", f"/f{i}.py", 1, 5, "function"),
                CallGraphNode("target_func", "/app.py", 10, 20, "function"),
            ], depth=1)
            paths_depth1.append(p)
            paths_depth3.append(p)
        analyzer, _ = _build_mock_engine_and_graph(paths_depth1, paths_depth3)
        result = analyzer.analyze_impact("target_func")
        assert result.total_affected >= 5
        assert result.risk_level == "high"


class TestImpactAnalyzerCriticalRisk:

    def test_critical_risk_ten_plus_callers(self):
        paths_depth1 = []
        paths_depth3 = []
        for i in range(12):
            p = CallPath(path=[
                CallGraphNode(f"caller_{i}", f"/f{i}.py", 1, 5, "function"),
                CallGraphNode("target_func", "/app.py", 10, 20, "function"),
            ], depth=1)
            paths_depth1.append(p)
            paths_depth3.append(p)
        analyzer, _ = _build_mock_engine_and_graph(paths_depth1, paths_depth3)
        result = analyzer.analyze_impact("target_func")
        assert result.total_affected >= 10
        assert result.risk_level == "critical"

    def test_critical_risk_cross_module(self):
        paths = [
            CallPath(path=[
                CallGraphNode("caller_a", "/module_a.py", 1, 5, "function"),
                CallGraphNode("target_func", "/module_b.py", 10, 20, "function"),
            ], depth=1),
        ]
        node_info = {"file_path": "/module_b.py", "name": "target_func"}

        def mock_find_node(symbol_name):
            if symbol_name == "target_func":
                return {"file_path": "/module_b.py", "name": "target_func"}
            elif symbol_name == "caller_a":
                return {"file_path": "/module_a.py", "name": "caller_a"}
            return None

        mock_engine = MagicMock()
        mock_engine.get_node = AsyncMock(side_effect=lambda s: asyncio.coroutine(lambda: mock_find_node(s))())
        mock_call_graph = MagicMock()
        mock_call_graph.get_callers = MagicMock(return_value=paths)

        analyzer = ImpactAnalyzer(mock_engine, mock_call_graph)
        result = analyzer.analyze_impact("target_func")
        assert result.risk_level == "critical"


class TestImpactAnalyzerSummary:

    def test_get_impact_summary_basic(self):
        analyzer, _ = _build_mock_engine_and_graph([], [])
        summary = analyzer.get_impact_summary("target_func")
        assert "影响分析报告: target_func" in summary
        assert "风险等级: LOW" in summary
        assert "直接影响: 0 个调用者" in summary
        assert "间接影响: 0 个调用者" in summary
        assert "总影响范围: 0 个符号" in summary

    def test_get_impact_summary_with_callers(self):
        paths = [
            CallPath(path=[
                CallGraphNode("caller_a", "/a.py", 1, 5, "function"),
                CallGraphNode("target_func", "/app.py", 10, 20, "function"),
            ], depth=1),
            CallPath(path=[
                CallGraphNode("caller_b", "/b.py", 1, 5, "function"),
                CallGraphNode("target_func", "/app.py", 10, 20, "function"),
            ], depth=1),
        ]
        analyzer, _ = _build_mock_engine_and_graph(paths, paths)
        summary = analyzer.get_impact_summary("target_func")
        assert "直接影响: 2 个调用者" in summary
        assert "caller_a" in summary or "caller_b" in summary

    def test_get_impact_summary_file_path(self):
        node_info = {"file_path": "/src/main.py", "name": "my_func"}
        analyzer, _ = _build_mock_engine_and_graph([], [], node_info=node_info)
        summary = analyzer.get_impact_summary("my_func")
        assert "/src/main.py" in summary


class TestImpactAnalyzerNoCallers:

    def test_no_callers_empty_result(self):
        analyzer, _ = _build_mock_engine_and_graph([], [])
        result = analyzer.analyze_impact("lonely_func")
        assert result.direct_callers == []
        assert result.indirect_callers == []
        assert result.total_affected == 0

    def test_no_callers_risk_is_low(self):
        analyzer, _ = _build_mock_engine_and_graph([], [])
        result = analyzer.analyze_impact("lonely_func")
        assert result.risk_level == "low"


class TestImpactAnalyzerCrossModule:

    def test_cross_module_same_file_not_critical(self):
        paths = [
            CallPath(path=[
                CallGraphNode("caller_a", "/app.py", 1, 5, "function"),
                CallGraphNode("target_func", "/app.py", 10, 20, "function"),
            ], depth=1),
            CallPath(path=[
                CallGraphNode("caller_b", "/app.py", 1, 5, "function"),
                CallGraphNode("target_func", "/app.py", 10, 20, "function"),
            ], depth=1),
            CallPath(path=[
                CallGraphNode("caller_c", "/app.py", 1, 5, "function"),
                CallGraphNode("target_func", "/app.py", 10, 20, "function"),
            ], depth=1),
        ]
        analyzer, _ = _build_mock_engine_and_graph(paths, paths)
        result = analyzer.analyze_impact("target_func")
        assert result.total_affected == 3
        assert result.risk_level in ("medium", "high")


class TestImpactAnalyzerDataClass:

    def test_impact_result_dataclass(self):
        result = ImpactResult(
            symbol_name="foo",
            file_path="/test.py",
            direct_callers=["a", "b"],
            indirect_callers=["c"],
            total_affected=3,
            risk_level="medium",
        )
        assert result.symbol_name == "foo"
        assert result.file_path == "/test.py"
        assert len(result.direct_callers) == 2
        assert len(result.indirect_callers) == 1
        assert result.total_affected == 3
        assert result.risk_level == "medium"


class TestImpactAnalyzerIndirectCallers:

    def test_indirect_callers_dedup(self):
        direct_paths = [
            CallPath(path=[
                CallGraphNode("a", "/a.py", 1, 5, "function"),
                CallGraphNode("target", "/app.py", 10, 20, "function"),
            ], depth=1),
        ]
        indirect_paths = direct_paths + [
            CallPath(path=[
                CallGraphNode("c", "/c.py", 1, 5, "function"),
                CallGraphNode("a", "/a.py", 1, 5, "function"),
                CallGraphNode("target", "/app.py", 10, 20, "function"),
            ], depth=2),
        ]
        analyzer, _ = _build_mock_engine_and_graph(direct_paths, indirect_paths)
        result = analyzer.analyze_impact("target")
        assert "a" in result.direct_callers
        assert "c" in result.indirect_callers
        assert "a" not in result.indirect_callers
