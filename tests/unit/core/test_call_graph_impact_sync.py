import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock

from src.core.call_graph_analyzer import CallGraphAnalyzer, CallGraphNode, CallPath
from src.core.impact_analyzer import ImpactAnalyzer, ImpactResult
from src.core.graph_sync_engine import GraphSyncEngine, FileState
from src.analysis.framework_patterns import (
    FrameworkRouteRecognizer, RouteInfo, integrate_routes_to_graph,
    match_framework_patterns, check_safe_pattern, check_unsafe_pattern,
)


class TestCallGraphAnalyzer:

    def test_get_callers_no_node(self):
        mock_engine = MagicMock()
        mock_engine.get_node = AsyncMock(return_value=None)
        analyzer = CallGraphAnalyzer(mock_engine)
        result = analyzer.get_callers("nonexistent")
        assert result == []

    def test_get_callees_no_node(self):
        mock_engine = MagicMock()
        mock_engine.get_node = AsyncMock(return_value=None)
        analyzer = CallGraphAnalyzer(mock_engine)
        result = analyzer.get_callees("nonexistent")
        assert result == []

    def test_get_call_chain_no_node(self):
        mock_engine = MagicMock()
        mock_engine.get_node = AsyncMock(return_value=None)
        analyzer = CallGraphAnalyzer(mock_engine)
        result = analyzer.get_call_chain("a", "b")
        assert result is None

    def test_to_node(self):
        mock_engine = MagicMock()
        analyzer = CallGraphAnalyzer(mock_engine)
        data = {
            "name": "foo",
            "file_path": "/test.py",
            "start_line": 10,
            "end_line": 20,
            "type": "function",
        }
        node = analyzer._to_node(data)
        assert node.symbol_name == "foo"
        assert node.file_path == "/test.py"
        assert node.start_line == 10
        assert node.symbol_type == "function"

    def test_call_graph_node_hash_eq(self):
        n1 = CallGraphNode("foo", "/a.py", 1, 10, "function")
        n2 = CallGraphNode("foo", "/a.py", 1, 15, "function")
        assert n1 == n2
        assert hash(n1) == hash(n2)


class TestImpactAnalyzer:

    def test_analyze_impact_low_risk(self):
        mock_engine = MagicMock()
        mock_engine.get_node = AsyncMock(return_value={
            "file_path": "/test.py", "name": "foo",
        })
        mock_call_graph = MagicMock()
        mock_call_graph.get_callers = MagicMock(return_value=[])

        analyzer = ImpactAnalyzer(mock_engine, mock_call_graph)
        result = analyzer.analyze_impact("foo")

        assert result.symbol_name == "foo"
        assert result.total_affected == 0
        assert result.risk_level == "low"

    def test_analyze_impact_medium_risk(self):
        mock_engine = MagicMock()
        mock_engine.get_node = AsyncMock(return_value={
            "file_path": "/test.py", "name": "foo",
        })
        mock_call_graph = MagicMock()
        mock_call_graph.get_callers = MagicMock(return_value=[
            CallPath(path=[
                CallGraphNode("a", "/a.py", 1, 5, "function"),
                CallGraphNode("foo", "/test.py", 10, 20, "function"),
            ], depth=1),
            CallPath(path=[
                CallGraphNode("b", "/b.py", 1, 5, "function"),
                CallGraphNode("foo", "/test.py", 10, 20, "function"),
            ], depth=1),
        ])

        analyzer = ImpactAnalyzer(mock_engine, mock_call_graph)
        result = analyzer.analyze_impact("foo")

        assert result.total_affected == 2
        assert result.risk_level == "medium"

    def test_get_impact_summary(self):
        mock_engine = MagicMock()
        mock_engine.get_node = AsyncMock(return_value={
            "file_path": "/test.py", "name": "foo",
        })
        mock_call_graph = MagicMock()
        mock_call_graph.get_callers = MagicMock(return_value=[])

        analyzer = ImpactAnalyzer(mock_engine, mock_call_graph)
        summary = analyzer.get_impact_summary("foo")

        assert "影响分析报告: foo" in summary
        assert "风险等级: LOW" in summary


class TestGraphSyncEngine:

    def test_detect_language(self):
        mock_engine = MagicMock()
        sync_engine = GraphSyncEngine(mock_engine, "/project")

        assert sync_engine._detect_language("foo.py") == "python"
        assert sync_engine._detect_language("foo.js") == "javascript"
        assert sync_engine._detect_language("foo.ts") == "typescript"
        assert sync_engine._detect_language("foo.java") == "java"
        assert sync_engine._detect_language("foo.go") == "go"
        assert sync_engine._detect_language("foo.rs") == "rust"
        assert sync_engine._detect_language("foo.cpp") == "cpp"
        assert sync_engine._detect_language("foo.c") == "c"
        assert sync_engine._detect_language("foo.php") == "php"
        assert sync_engine._detect_language("foo.xyz") == "unknown"

    def test_file_state_dataclass(self):
        state = FileState(path="/a.py", hash="abc", last_modified=1.0, node_count=5)
        assert state.path == "/a.py"
        assert state.hash == "abc"
        assert state.node_count == 5


class TestFrameworkPatterns:

    def test_match_safe_patterns(self):
        code = "Wrappers.query().eq('id', 1)"
        result = match_framework_patterns(code)
        assert len(result['safe']) > 0

    def test_match_unsafe_patterns(self):
        code = "${user_input}"
        result = match_framework_patterns(code)
        assert len(result['unsafe']) > 0

    def test_check_safe_pattern(self):
        assert check_safe_pattern("Wrappers.lambdaQuery()") is True
        assert check_safe_pattern("no safe pattern here") is False

    def test_check_unsafe_pattern(self):
        assert check_unsafe_pattern("${}") is True
        assert check_unsafe_pattern("#{safe}") is False

    def test_recognize_django(self):
        recognizer = FrameworkRouteRecognizer()
        code = "path('users/', views.UserView)"
        routes = recognizer.recognize("urls.py", code, "python")
        assert len(routes) == 1
        assert routes[0].url_pattern == "users/"
        assert routes[0].framework == "django"

    def test_recognize_flask(self):
        recognizer = FrameworkRouteRecognizer()
        code = "@app.route('/users', methods=['GET', 'POST'])\ndef get_users(): pass"
        routes = recognizer.recognize("app.py", code, "python")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/users"
        assert routes[0].framework == "flask"
        assert "GET" in routes[0].http_methods
        assert "POST" in routes[0].http_methods

    def test_recognize_fastapi(self):
        recognizer = FrameworkRouteRecognizer()
        code = "@app.get('/items')\ndef get_items(): pass"
        routes = recognizer.recognize("main.py", code, "python")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/items"
        assert routes[0].framework == "fastapi"
        assert routes[0].http_methods == ["GET"]

    def test_recognize_express(self):
        recognizer = FrameworkRouteRecognizer()
        code = "app.get('/api/users', handler)"
        routes = recognizer.recognize("server.js", code, "javascript")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/api/users"
        assert routes[0].framework == "express"
        assert routes[0].http_methods == ["GET"]

    def test_recognize_spring(self):
        recognizer = FrameworkRouteRecognizer()
        code = '@GetMapping("/users")'
        routes = recognizer.recognize("UserController.java", code, "java")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/users"
        assert routes[0].framework == "spring"
        assert routes[0].http_methods == ["GET"]

    def test_recognize_no_routes(self):
        recognizer = FrameworkRouteRecognizer()
        routes = recognizer.recognize("foo.py", "x = 1", "python")
        assert routes == []

    def test_route_info_dataclass(self):
        route = RouteInfo(
            url_pattern="/api",
            handler_name="handler",
            handler_file="/app.py",
            handler_line=1,
            http_methods=["GET"],
            framework="flask",
        )
        assert route.url_pattern == "/api"
        assert route.handler_name == "handler"

    def test_integrate_routes_to_graph_no_routes(self):
        mock_engine = MagicMock()
        mock_engine._db = None
        routes = integrate_routes_to_graph(mock_engine, "foo.py", "x = 1", "python")
        assert routes == []
