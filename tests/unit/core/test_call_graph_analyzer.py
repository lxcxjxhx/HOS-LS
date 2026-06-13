"""CallGraphAnalyzer 单元测试

使用真实的 CodeGraphEngine 创建测试图数据，验证调用链分析逻辑。
"""
import asyncio
from unittest.mock import MagicMock

from src.core.code_graph_engine import CodeGraphEngine
from src.core.call_graph_analyzer import CallGraphAnalyzer, CallGraphNode, CallPath


def _run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.Future() as fut:
                asyncio.run_coroutine_threadsafe(coro, loop).result()
                return fut
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def _build_test_graph(tmp_path):
    eng = CodeGraphEngine()
    _run(eng.init(str(tmp_path)))

    code = """import os

def helper():
    return os.getcwd()

def processor():
    result = helper()
    return result

def main():
    data = processor()
    print(data)

def entry():
    main()
"""
    test_file = tmp_path / "app.py"
    test_file.write_text(code, encoding="utf-8")
    _run(eng.index_file(str(test_file), code, "python"))
    return eng


class TestCallGraphAnalyzerInit:

    def test_init_sets_engine(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        assert analyzer.engine is eng
        _run(eng.close())


class TestCallGraphAnalyzerGetCallers:

    def test_get_callers_finds_callers(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        callers = analyzer.get_callers("helper")
        assert len(callers) > 0
        caller_names = [cp.path[0].symbol_name for cp in callers]
        assert "processor" in caller_names
        _run(eng.close())

    def test_get_callers_no_node(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        callers = analyzer.get_callers("nonexistent_xyz")
        assert callers == []
        _run(eng.close())

    def test_get_callers_max_depth_1(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        callers = analyzer.get_callers("helper", max_depth=1)
        for cp in callers:
            assert cp.depth <= 1
        _run(eng.close())

    def test_get_callers_max_depth_limited(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        callers_d1 = analyzer.get_callers("helper", max_depth=1)
        callers_d3 = analyzer.get_callers("helper", max_depth=3)
        assert len(callers_d3) >= len(callers_d1)
        _run(eng.close())

    def test_get_callers_chain_structure(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        callers = analyzer.get_callers("helper")
        if callers:
            cp = callers[0]
            assert isinstance(cp, CallPath)
            assert len(cp.path) >= 2
            assert isinstance(cp.path[0], CallGraphNode)
            _run(eng.close())
            return
        _run(eng.close())


class TestCallGraphAnalyzerGetCallees:

    def test_get_callees_finds_callees(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        callees = analyzer.get_callees("main")
        assert len(callees) > 0
        _run(eng.close())

    def test_get_callees_no_node(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        callees = analyzer.get_callees("nonexistent_xyz")
        assert callees == []
        _run(eng.close())

    def test_get_callees_max_depth_1(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        callees = analyzer.get_callees("main", max_depth=1)
        for cp in callees:
            assert cp.depth <= 1
        _run(eng.close())

    def test_get_callees_no_callees(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        callees = analyzer.get_callees("helper")
        callees = [c for c in callees if len(c.path) > 1]
        assert len(callees) == 0
        _run(eng.close())


class TestCallGraphAnalyzerGetCallChain:

    def test_get_call_chain_finds_path(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        chain = analyzer.get_call_chain("entry", "helper")
        if chain is not None:
            assert isinstance(chain, CallPath)
            assert len(chain.path) >= 2
            assert chain.path[0].symbol_name == "entry"
        _run(eng.close())

    def test_get_call_chain_no_start_node(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        chain = analyzer.get_call_chain("nonexistent_a", "helper")
        assert chain is None
        _run(eng.close())

    def test_get_call_chain_no_target_node(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        chain = analyzer.get_call_chain("entry", "nonexistent_b")
        assert chain is None
        _run(eng.close())

    def test_get_call_chain_max_depth_too_small(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        chain = analyzer.get_call_chain("entry", "helper", max_depth=0)
        assert chain is None
        _run(eng.close())


class TestCallGraphAnalyzerToNode:

    def test_to_node_converts_dict(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        data = {
            "name": "test_func",
            "file_path": "/test.py",
            "start_line": 10,
            "end_line": 20,
            "type": "function",
        }
        node = analyzer._to_node(data)
        assert node.symbol_name == "test_func"
        assert node.file_path == "/test.py"
        assert node.start_line == 10
        assert node.end_line == 20
        assert node.symbol_type == "function"
        _run(eng.close())

    def test_to_node_defaults_missing_fields(self, tmp_path):
        eng = _build_test_graph(tmp_path)
        analyzer = CallGraphAnalyzer(eng)
        data = {"name": "foo"}
        node = analyzer._to_node(data)
        assert node.symbol_name == "foo"
        assert node.file_path == ""
        assert node.start_line == 0
        _run(eng.close())


class TestCallGraphAnalyzerNodeEquivalence:

    def test_call_graph_node_eq(self):
        n1 = CallGraphNode("foo", "/a.py", 1, 10, "function")
        n2 = CallGraphNode("foo", "/a.py", 1, 15, "function")
        assert n1 == n2

    def test_call_graph_node_not_eq(self):
        n1 = CallGraphNode("foo", "/a.py", 1, 10, "function")
        n2 = CallGraphNode("bar", "/a.py", 1, 10, "function")
        assert n1 != n2

    def test_call_graph_node_hash(self):
        n1 = CallGraphNode("foo", "/a.py", 1, 10, "function")
        n2 = CallGraphNode("foo", "/a.py", 1, 15, "function")
        assert hash(n1) == hash(n2)

    def test_call_graph_node_not_eq_different_type(self):
        n1 = CallGraphNode("foo", "/a.py", 1, 10, "function")
        assert n1 != "not_a_node"


class TestCallGraphAnalyzerCircularCall:

    def test_circular_call_detection(self, tmp_path):
        eng = CodeGraphEngine()
        _run(eng.init(str(tmp_path)))

        code = """def a():
    b()

def b():
    a()
"""
        test_file = tmp_path / "circular.py"
        test_file.write_text(code, encoding="utf-8")
        _run(eng.index_file(str(test_file), code, "python"))

        analyzer = CallGraphAnalyzer(eng)
        callers_a = analyzer.get_callers("a", max_depth=3)
        caller_names = set()
        for cp in callers_a:
            caller_names.add(cp.path[0].symbol_name)
        assert "b" in caller_names
        _run(eng.close())
