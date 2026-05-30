"""CodeGraphEngine 单元测试

使用 tmp_path 创建临时项目目录，验证引擎的完整生命周期。
"""
import asyncio
from pathlib import Path

from src.core.code_graph_engine import CodeGraphEngine


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


class TestCodeGraphEngineInit:

    def test_init_creates_db(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            db_file = tmp_path / ".codegraph" / "codegraph.db"
            assert db_file.exists()
            assert eng._initialized is True
            await eng.close()
        _run(_test())

    def test_close_resets_state(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            await eng.close()
            assert eng._initialized is False
            assert eng._db is None
        _run(_test())

    def test_init_with_path_object(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(tmp_path)
            assert eng._initialized is True
            await eng.close()
        _run(_test())


class TestCodeGraphEngineIndexFile:

    def test_index_python_file(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def hello():\n    pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            result = await eng.index_file(str(test_file), code, "python")
            assert result["status"] == "indexed"
            assert result["nodes"] > 0
            await eng.close()
        _run(_test())

    def test_index_javascript_file(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'function handler() { return 1; }\n'
            test_file = tmp_path / "server.js"
            test_file.write_text(code, encoding="utf-8")
            result = await eng.index_file(str(test_file), code, "javascript")
            assert result["status"] == "indexed"
            await eng.close()
        _run(_test())

    def test_index_unsupported_language(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            test_file = tmp_path / "test.xyz"
            test_file.write_text("hello", encoding="utf-8")
            result = await eng.index_file(str(test_file), "hello", "unknown")
            assert result["status"] == "skipped"
            await eng.close()
        _run(_test())

    def test_index_same_file_up_to_date(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def foo(): pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            r1 = await eng.index_file(str(test_file), code, "python")
            r2 = await eng.index_file(str(test_file), code, "python")
            assert r2["status"] == "up_to_date"
            assert r1["file_id"] == r2["file_id"]
            await eng.close()
        _run(_test())

    def test_index_file_raises_without_init(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            try:
                await eng.index_file("foo.py", "x=1", "python")
                assert False, "Should raise RuntimeError"
            except RuntimeError as e:
                assert "数据库未初始化" in str(e)
        _run(_test())

    def test_index_path_object_conversion(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def bar(): pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            result = await eng.index_file(test_file, code, "python")
            assert result["status"] == "indexed"
            await eng.close()
        _run(_test())


class TestCodeGraphEngineSymbolExtraction:

    def test_extract_functions(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def fetch_data():\n    return 1\n\ndef main():\n    pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            nodes = await eng.get_nodes_by_file(str(test_file))
            func_names = [n["name"] for n in nodes if n["type"] in ("function", "method")]
            assert "fetch_data" in func_names
            assert "main" in func_names
            await eng.close()
        _run(_test())

    def test_extract_classes(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'class BaseService:\n    pass\n\nclass MyService(BaseService):\n    pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            nodes = await eng.get_nodes_by_file(str(test_file))
            class_names = [n["name"] for n in nodes if n["type"] == "class"]
            assert "BaseService" in class_names
            assert "MyService" in class_names
            await eng.close()
        _run(_test())

    def test_extract_imports(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'import os\nimport sys\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            nodes = await eng.get_nodes_by_file(str(test_file))
            import_names = [n["name"] for n in nodes if n["type"] == "import"]
            assert "os" in import_names
            assert "sys" in import_names
            await eng.close()
        _run(_test())

    def test_extract_edges_calls(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def helper():\n    pass\n\ndef main():\n    helper()\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            nodes = await eng.get_nodes_by_file(str(test_file))
            main_node = [n for n in nodes if n["name"] == "main" and n["type"] == "function"]
            assert len(main_node) > 0
            edges = await eng.get_edges(main_node[0]["id"], edge_type="calls")
            assert len(edges) > 0
            await eng.close()
        _run(_test())

    def test_extract_extends(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'class Base:\n    pass\n\nclass Child(Base):\n    pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            nodes = await eng.get_nodes_by_file(str(test_file))
            child_node = [n for n in nodes if n["name"] == "Child" and n["type"] == "class"]
            assert len(child_node) > 0
            edges = await eng.get_edges(child_node[0]["id"], edge_type="extends")
            assert len(edges) > 0
            await eng.close()
        _run(_test())


class TestCodeGraphEngineQuery:

    def test_get_node_existing(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def fetch_data():\n    return 1\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            node = await eng.get_node("fetch_data")
            assert node is not None
            assert node["name"] == "fetch_data"
            assert node["type"] == "function"
            assert node["file_path"] == str(test_file)
            await eng.close()
        _run(_test())

    def test_get_node_nonexistent(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            node = await eng.get_node("nonexistent_symbol")
            assert node is None
            await eng.close()
        _run(_test())

    def test_get_nodes_by_file(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def a():\n    pass\n\ndef b():\n    pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            nodes = await eng.get_nodes_by_file(str(test_file))
            assert len(nodes) > 0
            start_lines = [n["start_line"] for n in nodes]
            assert start_lines == sorted(start_lines)
            await eng.close()
        _run(_test())

    def test_get_nodes_by_file_empty(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            nodes = await eng.get_nodes_by_file(str(tmp_path / "nonexistent.py"))
            assert nodes == []
            await eng.close()
        _run(_test())

    def test_get_nodes_by_file_path_object(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def bar(): pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(test_file, code, "python")
            nodes = await eng.get_nodes_by_file(test_file)
            assert len(nodes) > 0
            await eng.close()
        _run(_test())

    def test_get_edges_invalid_type(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            edges = await eng.get_edges(1, edge_type="nonexistent")
            assert edges == []
            await eng.close()
        _run(_test())


class TestCodeGraphEngineSearch:

    def test_fts5_search(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def fetch_data():\n    return 1\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            results = await eng.search("fetch_data")
            assert len(results) > 0
            assert any(r["name"] == "fetch_data" for r in results)
            await eng.close()
        _run(_test())

    def test_fts5_search_no_results(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def foo(): pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            results = await eng.search("zzz_nonexistent_xyz")
            assert results == []
            await eng.close()
        _run(_test())

    def test_fts5_search_limit(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def a(): pass\n\ndef b(): pass\n\ndef c(): pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            results = await eng.search("def", limit=1)
            assert len(results) <= 1
            await eng.close()
        _run(_test())


class TestCodeGraphEngineDeleteFile:

    def test_delete_file_removes_data(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def main():\n    pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            stats_before = await eng.get_stats()
            await eng.delete_file(str(test_file))
            stats_after = await eng.get_stats()
            assert stats_after["files"] == stats_before["files"] - 1
            assert stats_after["nodes"] == 0
            node = await eng.get_node("main")
            assert node is None
            await eng.close()
        _run(_test())

    def test_delete_nonexistent_file(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            await eng.delete_file(str(tmp_path / "nonexistent.py"))
            await eng.close()
        _run(_test())

    def test_delete_file_path_object(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def foo(): pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(test_file, code, "python")
            await eng.delete_file(test_file)
            stats = await eng.get_stats()
            assert stats["files"] == 0
            await eng.close()
        _run(_test())


class TestCodeGraphEngineStats:

    def test_get_stats_empty(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            stats = await eng.get_stats()
            assert stats["files"] == 0
            assert stats["nodes"] == 0
            assert stats["edges"] == 0
            assert stats["unresolved_refs"] == 0
            await eng.close()
        _run(_test())

    def test_get_stats_after_index(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def foo():\n    bar()\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            stats = await eng.get_stats()
            assert stats["files"] == 1
            assert stats["nodes"] > 0
            assert stats["edges"] > 0
            await eng.close()
        _run(_test())

    def test_get_stats_without_db(self):
        eng = CodeGraphEngine()
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                future = asyncio.run_coroutine_threadsafe(eng.get_stats(), loop)
                stats = future.result()
            else:
                stats = loop.run_until_complete(eng.get_stats())
        except RuntimeError:
            stats = asyncio.run(eng.get_stats())
        assert stats == {}


class TestCodeGraphEngineClear:

    def test_clear_removes_all_data(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def main():\n    pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            await eng.index_file(str(test_file), code, "python")
            await eng.clear()
            stats = await eng.get_stats()
            assert stats["files"] == 0
            assert stats["nodes"] == 0
            assert stats["edges"] == 0
            await eng.close()
        _run(_test())


class TestCodeGraphEngineCrossPlatform:

    def test_pathlib_path_conversion(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def bar(): pass\n'
            test_file = tmp_path / "test.py"
            test_file.write_text(code, encoding="utf-8")
            p = Path(test_file)
            await eng.index_file(p, code, "python")
            nodes = await eng.get_nodes_by_file(p)
            assert len(nodes) > 0
            await eng.close()
        _run(_test())

    def test_string_path_works(self, tmp_path):
        async def _test():
            eng = CodeGraphEngine()
            await eng.init(str(tmp_path))
            code = 'def foo(): pass\n'
            test_file = str(tmp_path / "test.py")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write(code)
            result = await eng.index_file(test_file, code, "python")
            assert result["status"] == "indexed"
            await eng.close()
        _run(_test())
