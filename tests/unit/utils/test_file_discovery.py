"""Utils file discovery module tests"""

import os
import tempfile
import pytest
from pathlib import Path

from src.utils.file_discovery import (
    FileDiscoveryEngine, DiscoveryConfig, FileInfo,
    FileType, Language,
)


class TestFileType:
    def test_file_type_values(self):
        assert FileType.SOURCE.value == "source"
        assert FileType.CONFIG.value == "config"
        assert FileType.DOCUMENTATION.value == "documentation"
        assert FileType.TEST.value == "test"
        assert FileType.BUILD.value == "build"
        assert FileType.DEPENDENCY.value == "dependency"
        assert FileType.OTHER.value == "other"


class TestLanguage:
    def test_language_values(self):
        assert Language.PYTHON.value == "python"
        assert Language.JAVASCRIPT.value == "javascript"
        assert Language.JAVA.value == "java"
        assert Language.CPP.value == "cpp"
        assert Language.GO.value == "go"
        assert Language.RUST.value == "rust"


class TestFileInfo:
    def test_to_dict(self):
        info = FileInfo(
            path=Path("test.py"),
            size=100,
            language=Language.PYTHON,
            file_type=FileType.SOURCE,
            extension=".py",
            line_count=10,
            hash="abc123",
        )
        d = info.to_dict()
        assert d["path"] == "test.py"
        assert d["size"] == 100
        assert d["language"] == "python"
        assert d["file_type"] == "source"
        assert d["extension"] == ".py"
        assert d["line_count"] == 10
        assert d["hash"] == "abc123"


class TestDiscoveryConfig:
    def test_default_values(self):
        config = DiscoveryConfig()
        assert "*.py" in config.include_patterns
        assert "*.js" in config.include_patterns
        assert "node_modules/**" in config.exclude_patterns
        assert "__pycache__/**" in config.exclude_patterns
        assert config.max_file_size == 10 * 1024 * 1024
        assert config.min_file_size == 0
        assert config.follow_symlinks is False
        assert config.max_depth == 100
        assert config.exclude_hidden is True


class TestFileDiscoveryEngine:
    def test_init_default(self):
        engine = FileDiscoveryEngine()
        assert engine.config is not None
        assert engine._file_cache == {}

    def test_init_with_config(self):
        config = DiscoveryConfig(max_file_size=1024)
        engine = FileDiscoveryEngine(config=config)
        assert engine.config.max_file_size == 1024

    def test_discover_files_nonexistent_path(self):
        engine = FileDiscoveryEngine()
        with pytest.raises(FileNotFoundError):
            engine.discover_files("/nonexistent/path")

    def test_discover_files_not_a_directory(self):
        engine = FileDiscoveryEngine()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            with pytest.raises(NotADirectoryError):
                engine.discover_files(f.name)

    def test_discover_python_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = Path(tmpdir) / "test.py"
            py_file.write_text("print('hello')")
            js_file = Path(tmpdir) / "test.js"
            js_file.write_text("console.log('hello')")

            engine = FileDiscoveryEngine()
            files = engine.discover_files(tmpdir, include_patterns=["*.py"])

            assert len(files) == 1
            assert files[0].extension == ".py"

    def test_discover_files_with_exclude(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pycache = Path(tmpdir) / "__pycache__"
            pycache.mkdir()
            (pycache / "module.pyc").write_text("bytecode")
            py_file = Path(tmpdir) / "test.py"
            py_file.write_text("code")

            engine = FileDiscoveryEngine()
            files = engine.discover_files(tmpdir)

            pyc_files = [f for f in files if "__pycache__" in str(f.path)]
            assert len(pyc_files) == 0

    def test_discover_files_max_size(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            large_file = Path(tmpdir) / "large.py"
            large_file.write_text("x" * 1024)
            small_file = Path(tmpdir) / "small.py"
            small_file.write_text("code")

            engine = FileDiscoveryEngine()
            files = engine.discover_files(tmpdir, max_file_size=512)

            large_found = [f for f in files if f.path.name == "large.py"]
            assert len(large_found) == 0

    def test_discover_files_min_size(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tiny_file = Path(tmpdir) / "tiny.py"
            tiny_file.write_text("x")
            normal_file = Path(tmpdir) / "normal.py"
            normal_file.write_text("x" * 100)

            config = DiscoveryConfig(min_file_size=10)
            engine = FileDiscoveryEngine(config=config)
            files = engine.discover_files(tmpdir)

            tiny_found = [f for f in files if f.path.name == "tiny.py"]
            assert len(tiny_found) == 0

    def test_discover_nested_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()
            (subdir / "nested.py").write_text("nested code")
            (Path(tmpdir) / "root.py").write_text("root code")

            engine = FileDiscoveryEngine()
            files = engine.discover_files(tmpdir, include_patterns=["*.py"])
            assert len(files) == 2

    def test_discover_files_max_depth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            deep = Path(tmpdir) / "a" / "b" / "c"
            deep.mkdir(parents=True)
            (deep / "deep.py").write_text("deep code")
            (Path(tmpdir) / "root.py").write_text("root code")

            config = DiscoveryConfig(max_depth=1)
            engine = FileDiscoveryEngine(config=config)
            files = engine.discover_files(tmpdir, include_patterns=["*.py"])
            assert len(files) == 1

    def test_filter_by_language(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.py").write_text("python")
            (Path(tmpdir) / "test.js").write_text("javascript")

            engine = FileDiscoveryEngine()
            files = engine.discover_files(tmpdir)
            py_files = engine.filter_by_language(files, [Language.PYTHON])
            assert len(py_files) == 1
            assert py_files[0].language == Language.PYTHON

    def test_filter_by_language_string(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.py").write_text("python")
            (Path(tmpdir) / "test.js").write_text("javascript")

            engine = FileDiscoveryEngine()
            files = engine.discover_files(tmpdir)
            py_files = engine.filter_by_language(files, ["python"])
            assert len(py_files) == 1

    def test_filter_by_type(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir) / "tests"
            test_dir.mkdir()
            (test_dir / "test_example.py").write_text("test code")
            (Path(tmpdir) / "main.py").write_text("main code")

            engine = FileDiscoveryEngine()
            files = engine.discover_files(tmpdir)
            test_files = engine.filter_by_type(files, [FileType.TEST])
            test_in_tests = [f for f in test_files if "tests" in str(f.path)]
            assert len(test_in_tests) >= 1

    def test_detect_language(self):
        engine = FileDiscoveryEngine()
        assert engine.detect_language(Path("test.py")) == Language.PYTHON
        assert engine.detect_language(Path("test.js")) == Language.JAVASCRIPT
        assert engine.detect_language(Path("test.java")) == Language.JAVA
        assert engine.detect_language(Path("test.go")) == Language.GO
        assert engine.detect_language(Path("test.unknown")) == Language.UNKNOWN

    def test_detect_file_type(self):
        engine = FileDiscoveryEngine()
        assert engine.detect_file_type(Path("test.py")) == FileType.SOURCE
        assert engine.detect_file_type(Path("tests/test.py")) == FileType.TEST
        assert engine.detect_file_type(Path("docs/readme.md")) == FileType.DOCUMENTATION

    def test_get_file_metadata(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("line1\nline2\nline3\n")
            f.flush()
            engine = FileDiscoveryEngine()
            info = engine.get_file_metadata(f.name)
            assert info.size > 0
            assert info.language == Language.PYTHON
            assert info.extension == ".py"

    def test_matches_pattern(self):
        engine = FileDiscoveryEngine()
        assert engine._matches_patterns(Path("test.py"), ["*.py"]) is True
        assert engine._matches_patterns(Path("test.js"), ["*.py"]) is False
        assert engine._matches_patterns(Path("test.py"), ["*.py", "*.js"]) is True

    def test_should_skip_file(self):
        engine = FileDiscoveryEngine()
        assert engine._should_skip_file(Path("__pycache__/module.pyc"), ["__pycache__/**"]) is True
        assert engine._should_skip_file(Path("test.py"), ["__pycache__/**"]) is False

    def test_should_skip_directory(self):
        engine = FileDiscoveryEngine()
        visited = set()
        should_skip = engine._should_skip_directory(
            Path("node_modules"), ["node_modules/**"], visited
        )
        assert should_skip is True

    def test_file_cache(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.py").write_text("cache test")
            engine = FileDiscoveryEngine()
            engine.discover_files(tmpdir, include_patterns=["*.py"])
            assert len(engine._file_cache) > 0

    def test_discover_hidden_files_excluded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hidden = Path(tmpdir) / ".hidden"
            hidden.mkdir()
            (hidden / "secret.py").write_text("secret")
            (Path(tmpdir) / "visible.py").write_text("visible")

            engine = FileDiscoveryEngine()
            files = engine.discover_files(tmpdir)
            hidden_files = [f for f in files if ".hidden" in str(f.path)]
            assert len(hidden_files) == 0

    def test_discover_config_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "config.yaml").write_text("key: value")
            (Path(tmpdir) / "settings.json").write_text('{"key": "value"}')

            engine = FileDiscoveryEngine()
            files = engine.discover_files(tmpdir)
            yaml_files = [f for f in files if f.extension in [".yaml", ".json"]]
            assert len(yaml_files) >= 2
