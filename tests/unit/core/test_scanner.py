"""Scanner module tests - focused on testable components"""

import os
import tempfile
import pytest
from pathlib import Path

from src.core.scanner import FileContentCache, read_file_content


class TestFileContentCache:
    def setup_method(self):
        FileContentCache.clear()

    def teardown_method(self):
        FileContentCache.clear()

    def test_put_and_get(self):
        FileContentCache.put("test.py", "content")
        assert FileContentCache.get("test.py") == "content"

    def test_get_nonexistent(self):
        assert FileContentCache.get("nonexistent.py") is None

    def test_cache_overwrite(self):
        FileContentCache.put("test.py", "old_content")
        FileContentCache.put("test.py", "new_content")
        assert FileContentCache.get("test.py") == "new_content"

    def test_clear(self):
        FileContentCache.put("file1.py", "content1")
        FileContentCache.put("file2.py", "content2")
        FileContentCache.clear()
        assert FileContentCache.get("file1.py") is None
        assert FileContentCache.get("file2.py") is None
        assert FileContentCache._current_size_bytes == 0

    def test_path_str_conversion(self):
        FileContentCache.put(Path("test.py"), "content")
        assert FileContentCache.get(Path("test.py")) == "content"
        assert FileContentCache.get("test.py") == "content"

    def test_large_content_cache(self):
        large_content = "x" * 60 * 1024 * 1024
        FileContentCache.put("large.py", large_content)
        content = FileContentCache.get("large.py")
        assert content == large_content


class TestReadFileContent:
    def test_read_small_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('hello')\n")
            f.flush()
            content = read_file_content(f.name)
            assert content == "print('hello')\n"

    def test_read_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            read_file_content("/nonexistent/file.py")

    def test_read_empty_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.flush()
            content = read_file_content(f.name)
            assert content == ""

    def test_read_unicode_content(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write("# 中文注释\nprint('你好')\n")
            f.flush()
            content = read_file_content(f.name)
            assert "中文" in content
            assert "你好" in content

    def test_cache_hits(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("cached content\n")
            f.flush()
            content1 = read_file_content(f.name)
            content2 = read_file_content(f.name)
            assert content1 == content2
            assert FileContentCache.get(f.name) == content1

    def test_read_with_max_content(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("line1\nline2\nline3\nline4\nline5\n")
            f.flush()
            content = read_file_content(f.name, max_content_length=10)
            assert len(content) <= 10 or "截断" in content
