"""增量索引管理器测试"""

import pytest
import tempfile
import shutil
import os
import time
from pathlib import Path
from src.ai.pure_ai.incremental_index import (
    IncrementalIndexManager,
    FileIndexEntry
)


class TestIncrementalIndexManager:
    """IncrementalIndexManager 测试类"""

    @pytest.fixture
    def temp_project_dir(self):
        """创建临时项目目录"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.fixture
    def index_manager(self, temp_project_dir):
        """创建增量索引管理器实例"""
        return IncrementalIndexManager(
            project_path=temp_project_dir,
            config={"hash_cache_size": 8192}
        )

    @pytest.fixture
    def temp_files(self, temp_project_dir):
        """创建临时测试文件"""
        files = []
        for i in range(3):
            file_path = Path(temp_project_dir) / f"test_file_{i}.py"
            file_path.write_text(f"# Test file {i}\nprint('hello')")
            files.append(str(file_path))
        return files

    def test_build_index(self, index_manager, temp_files):
        """测试构建索引"""
        indexed_count = index_manager.build_index(temp_files)

        assert indexed_count == 3
        assert len(index_manager.get_indexed_files()) == 3

        for file_path in temp_files:
            entry = index_manager.get_index_entry(file_path)
            assert entry is not None
            assert entry.file_path == file_path
            assert entry.file_hash is not None
            assert entry.size > 0

    def test_detect_changes(self, index_manager, temp_files):
        """测试检测文件变更"""
        index_manager.build_index(temp_files)

        new_file = Path(temp_project_dir := index_manager.project_path) / "new_file.py"
        new_file_path = str(new_file)
        new_file.write_text("# New file")
        temp_files.append(new_file_path)

        changes = index_manager.detect_changes(temp_files)

        assert "added" in changes
        assert new_file_path in changes["added"]

        assert "removed" in changes
        removed_file = str(Path(temp_project_dir) / "test_file_0.py")
        remaining_files = [f for f in temp_files if f != removed_file]
        changes_after_removal = index_manager.detect_changes(remaining_files)
        assert removed_file in changes_after_removal["removed"]

    def test_get_unchanged_files(self, index_manager, temp_files):
        """测试获取未变更文件"""
        index_manager.build_index(temp_files)

        all_files = temp_files + ["new_file.py", "another_file.py"]
        changed_files = {"new_file.py"}

        unchanged = index_manager.get_unchanged_files(
            changed_files=set(changed_files),
            all_files=all_files
        )

        assert len(unchanged) == len(temp_files)
        for f in temp_files:
            assert f in unchanged

    def test_is_index_valid(self, index_manager, temp_files):
        """测试索引有效性检查"""
        assert index_manager.is_index_valid() is False

        index_manager.build_index(temp_files)
        assert index_manager.is_index_valid() is True

        index_manager.clear_index()
        assert index_manager.is_index_valid() is False

    def test_update_index(self, index_manager, temp_files):
        """测试更新索引"""
        index_manager.build_index(temp_files)
        original_entry = index_manager.get_index_entry(temp_files[0])
        original_hash = original_entry.file_hash

        time.sleep(0.1)
        with open(temp_files[0], "a") as f:
            f.write("\n# modified")

        new_hash = index_manager._compute_file_hash(temp_files[0])
        new_stat = os.stat(temp_files[0])

        index_manager.update_index(
            file_path=temp_files[0],
            file_hash=new_hash,
            mtime=new_stat.st_mtime,
            size=new_stat.st_size
        )

        updated_entry = index_manager.get_index_entry(temp_files[0])
        assert updated_entry.file_hash == new_hash
        assert updated_entry.file_hash != original_hash
