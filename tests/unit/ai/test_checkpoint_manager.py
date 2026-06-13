"""检查点管理器测试"""

import pytest
import tempfile
import shutil
from pathlib import Path
from src.ai.pure_ai.checkpoint_manager import (
    CheckpointManager,
    CheckpointData,
    CheckpointLevel
)


class TestCheckpointManager:
    """CheckpointManager 测试类"""

    @pytest.fixture
    def temp_project_dir(self):
        """创建临时项目目录"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.fixture
    def checkpoint_manager(self, temp_project_dir):
        """创建检查点管理器实例"""
        return CheckpointManager(
            project_path=temp_project_dir,
            config={"auto_save_interval": 5, "max_checkpoints": 10}
        )

    def test_create_checkpoint(self, checkpoint_manager):
        """测试创建检查点"""
        processed_files = ["file1.py", "file2.py"]
        checkpoint = checkpoint_manager.create_checkpoint(
            level=CheckpointLevel.STEP,
            current_step="scanning",
            processed_files=processed_files,
            current_file="file3.py",
            agent_states={"agent1": "running"}
        )

        assert checkpoint is not None
        assert checkpoint.checkpoint_id.startswith("ckpt_")
        assert checkpoint.level == CheckpointLevel.STEP
        assert checkpoint.current_step == "scanning"
        assert checkpoint.processed_files == processed_files
        assert checkpoint.current_file == "file3.py"
        assert checkpoint.agent_states == {"agent1": "running"}
        assert checkpoint_manager.current_checkpoint == checkpoint

    def test_save_and_load_checkpoint(self, checkpoint_manager):
        """测试保存和加载检查点"""
        processed_files = ["file1.py", "file2.py"]
        checkpoint = checkpoint_manager.create_checkpoint(
            level=CheckpointLevel.FILE,
            current_step="analyzing",
            processed_files=processed_files
        )

        save_result = checkpoint_manager.save_checkpoint(checkpoint)
        assert save_result is True

        loaded_checkpoint = checkpoint_manager.load_checkpoint(checkpoint.checkpoint_id)
        assert loaded_checkpoint is not None
        assert loaded_checkpoint.checkpoint_id == checkpoint.checkpoint_id
        assert loaded_checkpoint.level == checkpoint.level
        assert loaded_checkpoint.current_step == checkpoint.current_step
        assert loaded_checkpoint.processed_files == checkpoint.processed_files

    def test_should_auto_save(self, checkpoint_manager):
        """测试自动保存触发逻辑"""
        assert checkpoint_manager.auto_save_interval == 5

        for i in range(4):
            assert checkpoint_manager.should_auto_save() is False

        assert checkpoint_manager.should_auto_save() is True

        for i in range(4):
            assert checkpoint_manager.should_auto_save() is False
        assert checkpoint_manager.should_auto_save() is True

    def test_list_checkpoints(self, checkpoint_manager):
        """测试列出检查点"""
        checkpoint1 = checkpoint_manager.create_checkpoint(
            level=CheckpointLevel.STEP,
            current_step="step1",
            processed_files=["file1.py"]
        )
        checkpoint_manager.save_checkpoint(checkpoint1)

        checkpoint2 = checkpoint_manager.create_checkpoint(
            level=CheckpointLevel.AGENT,
            current_step="step2",
            processed_files=["file2.py"]
        )
        checkpoint_manager.save_checkpoint(checkpoint2)

        checkpoints = checkpoint_manager.list_checkpoints()
        assert len(checkpoints) == 2
        assert all(isinstance(cp, CheckpointData) for cp in checkpoints)
        assert checkpoints[0].timestamp >= checkpoints[1].timestamp

    def test_delete_checkpoint(self, checkpoint_manager):
        """测试删除检查点"""
        checkpoint = checkpoint_manager.create_checkpoint(
            level=CheckpointLevel.STEP,
            current_step="to_delete",
            processed_files=["file1.py"]
        )
        checkpoint_manager.save_checkpoint(checkpoint)

        delete_result = checkpoint_manager.delete_checkpoint(checkpoint.checkpoint_id)
        assert delete_result is True

        loaded = checkpoint_manager.load_checkpoint(checkpoint.checkpoint_id)
        assert loaded is None

        non_existent_result = checkpoint_manager.delete_checkpoint("non_existent_id")
        assert non_existent_result is False
