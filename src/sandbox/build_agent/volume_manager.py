"""
VolumeManager - 容器卷管理器

管理项目代码卷挂载和构建产物持久化。
"""

import shutil
import tempfile
import logging
from pathlib import Path, PurePosixPath
from typing import Dict, Optional
from dataclasses import dataclass


logger = logging.getLogger(__name__)


def normalize_to_posix_path(path: str) -> str:
    """将路径规范化为POSIX格式（使用正斜杠）"""
    return str(PurePosixPath(path.replace('\\', '/')))


@dataclass
class VolumeMount:
    """卷挂载配置"""
    source: str
    target: str
    read_only: bool = False


class VolumeManager:
    """容器卷管理器"""

    IGNORE_PATTERNS = {'.git', '__pycache__', 'node_modules', '.idea', '.vscode', '*.class', '*.pyc'}

    def __init__(self, base_dir: Optional[str] = None):
        temp_base = Path(tempfile.gettempdir()) / "hos-ls-volumes"
        base_path = str(Path(base_dir) if base_dir else temp_base).replace('\\', '/')
        self.base_dir = PurePosixPath(base_path)
        Path(base_path).mkdir(parents=True, exist_ok=True)
        self.active_volumes: Dict[str, VolumeMount] = {}

    def create_project_volume(self, project_id: str, project_path: str) -> VolumeMount:
        """为项目创建卷挂载"""
        volume_name = f"hos-ls-project-{project_id}"
        volume_path = PurePosixPath(str(self.base_dir / volume_name).replace('\\', '/'))

        if volume_path.exists():
            logger.info(f"Removing existing volume: {volume_path}")
            shutil.rmtree(volume_path)

        logger.info(f"Copying project from {project_path} to {volume_path}")

        ignore_func = shutil.ignore_patterns(
            '.git', '__pycache__', 'node_modules', '.idea', '.vscode',
            '*.class', '*.pyc', 'target', 'build', 'dist', '*.jar', '*.war'
        )

        shutil.copytree(project_path, volume_path, ignore=ignore_func)

        mount = VolumeMount(
            source=normalize_to_posix_path(str(volume_path)),
            target="/project",
            read_only=False
        )
        self.active_volumes[project_id] = mount
        logger.info(f"Created volume mount for project {project_id}: {mount}")
        return mount

    def get_build_output(self, project_id: str) -> Optional[str]:
        """获取构建产物路径"""
        if project_id not in self.active_volumes:
            return None

        mount = self.active_volumes[project_id]
        return mount.source

    def cleanup_project(self, project_id: str) -> bool:
        """清理项目卷"""
        if project_id not in self.active_volumes:
            return True

        mount = self.active_volumes[project_id]
        try:
            volume_path = Path(mount.source)
            if volume_path.exists():
                logger.info(f"Cleaning up volume: {volume_path}")
                shutil.rmtree(volume_path)
            del self.active_volumes[project_id]
            return True
        except Exception as e:
            logger.error(f"Failed to cleanup volume for {project_id}: {e}")
            return False

    def cleanup_all(self) -> int:
        """清理所有卷"""
        count = 0
        for project_id in list(self.active_volumes.keys()):
            if self.cleanup_project(project_id):
                count += 1
        logger.info(f"Cleaned up {count} volumes")
        return count

    def get_volume_size(self, project_id: str) -> int:
        """获取卷大小（字节）"""
        if project_id not in self.active_volumes:
            return 0

        mount = self.active_volumes[project_id]
        volume_path = Path(mount.source)

        if not volume_path.exists():
            return 0

        total_size = 0
        for dirpath, dirnames, filenames in shutil.os.walk(volume_path):
            for filename in filenames:
                filepath = shutil.os.path.join(dirpath, filename)
                try:
                    total_size += shutil.os.path.getsize(filepath)
                except Exception:
                    pass

        return total_size

    def list_active_volumes(self) -> Dict[str, VolumeMount]:
        """列出所有活跃卷"""
        return self.active_volumes.copy()
