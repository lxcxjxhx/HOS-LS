"""导入管理器模块

实现NVD数据导入的断点续传和去重机制。
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Set, Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ImportManager:
    """导入管理器"""

    def __init__(self, checkpoint_dir: Optional[Path] = None):
        """初始化导入管理器

        Args:
            checkpoint_dir: 检查点目录
        """
        self.checkpoint_dir = checkpoint_dir or Path("./import_checkpoints")
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        self.checkpoint_path = self.checkpoint_dir / "import_checkpoint.json"
        self.processed_cves_path = self.checkpoint_dir / "processed_cves.json"
        
        self._processed_cves: Set[str] = set()
        self._checkpoint: Dict[str, Any] = {}
        
        # 加载数据
        self._load_processed_cves()
        self._load_checkpoint()

    def _load_processed_cves(self):
        """加载已处理的CVE列表"""
        if self.processed_cves_path.exists():
            try:
                with open(self.processed_cves_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._processed_cves = set(data.get('processed_cves', []))
                logger.info(f"加载了 {len(self._processed_cves)} 个已处理的CVE")
            except Exception as e:
                logger.error(f"加载已处理CVE列表失败: {e}")
                self._processed_cves = set()

    def _save_processed_cves(self):
        """保存已处理的CVE列表"""
        try:
            data = {
                'processed_cves': list(self._processed_cves),
                'last_updated': datetime.now().isoformat()
            }
            with open(self.processed_cves_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存已处理CVE列表失败: {e}")

    def _load_checkpoint(self):
        """加载检查点"""
        if self.checkpoint_path.exists():
            try:
                with open(self.checkpoint_path, 'r', encoding='utf-8') as f:
                    self._checkpoint = json.load(f)
                logger.info(f"加载检查点成功")
            except Exception as e:
                logger.error(f"加载检查点失败: {e}")
                self._checkpoint = self._get_default_checkpoint()
        else:
            self._checkpoint = self._get_default_checkpoint()

    def _save_checkpoint(self):
        """保存检查点"""
        try:
            self._checkpoint['last_updated'] = datetime.now().isoformat()
            with open(self.checkpoint_path, 'w', encoding='utf-8') as f:
                json.dump(self._checkpoint, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存检查点失败: {e}")

    def _get_default_checkpoint(self) -> Dict[str, Any]:
        """获取默认检查点数据"""
        return {
            'last_processed_file': 0,
            'last_cve_id': None,
            'processed_count': 0,
            'success_count': 0,
            'failed_count': 0,
            'current_batch': 0,
            'total_batches': 0,
            'last_updated': datetime.now().isoformat()
        }

    def is_cve_processed(self, cve_id: str) -> bool:
        """检查CVE是否已处理

        Args:
            cve_id: CVE ID

        Returns:
            是否已处理
        """
        return cve_id in self._processed_cves

    def mark_cve_processed(self, cve_id: str):
        """标记CVE为已处理

        Args:
            cve_id: CVE ID
        """
        self._processed_cves.add(cve_id)
        # 每100个CVE保存一次
        if len(self._processed_cves) % 100 == 0:
            self._save_processed_cves()

    def mark_cve_failed(self, cve_id: str):
        """标记CVE处理失败

        Args:
            cve_id: CVE ID
        """
        # 可以在这里添加失败处理逻辑
        logger.warning(f"CVE {cve_id} 处理失败")

    def update_checkpoint(self, **kwargs):
        """更新检查点

        Args:
            **kwargs: 检查点数据
        """
        self._checkpoint.update(kwargs)
        self._save_checkpoint()

    def get_checkpoint(self) -> Dict[str, Any]:
        """获取检查点数据

        Returns:
            检查点数据
        """
        return self._checkpoint

    def reset_checkpoint(self):
        """重置检查点"""
        self._checkpoint = self._get_default_checkpoint()
        self._save_checkpoint()
        logger.info("检查点已重置")

    def clear_processed_cves(self):
        """清除已处理的CVE列表"""
        self._processed_cves.clear()
        self._save_processed_cves()
        logger.info("已处理CVE列表已清除")

    def get_processed_count(self) -> int:
        """获取已处理的CVE数量

        Returns:
            已处理的CVE数量
        """
        return len(self._processed_cves)

    def get_statistics(self) -> Dict[str, Any]:
        """获取导入统计信息

        Returns:
            统计信息
        """
        return {
            'processed_cves_count': len(self._processed_cves),
            'checkpoint': self._checkpoint
        }

    def generate_batch_id(self, batch_number: int) -> str:
        """生成批次ID

        Args:
            batch_number: 批次号

        Returns:
            批次ID
        """
        return hashlib.sha256(f"batch_{batch_number}_{datetime.now().isoformat()}".encode()).hexdigest()[:16]

    def save_batch_progress(self, batch_id: str, progress: Dict[str, Any]):
        """保存批次进度

        Args:
            batch_id: 批次ID
            progress: 进度数据
        """
        batch_path = self.checkpoint_dir / f"batch_{batch_id}.json"
        try:
            data = {
                'batch_id': batch_id,
                'progress': progress,
                'timestamp': datetime.now().isoformat()
            }
            with open(batch_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存批次进度失败: {e}")

    def load_batch_progress(self, batch_id: str) -> Optional[Dict[str, Any]]:
        """加载批次进度

        Args:
            batch_id: 批次ID

        Returns:
            进度数据或None
        """
        batch_path = self.checkpoint_dir / f"batch_{batch_id}.json"
        if batch_path.exists():
            try:
                with open(batch_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return data.get('progress')
            except Exception as e:
                logger.error(f"加载批次进度失败: {e}")
        return None

    def cleanup_old_checkpoints(self, keep_days: int = 7):
        """清理旧的检查点文件

        Args:
            keep_days: 保留天数
        """
        import time
        cutoff_time = time.time() - (keep_days * 24 * 3600)
        
        for file in self.checkpoint_dir.iterdir():
            if file.is_file() and file.suffix == '.json':
                try:
                    file_time = file.stat().st_mtime
                    if file_time < cutoff_time:
                        file.unlink()
                        logger.info(f"清理旧检查点文件: {file.name}")
                except Exception as e:
                    logger.error(f"清理检查点文件失败: {e}")


def create_import_manager(checkpoint_dir: Optional[Path] = None) -> ImportManager:
    """创建导入管理器

    Args:
        checkpoint_dir: 检查点目录

    Returns:
        导入管理器实例
    """
    return ImportManager(checkpoint_dir)