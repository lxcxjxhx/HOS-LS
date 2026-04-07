"""NVD导入模块

实现NVD数据的流式处理、批量embedding和导入功能。
"""

import json
import zipfile
import concurrent.futures
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from src.utils.logger import get_logger
from src.integration.nvd_processor import NVDProcessor, CVEStructuredData, CVEChunk
from src.integration.import_manager import ImportManager, create_import_manager
from src.storage.hybrid_store import HybridStore

logger = get_logger(__name__)


class NVDImporter:
    """NVD导入器"""

    def __init__(self, hybrid_store: HybridStore, batch_size: int = 100):
        """初始化NVD导入器

        Args:
            hybrid_store: 混合存储实例
            batch_size: 批量处理大小
        """
        self.hybrid_store = hybrid_store
        self.batch_size = batch_size
        self.processor = NVDProcessor()
        self.import_manager = create_import_manager()
        self.checkpoint_path = Path("./nvd_import_checkpoint.json")

    def load_checkpoint(self) -> Dict[str, Any]:
        """加载检查点

        Returns:
            检查点数据
        """
        if not self.checkpoint_path.exists():
            return {
                "last_processed_file": 0,
                "last_cve_id": None,
                "processed_count": 0,
                "success_count": 0,
                "failed_count": 0,
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            with open(self.checkpoint_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载检查点失败: {e}")
            return {
                "last_processed_file": 0,
                "last_cve_id": None,
                "processed_count": 0,
                "success_count": 0,
                "failed_count": 0,
                "timestamp": datetime.now().isoformat()
            }

    def save_checkpoint(self, checkpoint: Dict[str, Any]):
        """保存检查点

        Args:
            checkpoint: 检查点数据
        """
        try:
            checkpoint['timestamp'] = datetime.now().isoformat()
            with open(self.checkpoint_path, 'w', encoding='utf-8') as f:
                json.dump(checkpoint, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存检查点失败: {e}")

    def process_zip_file(self, zip_path: Path) -> Dict[str, int]:
        """处理NVD ZIP文件

        Args:
            zip_path: ZIP文件路径

        Returns:
            处理统计信息
        """
        stats = {
            "total": 0,
            "success": 0,
            "failed": 0
        }

        # 加载检查点
        checkpoint = self.load_checkpoint()

        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # 过滤出JSON文件
                json_files = [member for member in zf.infolist() 
                            if member.filename.endswith('.json') and not member.is_dir()]
                
                logger.info(f"发现 {len(json_files)} 个JSON文件")
                
                # 跳过已处理的文件
                json_files = json_files[checkpoint['last_processed_file']:]
                
                for file_idx, member in enumerate(json_files, checkpoint['last_processed_file']):
                    try:
                        logger.info(f"处理文件 {member.filename} ({file_idx + 1}/{len(json_files) + checkpoint['last_processed_file']})")
                        
                        with zf.open(member) as f:
                            data = json.load(f)
                            
                            # 检查是否是CVE集合
                            if 'CVE_Items' in data:
                                cve_items = data.get('CVE_Items', [])
                                logger.info(f"文件包含 {len(cve_items)} 个CVE")
                                
                                # 批量处理CVE
                                batch = []
                                for item in cve_items:
                                    result = self.processor.parse_nvd(item)
                                    if result:
                                        cve_id = result[0].cve_id
                                        # 检查是否已处理
                                        if not self.import_manager.is_cve_processed(cve_id):
                                            batch.append(result)
                                    
                                    # 达到批次大小，执行批量存储
                                    if len(batch) >= self.batch_size:
                                        success = self.hybrid_store.store_cves_batch(batch)
                                        stats['success'] += success
                                        stats['failed'] += len(batch) - success
                                        stats['total'] += len(batch)
                                        
                                        # 标记成功处理的CVE
                                        for cve_data in batch[:success]:
                                            self.import_manager.mark_cve_processed(cve_data[0].cve_id)
                                        
                                        # 标记失败处理的CVE
                                        for cve_data in batch[success:]:
                                            self.import_manager.mark_cve_failed(cve_data[0].cve_id)
                                        
                                        # 更新检查点
                                        checkpoint['processed_count'] += len(batch)
                                        checkpoint['success_count'] += success
                                        checkpoint['failed_count'] += len(batch) - success
                                        checkpoint['last_processed_file'] = file_idx
                                        if batch:
                                            checkpoint['last_cve_id'] = batch[-1][0].cve_id
                                        self.save_checkpoint(checkpoint)
                                        
                                        # 更新导入管理器检查点
                                        self.import_manager.update_checkpoint(**checkpoint)
                                        
                                        batch = []
                                
                                # 处理剩余的CVE
                                if batch:
                                    success = self.hybrid_store.store_cves_batch(batch)
                                    stats['success'] += success
                                    stats['failed'] += len(batch) - success
                                    stats['total'] += len(batch)
                                    
                                    # 标记成功处理的CVE
                                    for cve_data in batch[:success]:
                                        self.import_manager.mark_cve_processed(cve_data[0].cve_id)
                                    
                                    # 标记失败处理的CVE
                                    for cve_data in batch[success:]:
                                        self.import_manager.mark_cve_failed(cve_data[0].cve_id)
                                    
                                    # 更新检查点
                                    checkpoint['processed_count'] += len(batch)
                                    checkpoint['success_count'] += success
                                    checkpoint['failed_count'] += len(batch) - success
                                    checkpoint['last_processed_file'] = file_idx
                                    if batch:
                                        checkpoint['last_cve_id'] = batch[-1][0].cve_id
                                    self.save_checkpoint(checkpoint)
                                    
                                    # 更新导入管理器检查点
                                    self.import_manager.update_checkpoint(**checkpoint)
                            else:
                                # 单个CVE文件
                                result = self.processor.parse_nvd(data)
                                if result:
                                    cve_id = result[0].cve_id
                                    # 检查是否已处理
                                    if not self.import_manager.is_cve_processed(cve_id):
                                        success = self.hybrid_store.store_cve(*result)
                                        if success:
                                            stats['success'] += 1
                                            self.import_manager.mark_cve_processed(cve_id)
                                        else:
                                            stats['failed'] += 1
                                            self.import_manager.mark_cve_failed(cve_id)
                                        stats['total'] += 1
                                        
                                        # 更新检查点
                                        checkpoint['processed_count'] += 1
                                        if success:
                                            checkpoint['success_count'] += 1
                                        else:
                                            checkpoint['failed_count'] += 1
                                        checkpoint['last_processed_file'] = file_idx
                                        checkpoint['last_cve_id'] = cve_id
                                        self.save_checkpoint(checkpoint)
                                        
                                        # 更新导入管理器检查点
                                        self.import_manager.update_checkpoint(**checkpoint)
                    except Exception as e:
                        logger.error(f"处理文件 {member.filename} 失败: {e}")
                        continue
        except Exception as e:
            logger.error(f"处理ZIP文件失败: {e}")
        
        return stats

    def process_directory(self, directory: Path) -> Dict[str, int]:
        """处理NVD目录

        Args:
            directory: 目录路径

        Returns:
            处理统计信息
        """
        stats = {
            "total": 0,
            "success": 0,
            "failed": 0
        }

        # 加载检查点
        checkpoint = self.load_checkpoint()

        try:
            json_files = list(directory.rglob('*.json'))
            logger.info(f"发现 {len(json_files)} 个JSON文件")
            
            # 跳过已处理的文件
            json_files = json_files[checkpoint['last_processed_file']:]
            
            for file_idx, json_file in enumerate(json_files, checkpoint['last_processed_file']):
                try:
                    logger.info(f"处理文件 {json_file.name} ({file_idx + 1}/{len(json_files) + checkpoint['last_processed_file']})")
                    
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        # 检查是否是CVE集合
                        if 'CVE_Items' in data:
                            cve_items = data.get('CVE_Items', [])
                            logger.info(f"文件包含 {len(cve_items)} 个CVE")
                            
                            # 批量处理CVE
                            batch = []
                            for item in cve_items:
                                result = self.processor.parse_nvd(item)
                                if result:
                                    cve_id = result[0].cve_id
                                    # 检查是否已处理
                                    if not self.import_manager.is_cve_processed(cve_id):
                                        batch.append(result)
                                    
                                    # 达到批次大小，执行批量存储
                                    if len(batch) >= self.batch_size:
                                        success = self.hybrid_store.store_cves_batch(batch)
                                        stats['success'] += success
                                        stats['failed'] += len(batch) - success
                                        stats['total'] += len(batch)
                                        
                                        # 标记成功处理的CVE
                                        for cve_data in batch[:success]:
                                            self.import_manager.mark_cve_processed(cve_data[0].cve_id)
                                        
                                        # 标记失败处理的CVE
                                        for cve_data in batch[success:]:
                                            self.import_manager.mark_cve_failed(cve_data[0].cve_id)
                                        
                                        # 更新检查点
                                        checkpoint['processed_count'] += len(batch)
                                        checkpoint['success_count'] += success
                                        checkpoint['failed_count'] += len(batch) - success
                                        checkpoint['last_processed_file'] = file_idx
                                        if batch:
                                            checkpoint['last_cve_id'] = batch[-1][0].cve_id
                                        self.save_checkpoint(checkpoint)
                                        
                                        # 更新导入管理器检查点
                                        self.import_manager.update_checkpoint(**checkpoint)
                                        
                                        batch = []
                            
                            # 处理剩余的CVE
                            if batch:
                                success = self.hybrid_store.store_cves_batch(batch)
                                stats['success'] += success
                                stats['failed'] += len(batch) - success
                                stats['total'] += len(batch)
                                
                                # 标记成功处理的CVE
                                for cve_data in batch[:success]:
                                    self.import_manager.mark_cve_processed(cve_data[0].cve_id)
                                
                                # 标记失败处理的CVE
                                for cve_data in batch[success:]:
                                    self.import_manager.mark_cve_failed(cve_data[0].cve_id)
                                
                                # 更新检查点
                                checkpoint['processed_count'] += len(batch)
                                checkpoint['success_count'] += success
                                checkpoint['failed_count'] += len(batch) - success
                                checkpoint['last_processed_file'] = file_idx
                                if batch:
                                    checkpoint['last_cve_id'] = batch[-1][0].cve_id
                                self.save_checkpoint(checkpoint)
                                
                                # 更新导入管理器检查点
                                self.import_manager.update_checkpoint(**checkpoint)
                        else:
                            # 单个CVE文件
                            result = self.processor.parse_nvd(data)
                            if result:
                                cve_id = result[0].cve_id
                                # 检查是否已处理
                                if not self.import_manager.is_cve_processed(cve_id):
                                    success = self.hybrid_store.store_cve(*result)
                                    if success:
                                        stats['success'] += 1
                                        self.import_manager.mark_cve_processed(cve_id)
                                    else:
                                        stats['failed'] += 1
                                        self.import_manager.mark_cve_failed(cve_id)
                                    stats['total'] += 1
                                    
                                    # 更新检查点
                                    checkpoint['processed_count'] += 1
                                    if success:
                                        checkpoint['success_count'] += 1
                                    else:
                                        checkpoint['failed_count'] += 1
                                    checkpoint['last_processed_file'] = file_idx
                                    checkpoint['last_cve_id'] = cve_id
                                    self.save_checkpoint(checkpoint)
                                    
                                    # 更新导入管理器检查点
                                    self.import_manager.update_checkpoint(**checkpoint)
                except Exception as e:
                    logger.error(f"处理文件 {json_file} 失败: {e}")
                    continue
        except Exception as e:
            logger.error(f"处理目录失败: {e}")
        
        return stats

    def process_cve_batch(self, cve_data_list: List[Tuple[CVEStructuredData, List[CVEChunk]]) -> int:
        """处理CVE批次

        Args:
            cve_data_list: CVE数据列表

        Returns:
            成功存储的数量
        """
        return self.hybrid_store.store_cves_batch(cve_data_list)

    def resume_import(self):
        """从检查点恢复导入"""
        checkpoint = self.load_checkpoint()
        logger.info(f"从检查点恢复导入: 已处理 {checkpoint['processed_count']} 个CVE")
        logger.info(f"成功: {checkpoint['success_count']}, 失败: {checkpoint['failed_count']}")
        logger.info(f"最后处理的文件: {checkpoint['last_processed_file']}")
        logger.info(f"最后处理的CVE: {checkpoint['last_cve_id']}")

    def clear_checkpoint(self):
        """清除检查点"""
        if self.checkpoint_path.exists():
            try:
                self.checkpoint_path.unlink()
                logger.info("检查点已清除")
            except Exception as e:
                logger.error(f"清除检查点失败: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """获取导入统计信息

        Returns:
            统计信息
        """
        checkpoint = self.load_checkpoint()
        cve_count = self.hybrid_store.get_cve_count()
        vector_count = self.hybrid_store.get_vector_count()
        
        return {
            "processed_count": checkpoint['processed_count'],
            "success_count": checkpoint['success_count'],
            "failed_count": checkpoint['failed_count'],
            "cve_count": cve_count,
            "vector_count": vector_count,
            "last_processed_file": checkpoint['last_processed_file'],
            "last_cve_id": checkpoint['last_cve_id'],
            "last_update": checkpoint['timestamp']
        }


def create_nvd_importer(hybrid_store: HybridStore, batch_size: int = 100) -> NVDImporter:
    """创建NVD导入器

    Args:
        hybrid_store: 混合存储实例
        batch_size: 批量处理大小

    Returns:
        NVD导入器实例
    """
    return NVDImporter(hybrid_store, batch_size)