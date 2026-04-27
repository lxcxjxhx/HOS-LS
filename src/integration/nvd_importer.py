"""NVD导入模块

实现NVD数据的流式处理、批量embedding和导入功能。
"""

import os
import json
import zipfile
import concurrent.futures
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# 全局极致内存优化
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True,max_split_size_mb:256"
os.environ["TOKENIZERS_PARALLELISM"] = "false"  # 避免tokenizer警告

# 尝试导入ijson进行流式JSON解析
try:
    import ijson
    IJSON_AVAILABLE = True
except ImportError:
    IJSON_AVAILABLE = False

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
        # 批处理参数优化
        self.READ_BATCH = 200
        self.EMBED_BATCH = 32
        self.WRITE_BATCH = 500
        self.processor = NVDProcessor()
        self.import_manager = create_import_manager()
        self.checkpoint_path = Path("./nvd_import_checkpoint.json")
        self.embeddings_cache_dir = Path("./embeddings_cache")
        self.embeddings_cache_dir.mkdir(exist_ok=True)
        # 尝试导入内存监控模块
        try:
            import psutil
            self.psutil_available = True
        except ImportError:
            self.psutil_available = False
        # 尝试导入torch进行GPU内存监控
        try:
            import torch
            self.torch_available = True
        except ImportError:
            self.torch_available = False
        # 尝试导入numpy进行内存映射
        try:
            import numpy as np
            self.numpy_available = True
        except ImportError:
            self.numpy_available = False
        # 内存映射相关
        self.memmap_file = None
        self.memmap_array = None
        self.memmap_idx = 0

    def stream_read_json(self, file_obj) -> Optional[Dict[str, Any]]:
        """流式读取JSON文件

        Args:
            file_obj: 文件对象

        Returns:
            JSON数据或None
        """
        try:
            if IJSON_AVAILABLE:
                # 使用ijson进行流式解析
                parser = ijson.parse(file_obj)
                data = {}
                current_path = []
                stack = [data]
                
                for prefix, event, value in parser:
                    if event == 'start_map':
                        new_obj = {}
                        stack[-1][prefix.split('.')[-1]] = new_obj
                        stack.append(new_obj)
                    elif event == 'end_map':
                        stack.pop()
                    elif event == 'start_array':
                        new_array = []
                        stack[-1][prefix.split('.')[-1]] = new_array
                        stack.append(new_array)
                    elif event == 'end_array':
                        stack.pop()
                    elif event == 'map_key':
                        pass
                    else:
                        # 处理值
                        parts = prefix.split('.')
                        if len(parts) == 1:
                            # 顶层键
                            stack[-1][prefix] = value
                        else:
                            # 嵌套键
                            parent = stack[-1]
                            for part in parts[:-1]:
                                if part not in parent:
                                    parent[part] = {}
                                parent = parent[part]
                            parent[parts[-1]] = value
                return data
            else:
                # 回退到普通JSON解析
                return json.load(file_obj)
        except Exception as e:
            logger.error(f"流式读取JSON失败: {e}")
            return None

    def get_optimal_batch_size(self) -> int:
        """根据系统内存和GPU内存计算最优批量大小

        Returns:
            最优批量大小
        """
        # 从配置中获取批量大小自适应设置
        from src.core.config import get_config
        config = get_config()
        
        # 检查是否启用批量大小自适应
        adaptive_enabled = False
        min_batch_size = 16
        max_batch_size = 256
        
        try:
            batch_config = config.get('batch_processing', {})
            adaptive_config = batch_config.get('adaptive_batch_size', {})
            adaptive_enabled = adaptive_config.get('enabled', False)
            min_batch_size = adaptive_config.get('min_batch_size', 16)
            max_batch_size = adaptive_config.get('max_batch_size', 256)
            logger.info(f"批量大小自适应配置: enabled={adaptive_enabled}, min={min_batch_size}, max={max_batch_size}")
        except Exception as e:
            logger.warning(f"获取批量处理配置失败: {e}")
            adaptive_enabled = False
        
        # 如果未启用自适应，使用固定批量大小
        if not adaptive_enabled:
            logger.info("批量大小自适应已关闭，使用固定批量大小: 256")
            return 256
        
        # 基础批量大小
        base_batch_size = 128
        
        # 检查系统内存
        if self.psutil_available:
            import psutil
            try:
                memory = psutil.virtual_memory()
                available_memory_gb = memory.available / (1024 * 1024 * 1024)
                logger.info(f"🔍 系统可用内存: {available_memory_gb:.2f} GB")
                
                # 根据系统内存调整批量大小
                if available_memory_gb < 4:
                    return max(min_batch_size, 32)  # 内存不足，使用小批量
                elif available_memory_gb < 8:
                    return max(min_batch_size, 64)  # 内存较少，使用中批量
                elif available_memory_gb < 16:
                    return max(min_batch_size, 128)  # 内存充足，使用默认批量
                else:
                    base_batch_size = min(max_batch_size, 256)  # 内存非常充足，使用更大批量
            except Exception as e:
                logger.warning(f"获取系统内存信息失败: {e}")
        
        # 检查GPU内存
        if self.torch_available:
            import torch
            try:
                if torch.cuda.is_available():
                    # 获取GPU内存信息
                    device = torch.device('cuda')
                    total_gpu_memory = torch.cuda.get_device_properties(device).total_memory / (1024 * 1024 * 1024)  # GB
                    allocated_gpu_memory = torch.cuda.memory_allocated(device) / (1024 * 1024 * 1024)  # GB
                    available_gpu_memory = total_gpu_memory - allocated_gpu_memory
                    
                    logger.info(f"🔍 GPU 可用内存: {available_gpu_memory:.2f} GB")
                    
                    # 根据GPU内存调整批量大小
                    if available_gpu_memory < 1:
                        return max(min_batch_size, 32)  # GPU内存不足，使用小批量
                    elif available_gpu_memory < 2:
                        return max(min_batch_size, 64)  # GPU内存较少，使用中批量
                    elif available_gpu_memory < 4:
                        return max(min_batch_size, 128)  # GPU内存充足，使用默认批量
                    else:
                        return min(base_batch_size, max_batch_size)  # GPU内存非常充足，使用更大批量
            except Exception as e:
                logger.warning(f"获取GPU内存信息失败: {e}")
        
        # 无法获取内存信息，使用基础批量大小
        base_batch_size = max(min_batch_size, min(base_batch_size, max_batch_size))
        logger.info(f"使用基础批量大小: {base_batch_size}")
        return base_batch_size

    def init_memmap(self, total_embeddings: int, embedding_dim: int = 256):
        """初始化内存映射文件

        Args:
            total_embeddings: 总嵌入数量
            embedding_dim: 嵌入维度
        """
        if not self.numpy_available:
            logger.warning("numpy不可用，无法使用内存映射文件")
            return
        
        try:
            import numpy as np
            memmap_path = self.embeddings_cache_dir / "embeddings_memmap.npy"
            logger.info(f"初始化内存映射文件: {memmap_path}")
            logger.info(f"总嵌入数量: {total_embeddings}, 维度: {embedding_dim}")
            
            # 创建内存映射文件
            self.memmap_array = np.memmap(
                str(memmap_path),
                dtype='float16',
                mode='w+',
                shape=(total_embeddings, embedding_dim)
            )
            self.memmap_idx = 0
            logger.info("内存映射文件初始化完成")
        except Exception as e:
            logger.error(f"初始化内存映射文件失败: {e}")

    def store_embedding(self, embedding):
        """存储嵌入向量到内存映射文件

        Args:
            embedding: 嵌入向量
        """
        if not self.numpy_available or self.memmap_array is None:
            return False
        
        try:
            import numpy as np
            # 检查内存映射文件是否有足够空间
            if self.memmap_idx >= self.memmap_array.shape[0]:
                logger.warning("内存映射文件空间不足")
                return False
            
            # 存储嵌入向量
            self.memmap_array[self.memmap_idx] = embedding
            self.memmap_idx += 1
            
            # 每1000个嵌入刷新一次
            if self.memmap_idx % 1000 == 0:
                self.memmap_array.flush()
                logger.info(f"已存储 {self.memmap_idx} 个嵌入向量")
            
            return True
        except Exception as e:
            logger.error(f"存储嵌入向量失败: {e}")
            return False

    def close_memmap(self):
        """关闭内存映射文件"""
        if self.memmap_array is not None:
            try:
                self.memmap_array.flush()
                del self.memmap_array
                self.memmap_array = None
                logger.info("内存映射文件已关闭")
            except Exception as e:
                logger.error(f"关闭内存映射文件失败: {e}")

    def cleanup_memory(self, force=False):
        """清理内存，释放不再使用的资源

        Args:
            force: 是否强制清理

        强制垃圾回收，释放GPU内存（如果可用），优化内存映射文件使用
        """
        try:
            # 强制垃圾回收
            import gc
            import psutil
            
            # 获取清理前的内存使用
            process = psutil.Process()
            before_memory = process.memory_info().rss / 1024 / 1024
            
            logger.info(f"开始清理内存... 清理前内存使用: {before_memory:.2f} MB")
            
            # 清理内存映射文件
            if self.memmap_array is not None:
                try:
                    self.memmap_array.flush()
                    del self.memmap_array
                    self.memmap_array = None
                    logger.info("内存映射文件已清理")
                except Exception as e:
                    logger.error(f"清理内存映射文件失败: {e}")
            
            # 显式删除大对象引用
            large_objects = ['processed_texts', 'text_mapping', 'embeddings', 'batch_texts', 'sub_batch_embeddings']
            for obj_name in large_objects:
                if obj_name in locals():
                    try:
                        del locals()[obj_name]
                        logger.debug(f"清理大对象: {obj_name}")
                    except Exception as e:
                        logger.debug(f"清理对象 {obj_name} 失败: {e}")
            
            # 多次垃圾回收以确保释放所有内存
            for _ in range(3):
                gc.collect()
                logger.debug(f"垃圾回收后，已用内存: {gc.get_count()}")
            
            # 释放GPU内存（如果可用）
            if self.torch_available:
                import torch
                try:
                    if torch.cuda.is_available():
                        # 获取清理前的GPU内存使用
                        before_gpu_memory = torch.cuda.memory_allocated() / 1024 / 1024
                        before_gpu_cached = torch.cuda.memory_reserved() / 1024 / 1024
                        
                        # 彻底清理GPU内存
                        torch.cuda.empty_cache()
                        torch.cuda.ipc_collect()  # 添加IPC收集，清理跨进程内存
                        torch.cuda.reset_peak_memory_stats()
                        
                        # 获取清理后的GPU内存使用
                        after_gpu_memory = torch.cuda.memory_allocated() / 1024 / 1024
                        after_gpu_cached = torch.cuda.memory_reserved() / 1024 / 1024
                        
                        logger.info(f"GPU内存清理完成: 分配 {before_gpu_memory:.2f} MB -> {after_gpu_memory:.2f} MB, 缓存 {before_gpu_cached:.2f} MB -> {after_gpu_cached:.2f} MB")
                except Exception as e:
                    logger.error(f"清理GPU内存失败: {e}")
            
            # 再次强制垃圾回收
            gc.collect()
            
            # 获取清理后的内存使用
            after_memory = process.memory_info().rss / 1024 / 1024
            logger.info(f"内存清理完成，清理后内存使用: {after_memory:.2f} MB (释放: {before_memory - after_memory:.2f} MB)")
        except Exception as e:
            logger.error(f"清理内存失败: {e}")

    def monitor_memory_usage(self):
        """监控内存使用情况"""
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_usage = memory_info.rss / 1024 / 1024  # MB
            
            logger.info(f"当前内存使用: {memory_usage:.2f} MB")
            
            # 监控GPU内存（如果可用）
            if self.torch_available:
                import torch
                try:
                    if torch.cuda.is_available():
                        allocated = torch.cuda.memory_allocated() / 1024 / 1024  # MB
                        reserved = torch.cuda.memory_reserved() / 1024 / 1024  # MB
                        total = torch.cuda.get_device_properties(0).total_memory / 1024 / 1024  # MB
                        
                        logger.info(f"GPU内存使用: 分配 {allocated:.2f} MB, 缓存 {reserved:.2f} MB, 总容量 {total:.2f} MB")
                except Exception as e:
                    logger.error(f"监控GPU内存失败: {e}")
        except Exception as e:
            logger.error(f"监控内存使用失败: {e}")

    def get_batch_size_by_text_length(self, texts: List[str]) -> int:
        """根据文本长度获取合适的批次大小

        Args:
            texts: 文本列表

        Returns:
            合适的批次大小
        """
        if not texts:
            return self.batch_size
        
        # 计算文本长度统计
        text_lengths = [len(text) for text in texts]
        max_length = max(text_lengths)
        avg_length = sum(text_lengths) / len(text_lengths)
        
        logger.info(f"文本长度统计: 平均={avg_length:.1f}, 最大={max_length}, 最小={min(text_lengths)}")
        
        # 根据文本长度调整批次大小（根据fix_1.md建议）
        if avg_length > 3000:
            # 超长文本，使用最小批次
            logger.info("检测到超长文本，使用最小批次大小")
            return 4
        elif avg_length > 2000:
            # 长文本，使用小批次
            logger.info("检测到长文本，使用小批次大小")
            return 8
        elif avg_length > 1000:
            # 中等长度文本，使用中批次
            logger.info("检测到中等长度文本，使用中批次大小")
            return 16
        elif avg_length > 500:
            # 较短文本，使用较大批次
            logger.info("检测到较短文本，使用较大批次大小")
            return 32
        else:
            # 短文本，使用最大批次
            logger.info("检测到短文本，使用最大批次大小")
            return 64

    def optimize_embedding_generation(self, texts: List[str]) -> List[List[float]]:
        """优化嵌入生成过程，减少显存使用并处理NaN值

        Args:
            texts: 文本列表

        Returns:
            嵌入向量列表
        """
        try:
            if not texts:
                logger.info("没有文本需要处理")
                return []
            
            # 对文本进行切分，避免超长文本
            processed_texts = []
            text_mapping = []  # 记录原始文本与切分后文本的映射
            
            for text in texts:
                try:
                    # 对每个文本进行切分
                    text_chunks = self.processor.split_text_for_embedding(text)
                    processed_texts.extend(text_chunks)
                    text_mapping.append(len(text_chunks))
                except Exception as e:
                    logger.error(f"文本切分失败: {e}")
                    # 使用原始文本作为备选
                    processed_texts.append(text)
                    text_mapping.append(1)
            
            logger.info(f"文本切分完成，原始文本数: {len(texts)}, 切分后文本数: {len(processed_texts)}")
            
            if not processed_texts:
                logger.warning("没有可处理的文本")
                return []
            
            # 分批处理文本
            embeddings = []
            total_texts = len(processed_texts)
            
            # 先计算合适的批次大小
            initial_batch_size = self.get_batch_size_by_text_length(processed_texts)
            logger.info(f"初始嵌入批量大小: {initial_batch_size}")
            
            for i in range(0, total_texts, initial_batch_size):
                batch_texts = processed_texts[i:i + initial_batch_size]
                logger.info(f"处理嵌入批次 {i//initial_batch_size + 1}/{(total_texts + initial_batch_size - 1)//initial_batch_size}")
                
                # 再次根据当前批次的文本长度调整批次大小
                batch_size = self.get_batch_size_by_text_length(batch_texts)
                logger.info(f"使用批次大小: {batch_size}")
                
                # 生成嵌入，添加OOM错误处理
                retry_count = 0
                max_retries = 3
                while retry_count < max_retries:
                    try:
                        # 生成嵌入，确保使用正确的批次大小
                        sub_batch_embeddings = self.hybrid_store.generate_embeddings(batch_texts, batch_size=batch_size)
                        
                        if not sub_batch_embeddings:
                            logger.warning(f"生成的嵌入为空，批次大小: {batch_size}")
                            # 减小批次大小并重试
                            batch_size = max(1, batch_size // 2)
                            logger.info(f"减小批次大小到 {batch_size} 并重试")
                            retry_count += 1
                            if retry_count >= max_retries:
                                logger.error("达到最大重试次数，跳过此批次")
                                break
                            continue
                        
                        # 检测和处理NaN值
                        valid_embeddings = []
                        for j, embedding in enumerate(sub_batch_embeddings):
                            if self._is_valid_embedding(embedding):
                                valid_embeddings.append(embedding)
                            else:
                                logger.warning(f"检测到无效嵌入向量（包含NaN或无穷值），索引: {i + j}")
                                # 尝试重新生成单个嵌入
                                try:
                                    single_embedding = self.hybrid_store.generate_embeddings([batch_texts[j]], batch_size=1)
                                    if single_embedding and self._is_valid_embedding(single_embedding[0]):
                                        valid_embeddings.append(single_embedding[0])
                                        logger.info(f"重新生成嵌入成功，索引: {i + j}")
                                    else:
                                        # 使用零向量作为 fallback
                                        embedding_dim = len(embedding) if embedding else 256
                                        valid_embeddings.append([0.0] * embedding_dim)
                                        logger.info(f"使用零向量作为 fallback，索引: {i + j}")
                                except Exception as e:
                                    # 无法重新生成，使用零向量
                                    embedding_dim = len(embedding) if embedding else 256
                                    valid_embeddings.append([0.0] * embedding_dim)
                                    logger.error(f"重新生成嵌入失败: {e}，使用零向量，索引: {i + j}")
                        
                        embeddings.extend(valid_embeddings)
                        break
                    except Exception as e:
                        # 捕获OOM错误
                        if "CUDA out of memory" in str(e) or "out of memory" in str(e):
                            logger.warning(f"OOM错误: {e}")
                            # 清理内存
                            self.cleanup_memory(force=True)
                            # 减小批次大小并重试
                            batch_size = max(1, batch_size // 2)
                            logger.info(f"减小批次大小到 {batch_size} 并重试")
                            retry_count += 1
                            if retry_count >= max_retries:
                                logger.error("达到最大重试次数，跳过此批次")
                                break
                        else:
                            # 其他错误，记录详细信息
                            logger.error(f"生成嵌入失败: {e}")
                            # 尝试使用更小的批次大小
                            batch_size = max(1, batch_size // 2)
                            logger.info(f"减小批次大小到 {batch_size} 并重试")
                            retry_count += 1
                            if retry_count >= max_retries:
                                logger.error("达到最大重试次数，跳过此批次")
                                break
                
                # 清理内存
                self.cleanup_memory()
                
                # 释放批次文本内存
                del batch_texts
            
            # 合并切分后的嵌入（如果需要）
            # 这里可以根据需要实现嵌入合并逻辑
            
            logger.info(f"嵌入生成完成，共生成 {len(embeddings)} 个嵌入向量")
            return embeddings
        except Exception as e:
            logger.error(f"优化嵌入生成失败: {e}")
            import traceback
            logger.error(f"错误堆栈: {traceback.format_exc()}")
            # 清理内存
            self.cleanup_memory()
            return []
    
    def _is_valid_embedding(self, embedding: List[float]) -> bool:
        """检查嵌入向量是否有效（不包含NaN或无穷值）

        Args:
            embedding: 嵌入向量

        Returns:
            是否有效
        """
        if not embedding:
            return False
        
        try:
            import numpy as np
            embedding_array = np.array(embedding)
            return not (np.isnan(embedding_array).any() or np.isinf(embedding_array).any())
        except Exception as e:
            logger.error(f"检查嵌入向量有效性失败: {e}")
            # 回退到基本检查
            for value in embedding:
                if value != value:  # NaN
                    return False
                if abs(value) == float('inf'):  # 无穷值
                    return False
            return True

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
                            data = self.stream_read_json(f)
                            if not data:
                                logger.error(f"无法读取文件 {member.filename}")
                                continue
                            
                            # 检查是否是CVE集合
                            if 'CVE_Items' in data:
                                cve_items = data.get('CVE_Items', [])
                                logger.info(f"文件包含 {len(cve_items)} 个CVE")
                                
                                # 动态调整批量大小
                                optimal_batch_size = self.get_optimal_batch_size()
                                logger.info(f"使用最优批量大小: {optimal_batch_size}")
                                # 监控内存使用
                                self.monitor_memory_usage()
                                
                                # 使用多进程处理CVE
                                processed_cves = self.process_with_workers(cve_items)
                                logger.info(f"多进程处理完成，成功处理 {len(processed_cves)} 个CVE")
                                
                                # 批量存储处理后的CVE
                                write_batch = self.WRITE_BATCH
                                for i in range(0, len(processed_cves), write_batch):
                                    batch = processed_cves[i:i + write_batch]
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
                                    
                                    # 清理内存
                                    self.cleanup_memory()
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
                        data = self.stream_read_json(f)
                        if not data:
                            logger.error(f"无法读取文件 {json_file}")
                            continue
                        
                        # 检查是否是CVE集合
                        if 'CVE_Items' in data:
                            cve_items = data.get('CVE_Items', [])
                            logger.info(f"文件包含 {len(cve_items)} 个CVE")
                            
                            # 动态调整批量大小
                            optimal_batch_size = self.get_optimal_batch_size()
                            logger.info(f"使用最优批量大小: {optimal_batch_size}")
                            
                            # 使用多进程处理CVE
                            processed_cves = self.process_with_workers(cve_items)
                            logger.info(f"多进程处理完成，成功处理 {len(processed_cves)} 个CVE")
                            
                            # 批量存储处理后的CVE
                            write_batch = self.WRITE_BATCH
                            for i in range(0, len(processed_cves), write_batch):
                                batch = processed_cves[i:i + write_batch]
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
                                
                                # 清理内存
                                self.cleanup_memory()
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

    def process_cve(self, item) -> Optional[Tuple[CVEStructuredData, List[CVEChunk]]]:
        """处理单个CVE数据

        Args:
            item: CVE数据项

        Returns:
            处理后的CVE数据或None
        """
        try:
            result = self.processor.parse_nvd(item)
            if result:
                cve_id = result[0].cve_id
                if not self.import_manager.is_cve_processed(cve_id):
                    return result
        except Exception as e:
            logger.error(f"处理CVE失败: {e}")
        return None

    def process_with_workers(self, cve_items: List[Dict[str, Any]]) -> List[Tuple[CVEStructuredData, List[CVEChunk]]]:
        """使用多进程处理CVE数据

        Args:
            cve_items: CVE数据项列表

        Returns:
            处理后的CVE数据列表
        """
        results = []
        
        # 计算合适的worker数量
        import os
        max_workers = min(os.cpu_count(), 4)  # 最多4个worker
        logger.info(f"使用 {max_workers} 个进程处理CVE数据")
        
        # 分批处理
        batch_size = self.READ_BATCH
        for i in range(0, len(cve_items), batch_size):
            batch = cve_items[i:i + batch_size]
            logger.info(f"处理批次 {i//batch_size + 1}/{(len(cve_items) + batch_size - 1)//batch_size}")
            
            # 使用进程池并行处理
            with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for item in batch:
                    future = executor.submit(self.process_cve, item)
                    futures.append(future)
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
            
            # 每处理完一个批次清理内存
            self.cleanup_memory()
        
        return results

    def process_cve_batch(self, cve_data_list: List[Tuple[CVEStructuredData, List[CVEChunk]]]) -> int:
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