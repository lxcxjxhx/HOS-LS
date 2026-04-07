"""代码嵌入模块

使用 sentence-transformers 或 HuggingFace 模型为代码文本生成嵌入向量。
支持多种嵌入模型，提供单例模式以优化资源使用。
"""

import gc
import os
import threading
import numpy as np
from typing import List, Optional, Any, Dict, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)

# 全局极致内存优化
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True,max_split_size_mb:256"
os.environ["TOKENIZERS_PARALLELISM"] = "false"


@dataclass
class EmbedConfig:
    """嵌入配置"""
    model_name: str = "google/embeddinggemma-300M"
    device: str = "auto"
    cache_dir: Optional[str] = None
    trust_remote_code: bool = True
    batch_size: int = 8
    embedding_batch_size: int = 8
    max_seq_length: int = 512
    chunk_size: int = 512
    stride: int = 128
    max_token_length: int = 1024
    normalize_embeddings: bool = True


# 单例实例
_code_embedder_instance: Optional['CodeEmbedder'] = None
_instance_lock = threading.Lock()


class CodeEmbedder:
    """代码嵌入器

    为代码文本生成嵌入向量。
    """

    def __init__(self, config: Optional[EmbedConfig] = None):
        """初始化代码嵌入器

        Args:
            config: 嵌入配置
        """
        self.config = config or EmbedConfig()
        self._model = None
        self._tokenizer = None
        self._device = self.config.device
        self._initialized = False
        self._init_lock = threading.Lock()

    def _initialize(self):
        """延迟初始化模型"""
        if self._initialized:
            return

        with self._init_lock:
            if self._initialized:
                return

            try:
                logger.info(f"初始化嵌入模型: {self.config.model_name}")
                
                # 尝试导入 PyTorch
                try:
                    import torch
                    TORCH_AVAILABLE = True
                except ImportError:
                    TORCH_AVAILABLE = False
                    logger.warning("PyTorch 不可用，嵌入功能将不可用")

                if TORCH_AVAILABLE:
                    # 自动选择设备
                    if self._device == "auto":
                        if torch.cuda.is_available():
                            self._device = "cuda"
                        else:
                            self._device = "cpu"
                    
                    logger.info(f"使用设备: {self._device}")

                    # 尝试使用 sentence-transformers
                    try:
                        from sentence_transformers import SentenceTransformer
                        self._model = SentenceTransformer(
                            self.config.model_name,
                            device=self._device,
                            cache_folder=self.config.cache_dir,
                            trust_remote_code=self.config.trust_remote_code
                        )
                        
                        # 获取 tokenizer
                        if hasattr(self._model, 'tokenizer'):
                            self._tokenizer = self._model.tokenizer
                        
                        logger.info(f"✅ 嵌入模型初始化成功: {self.config.model_name}")
                    except ImportError:
                        logger.warning("sentence-transformers 不可用，尝试直接使用 HuggingFace 模型")
                        self._initialize_huggingface_model()
                    except Exception as e:
                        logger.warning(f"使用 sentence-transformers 初始化失败: {e}，尝试直接使用 HuggingFace 模型")
                        self._initialize_huggingface_model()
                else:
                    logger.warning("PyTorch 不可用，嵌入功能将不可用")

                self._initialized = True
            except Exception as e:
                logger.error(f"初始化嵌入模型失败: {e}")
                self._model = None
                self._tokenizer = None
                self._initialized = True

    def _initialize_huggingface_model(self):
        """使用 HuggingFace 直接初始化模型"""
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(
                self.config.model_name,
                cache_dir=self.config.cache_dir,
                trust_remote_code=self.config.trust_remote_code
            )
            self._model = AutoModel.from_pretrained(
                self.config.model_name,
                cache_dir=self.config.cache_dir,
                trust_remote_code=self.config.trust_remote_code
            )
            self._model = self._model.to(self._device)
            self._model.eval()
            logger.info(f"✅ 使用 HuggingFace 直接初始化模型成功: {self.config.model_name}")
        except Exception as e:
            logger.error(f"使用 HuggingFace 直接初始化模型失败: {e}")
            self._model = None
            self._tokenizer = None

    def is_available(self) -> bool:
        """检查嵌入器是否可用

        Returns:
            是否可用
        """
        self._initialize()
        return self._model is not None

    def _get_token_length(self, text: str) -> int:
        """获取文本的 token 长度

        Args:
            text: 输入文本

        Returns:
            token 数量
        """
        self._initialize()
        if self._tokenizer is None:
            # 如果没有 tokenizer，回退到字符长度估算
            return len(text) // 4
        
        try:
            return len(self._tokenizer.encode(text, truncation=False))
        except Exception:
            return len(text) // 4

    def _chunk_text(self, text: str) -> List[str]:
        """将长文本切分为多个 chunk

        Args:
            text: 输入文本

        Returns:
            文本 chunk 列表
        """
        if not text:
            return []
        
        # 检查 token 长度
        token_length = self._get_token_length(text)
        
        if token_length <= self.config.max_token_length:
            return [text]
        
        chunks = []
        # 使用滑动窗口切分
        for i in range(0, len(text), self.config.chunk_size - self.config.stride):
            chunk = text[i:i + self.config.chunk_size]
            if chunk:
                chunks.append(chunk)
        
        logger.debug(f"文本切分为 {len(chunks)} 个 chunks")
        return chunks

    def _aggregate_embeddings(self, embeddings: List[np.ndarray]) -> np.ndarray:
        """聚合多个 chunk 的 embedding

        Args:
            embeddings: 多个 chunk 的 embedding 列表

        Returns:
            聚合后的 embedding
        """
        if len(embeddings) == 1:
            return embeddings[0]
        
        # 平均聚合
        return np.mean(embeddings, axis=0)

    def _clear_memory(self):
        """彻底清理内存"""
        try:
            # 强制垃圾回收
            gc.collect()
            
            # 清理 GPU 内存
            try:
                import torch
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                    torch.cuda.ipc_collect()
                    torch.cuda.synchronize()
                    torch.cuda.reset_peak_memory_stats()
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"清理内存失败: {e}")

    def _generate_embeddings_batch(self, texts: List[str]) -> List[np.ndarray]:
        """批量生成嵌入向量

        Args:
            texts: 文本列表

        Returns:
            嵌入向量列表
        """
        self._initialize()
        if self._model is None:
            raise RuntimeError("嵌入模型不可用")

        try:
            import torch
        except ImportError:
            raise RuntimeError("PyTorch 不可用")

        # 强制使用小批量
        real_batch_size = self.config.embedding_batch_size
        
        all_embeddings = []
        
        for i in range(0, len(texts), real_batch_size):
            batch_texts = texts[i:i + real_batch_size]
            
            retry_count = 0
            max_retries = 3
            current_batch_size = real_batch_size
            
            while retry_count < max_retries:
                try:
                    with torch.no_grad():
                        if hasattr(self._model, 'encode'):
                            embeddings = self._model.encode(
                                batch_texts,
                                batch_size=current_batch_size,
                                convert_to_numpy=True,
                                convert_to_tensor=False,
                                normalize_embeddings=self.config.normalize_embeddings
                            )
                        else:
                            # 使用 HuggingFace 模型直接生成
                            embeddings = self._generate_embeddings_huggingface(batch_texts)
                    
                    all_embeddings.extend(embeddings)
                    break
                    
                except RuntimeError as e:
                    if "CUDA out of memory" in str(e) or "out of memory" in str(e):
                        logger.warning(f"OOM错误，批次大小 {current_batch_size} -> {max(1, current_batch_size // 2)}")
                        self._clear_memory()
                        current_batch_size = max(1, current_batch_size // 2)
                        retry_count += 1
                        
                        # 如果批次已经是 1，尝试单条处理
                        if current_batch_size == 1 and retry_count >= max_retries:
                            logger.warning("批量处理失败，尝试单条处理")
                            for text in batch_texts:
                                try:
                                    single_emb = self._model.encode(
                                        [text],
                                        batch_size=1,
                                        convert_to_numpy=True,
                                        convert_to_tensor=False,
                                        normalize_embeddings=self.config.normalize_embeddings
                                    )
                                    all_embeddings.extend(single_emb)
                                except Exception as se:
                                    logger.error(f"单条处理失败: {se}")
                                    raise
                            break
                    else:
                        raise
                except Exception:
                    raise
            
            # 每批次后清理内存
            self._clear_memory()
        
        return all_embeddings

    def _generate_embeddings_huggingface(self, texts: List[str]) -> List[np.ndarray]:
        """使用 HuggingFace 模型直接生成嵌入

        Args:
            texts: 文本列表

        Returns:
            嵌入向量列表
        """
        import torch
        
        embeddings = []
        
        for text in texts:
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=self.config.max_seq_length
            )
            inputs = {k: v.to(self._device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self._model(**inputs)
                embedding = outputs.last_hidden_state.mean(dim=1).squeeze().cpu().numpy()
            
            if self.config.normalize_embeddings:
                norm = np.linalg.norm(embedding)
                if norm > 0:
                    embedding = embedding / norm
            
            embeddings.append(embedding)
        
        return embeddings

    def embed_code(self, code: str) -> List[float]:
        """为代码生成嵌入向量

        Args:
            code: 代码文本

        Returns:
            嵌入向量
        """
        self._initialize()
        if self._model is None:
            raise RuntimeError("嵌入模型不可用")

        try:
            # 先切分文本
            chunks = self._chunk_text(code)
            
            if len(chunks) == 1:
                embeddings = self._generate_embeddings_batch([code])
                return embeddings[0].tolist()
            else:
                # 处理多个 chunks
                chunk_embeddings = self._generate_embeddings_batch(chunks)
                aggregated = self._aggregate_embeddings(chunk_embeddings)
                return aggregated.tolist()
        except Exception as e:
            logger.error(f"生成嵌入失败: {e}")
            raise
        finally:
            self._clear_memory()

    def embed_batch(self, texts: List[str], batch_size: Optional[int] = None) -> List[List[float]]:
        """批量为文本生成嵌入向量

        Args:
            texts: 文本列表
            batch_size: 批量大小（可选，覆盖配置中的值）

        Returns:
            嵌入向量列表
        """
        self._initialize()
        if self._model is None:
            raise RuntimeError("嵌入模型不可用")

        if not texts:
            return []

        try:
            # 处理每个文本，处理长文本切分
            all_chunks = []
            text_indices = []
            
            for idx, text in enumerate(texts):
                chunks = self._chunk_text(text)
                all_chunks.extend(chunks)
                text_indices.extend([idx] * len(chunks))
            
            # 批量生成所有 chunks 的 embedding
            chunk_embeddings = self._generate_embeddings_batch(all_chunks)
            
            # 聚合每个原始文本的 embedding
            final_embeddings: List[Optional[List[np.ndarray]]] = [None] * len(texts)
            
            for idx, chunk_emb in zip(text_indices, chunk_embeddings):
                if final_embeddings[idx] is None:
                    final_embeddings[idx] = []
                final_embeddings[idx].append(chunk_emb)
            
            # 聚合并转换为列表
            result = []
            for embs in final_embeddings:
                if embs is None:
                    result.append([])
                else:
                    aggregated = self._aggregate_embeddings(embs)
                    result.append(aggregated.tolist())
            
            return result
        except Exception as e:
            logger.error(f"批量生成嵌入失败: {e}")
            raise
        finally:
            self._clear_memory()

    def get_embedding_dimension(self) -> int:
        """获取嵌入向量的维度

        Returns:
            嵌入维度
        """
        self._initialize()
        if self._model is None:
            return 256

        try:
            if hasattr(self._model, 'get_sentence_embedding_dimension'):
                return self._model.get_sentence_embedding_dimension()
            
            test_emb = self.embed_code("test")
            return len(test_emb) if test_emb else 256
        except Exception as e:
            logger.warning(f"获取嵌入维度失败: {e}，使用默认值 256")
            return 256

    def clear(self):
        """清理资源"""
        try:
            self._clear_memory()
            self._model = None
            self._tokenizer = None
            self._initialized = False
            gc.collect()
        except Exception as e:
            logger.error(f"清理资源失败: {e}")


def create_embedder(config: Optional[EmbedConfig] = None) -> CodeEmbedder:
    """创建代码嵌入器实例

    Args:
        config: 嵌入配置

    Returns:
        代码嵌入器实例
    """
    return CodeEmbedder(config)


def get_embedder(config: Optional[EmbedConfig] = None) -> CodeEmbedder:
    """获取代码嵌入器单例

    Args:
        config: 嵌入配置（仅在首次创建时使用）

    Returns:
        代码嵌入器单例
    """
    global _code_embedder_instance

    if _code_embedder_instance is None:
        with _instance_lock:
            if _code_embedder_instance is None:
                _code_embedder_instance = create_embedder(config)

    return _code_embedder_instance


def reset_embedder():
    """重置嵌入器单例"""
    global _code_embedder_instance

    with _instance_lock:
        if _code_embedder_instance:
            _code_embedder_instance.clear()
        _code_embedder_instance = None
