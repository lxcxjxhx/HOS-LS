"""代码嵌入生成器模块

使用预训练模型生成代码嵌入，支持语义搜索和相似性分析。
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from enum import Enum

try:
    from sentence_transformers import SentenceTransformer

    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


try:
    import torch

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class ModelType(Enum):
    """模型类型"""

    ALL_MINILM_L6_V2 = "all-MiniLM-L6-v2"
    ALL_MPNET_BASE_V2 = "all-mpnet-base-v2"
    CODE_BERT_BASE = "microsoft/codebert-base"
    ROBERTA_BASE = "roberta-base"
    BGE_BASE = "BAAI/bge-base-en-v1.5"
    BGE_SMALL = "BAAI/bge-small-en-v1.5"
    E5_BASE = "intfloat/e5-base-v2"
    CUSTOM = "custom"


@dataclass
class EmbedConfig:
    """嵌入配置"""

    model_name: str = "all-MiniLM-L6-v2"
    batch_size: int = 64
    max_length: int = 512
    use_cache: bool = True
    cache_dir: Optional[str] = None
    device: str = "auto"
    use_blockify: bool = True


class CodeEmbedder:
    """代码嵌入生成器

    使用预训练模型生成代码嵌入。
    """

    def __init__(self, config: Optional[EmbedConfig] = None):
        """初始化代码嵌入生成器

        Args:
            config: 嵌入配置
        """
        self.config = config or EmbedConfig()
        self._model: Optional[Any] = None
        self._cache: Dict[str, List[float]] = {}
        self._block_cache: Dict[str, str] = {}
        self._initialized = False

        if SENTENCE_TRANSFORMERS_AVAILABLE:
            self._initialize_model()

    def _initialize_model(self) -> None:
        """初始化模型"""
        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            return

        try:
            model_kwargs = {}
            if self.config.cache_dir:
                model_kwargs["cache_folder"] = self.config.cache_dir

            # 自动检测 GPU
            if self.config.device == "auto":
                if TORCH_AVAILABLE and torch.cuda.is_available():
                    device = "cuda"
                    print(f"✅ Using GPU: {torch.cuda.get_device_name(0)}")
                else:
                    device = "cpu"
                    print("ℹ️ Using CPU (GPU not available)")
            else:
                device = self.config.device

            model_kwargs["device"] = device

            self._model = SentenceTransformer(
                self.config.model_name,
                **model_kwargs
            )

            self._initialized = True
        except Exception as e:
            print(f"❌ Model initialization failed: {e}")
            self._initialized = False

    def embed_code(self, code: str) -> List[float]:
        """生成代码嵌入

        Args:
            code: 代码

        Returns:
            嵌入向量
        """
        if self.config.use_cache:
            cache_key = self._generate_cache_key(code)
            if cache_key in self._cache:
                return self._cache[cache_key]

        embedding = self._generate_embedding(code)

        if self.config.use_cache:
            cache_key = self._generate_cache_key(code)
            self._cache[cache_key] = embedding

        return embedding

    def embed_batch(self, codes: List[str]) -> List[List[float]]:
        """批量生成嵌入

        Args:
            codes: 代码列表

        Returns:
            嵌入向量列表
        """
        if not codes:
            return []

        embeddings: List[List[float]] = []
        uncached_codes: List[str] = []
        uncached_indices: List[int] = []

        for i, code in enumerate(codes):
            if self.config.use_cache:
                cache_key = self._generate_cache_key(code)
                if cache_key in self._cache:
                    embeddings.append(self._cache[cache_key])
                    continue

            uncached_codes.append(code)
            uncached_indices.append(i)

        if uncached_codes:
            batch_embeddings = self._generate_embeddings_batch(uncached_codes)

            for i, (idx, embedding) in enumerate(zip(uncached_indices, batch_embeddings)):
                embeddings.insert(idx, embedding)

                if self.config.use_cache:
                    cache_key = self._generate_cache_key(uncached_codes[i])
                    self._cache[cache_key] = embedding

        return embeddings

    def get_embedding_dimension(self) -> int:
        """获取嵌入维度

        Returns:
            嵌入维度
        """
        if not self._initialized:
            return 384  # 默认维度

        try:
            sample_embedding = self.embed_code('def hello():\n    pass')
            return len(sample_embedding)
        except Exception:
            return 384

    def clear_cache(self) -> None:
        """清除缓存"""
        self._cache.clear()
        self._block_cache.clear()

    def save_cache(self, path: Union[str, Path]) -> bool:
        """保存缓存

        Args:
            path: 缓存文件路径

        Returns:
            是否成功
        """
        try:
            cache_data = {
                "cache": self._cache,
                "metadata": {
                    "model": self.config.model_name,
                    "saved_at": datetime.now().isoformat(),
                },
            }

            with open(path, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)

            return True
        except Exception:
            return False

    def load_cache(self, path: Union[str, Path]) -> bool:
        """加载缓存

        Args:
            path: 缓存文件路径

        Returns:
            是否成功
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)

            self._cache = cache_data.get("cache", {})
            return True
        except Exception:
            return False

    def is_available(self) -> bool:
        """检查是否可用

        Returns:
            是否可用
        """
        return self._initialized and SENTENCE_TRANSFORMERS_AVAILABLE

    def _generate_embedding(self, code: str) -> List[float]:
        """生成单个嵌入

        Args:
            code: 代码

        Returns:
            嵌入向量
        """
        if not self._initialized:
            return self._fallback_embedding(code)

        try:
            # 使用Blockify压缩
            compressed_code = self._blockify(code)
            embedding = self._model.encode(
                compressed_code,
                batch_size=self.config.batch_size,
                max_length=self.config.max_length,
                show_progress_bar=False,
            )

            if NUMPY_AVAILABLE and isinstance(embedding, np.ndarray):
                return embedding.tolist()
            elif isinstance(embedding, list):
                return embedding
            else:
                return self._fallback_embedding(code)

        except Exception:
            return self._fallback_embedding(code)

    def _generate_embeddings_batch(self, codes: List[str]) -> List[List[float]]:
        """批量生成嵌入

        Args:
            codes: 代码列表

        Returns:
            嵌入向量列表
        """
        if not self._initialized:
            return [self._fallback_embedding(code) for code in codes]

        try:
            # 使用Blockify压缩
            compressed_codes = [self._blockify(code) for code in codes]
            
            # 优化批处理大小以充分利用 GPU
            batch_size = min(self.config.batch_size, 128)  # 增加批处理大小以提高 GPU 利用率
            
            embeddings = self._model.encode(
                compressed_codes,
                batch_size=batch_size,
                max_length=self.config.max_length,
                show_progress_bar=False,
                convert_to_tensor=TORCH_AVAILABLE,  # 使用张量输出以提高性能
            )

            if TORCH_AVAILABLE and isinstance(embeddings, torch.Tensor):
                # 确保在 CPU 上转换为 numpy 数组
                embeddings = embeddings.cpu().numpy()

            if NUMPY_AVAILABLE and isinstance(embeddings, np.ndarray):
                return embeddings.tolist()
            elif isinstance(embeddings, list):
                return embeddings
            else:
                return [self._fallback_embedding(code) for code in codes]

        except Exception as e:
            print(f"❌ Batch embedding failed: {e}")
            return [self._fallback_embedding(code) for code in codes]

    def _fallback_embedding(self, code: str) -> List[float]:
        """降级嵌入方案

        Args:
            code: 代码

        Returns:
            嵌入向量
        """
        hash_value = hashlib.sha256(code.encode()).hexdigest()
        embedding = []

        for i in range(0, 384, 2):
            if i < len(hash_value):
                embedding.append(int(hash_value[i:i+2], 16) / 255.0)
            else:
                embedding.append(0.0)

        return embedding

    def _blockify(self, text: str) -> str:
        """Blockify压缩：去重和压缩文本

        Args:
            text: 原始文本

        Returns:
            压缩后的文本
        """
        if not self.config.use_blockify:
            return text

        # 生成缓存键
        block_key = hashlib.sha256(text.encode()).hexdigest()
        if block_key in self._block_cache:
            return self._block_cache[block_key]

        # 去重和压缩逻辑
        lines = text.strip().split('\n')
        seen_lines = set()
        unique_lines = []

        for line in lines:
            line = line.strip()
            if line and line not in seen_lines:
                seen_lines.add(line)
                unique_lines.append(line)

        # 压缩连续的空行
        compressed_lines = []
        prev_empty = False
        for line in unique_lines:
            if line.strip():
                compressed_lines.append(line)
                prev_empty = False
            elif not prev_empty:
                compressed_lines.append('')
                prev_empty = True

        compressed_text = '\n'.join(compressed_lines)
        self._block_cache[block_key] = compressed_text
        return compressed_text

    def _generate_cache_key(self, code: str) -> str:
        """生成缓存键

        Args:
            code: 代码

        Returns:
            缓存键
        """
        content = f"{self.config.model_name}:{code}"
        return hashlib.sha256(content.encode()).hexdigest()


class InMemoryEmbedder:
    """内存嵌入器

    不依赖 sentence-transformers 的简单嵌入实现。
    """

    def __init__(self, config: Optional[EmbedConfig] = None):
        """初始化内存嵌入器

        Args:
            config: 嵌入配置
        """
        self.config = config or EmbedConfig()
        self._cache: Dict[str, List[float]] = {}

    def embed_code(self, code: str) -> List[float]:
        """生成代码嵌入

        Args:
            code: 代码

        Returns:
            嵌入向量
        """
        if self.config.use_cache:
            cache_key = self._generate_cache_key(code)
            if cache_key in self._cache:
                return self._cache[cache_key]

        embedding = self._generate_embedding(code)

        if self.config.use_cache:
            cache_key = self._generate_cache_key(code)
            self._cache[cache_key] = embedding

        return embedding

    def embed_batch(self, codes: List[str]) -> List[List[float]]:
        """批量生成嵌入

        Args:
            codes: 代码列表

        Returns:
            嵌入向量列表
        """
        return [self.embed_code(code) for code in codes]

    def get_embedding_dimension(self) -> int:
        """获取嵌入维度

        Returns:
            嵌入维度
        """
        return 384

    def clear_cache(self) -> None:
        """清除缓存"""
        self._cache.clear()
        self._block_cache.clear()

    def is_available(self) -> bool:
        """检查是否可用

        Returns:
            是否可用
        """
        return True

    def _generate_embedding(self, code: str) -> List[float]:
        """生成嵌入

        Args:
            code: 代码

        Returns:
            嵌入向量
        """
        code_lower = code.lower()
        features = {
            "length": len(code) / 1000.0,
            "lines": code.count("\n") / 100.0,
            "keywords": sum(1 for kw in ["def", "class", "import", "from", "if", "else", "for", "while"] if kw in code_lower),
            "functions": code_lower.count("def ") / 10.0,
            "classes": code_lower.count("class ") / 5.0,
            "imports": code_lower.count("import ") / 5.0,
            "comments": code_lower.count("#") / 10.0,
            "strings": code_lower.count('"') / 20.0,
            "numbers": len([c for c in code if c.isdigit()]) / 50.0,
            "symbols": len([c for c in code if not c.isalnum() and c not in ' \t\n\r']) / 100.0,
        }

        embedding = []
        for i in range(384):
            feature_key = list(features.keys())[i % len(features)]
            embedding.append(features[feature_key] % 1.0)

        return embedding

    def _generate_cache_key(self, code: str) -> str:
        """生成缓存键

        Args:
            code: 代码

        Returns:
            缓存键
        """
        content = f"in_memory:{code}"
        return hashlib.sha256(content.encode()).hexdigest()


def create_embedder(
    config: Optional[EmbedConfig] = None,
    prefer_memory: bool = False,
) -> Union[CodeEmbedder, InMemoryEmbedder]:
    """创建代码嵌入生成器

    Args:
        config: 嵌入配置
        prefer_memory: 是否优先使用内存嵌入器

    Returns:
        代码嵌入生成器实例
    """
    if prefer_memory or not SENTENCE_TRANSFORMERS_AVAILABLE:
        return InMemoryEmbedder(config)

    return CodeEmbedder(config)
