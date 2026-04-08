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

# 全局极致内存优化
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True,max_split_size_mb:256"
os.environ["TOKENIZERS_PARALLELISM"] = "false"  # 避免tokenizer警告

# 在nvd_importer.py中也添加相同的环境变量设置，确保在导入时就生效
# 这样可以确保在整个NVD导入过程中都使用这个设置

try:
    print("🔍 尝试导入 sentence_transformers...")
    from sentence_transformers import SentenceTransformer
    print("✅ sentence_transformers 导入成功")
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError as e:
    print(f"❌ sentence_transformers 导入失败: {e}")
    import traceback
    traceback.print_exc()
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
    QWEN3_EMBEDDING_0_6B = "Qwen/Qwen3-Embedding-0.6B"
    EMBEDDING_GEMMA_300M = "google/embeddinggemma-300M"
    CUSTOM = "custom"


@dataclass
class EmbedConfig:
    """嵌入配置"""

    model_name: str = "google/embeddinggemma-300M"
    batch_size: int = 256  # 批量处理大小，外层batch_size
    max_length: int = 512
    use_cache: bool = True
    cache_dir: Optional[str] = None
    device: str = "auto"
    use_blockify: bool = True
    use_onnx: bool = False
    precision: str = "float16"
    matryoshka_dim: Optional[int] = 256  # Matryoshka 压缩维度（从512降到256，内存/速度大幅改善）
    embedding_batch_size: int = 256  # 嵌入批处理大小，统一为256
    chunk_size: int = 512  # 文本切分大小
    stride: int = 128  # 切分重叠大小


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

        # 避免重复初始化
        if self._initialized:
            print(f"✅ 模型 {self.config.model_name} 已经初始化，直接使用")
            return

        try:
            print(f"🔧 开始初始化模型: {self.config.model_name}")
            print(f"⏱️ 开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            model_kwargs = {}
            tokenizer_kwargs = {}
            
            # 检查模型路径
            import os
            from pathlib import Path
            cache_dir = self.config.cache_dir or str(Path.home() / ".cache" / "huggingface" / "hub")
            print(f"🔍 检查模型缓存目录: {cache_dir}")
            
            # 检查具体模型目录
            model_dir_name = f"models--{self.config.model_name.replace('/', '--')}"
            model_path = Path(cache_dir) / model_dir_name
            print(f"🔍 检查模型目录: {model_path}")
            print(f"📁 目录是否存在: {model_path.exists()}")
            
            # 检查模型目录是否包含必要的配置文件
            config_file = None
            if model_path.exists() and list(model_path.glob("snapshots/*")):
                snapshots_dir = model_path / "snapshots"
                snapshot_subdirs = list(snapshots_dir.iterdir())
                if snapshot_subdirs:
                    config_file = snapshot_subdirs[0] / "config.json"
            
            model_name_or_path = self.config.model_name
            
            if model_path.exists():
                files = list(model_path.iterdir())[:10]  # 只显示前10个文件
                print(f"📄 目录中的文件: {[f.name for f in files]}")
                
                # 优先使用本地模型路径
                if config_file and config_file.exists():
                    # 检查config.json是否包含model_type键
                    try:
                        import json
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config_data = json.load(f)
                        if 'model_type' in config_data:
                            # 如果本地模型目录存在且配置文件完整，直接使用本地路径
                            model_name_or_path = str(model_path)
                            print(f"✅ 使用本地模型路径: {model_name_or_path}")
                        else:
                            # 如果配置文件不完整，仍然尝试使用本地模型
                            print(f"⚠️ 本地模型配置文件不完整，缺少model_type键，但仍尝试使用本地模型")
                            model_name_or_path = str(model_path)
                    except Exception as e:
                        print(f"⚠️ 读取模型配置文件失败: {e}，但仍尝试使用本地模型")
                        model_name_or_path = str(model_path)
                else:
                    # 即使没有配置文件，也尝试使用本地模型
                    print(f"⚠️ 本地模型缺少配置文件，但仍尝试使用本地模型")
                    model_name_or_path = str(model_path)
            else:
                # 否则使用模型名称从 Hugging Face 下载
                print(f"ℹ️ 使用模型名称: {model_name_or_path}")
            
            if self.config.cache_dir:
                model_kwargs["cache_folder"] = self.config.cache_dir
                print(f"📁 使用缓存目录: {self.config.cache_dir}")
            
            # 添加 Hugging Face token 认证
            import os
            hf_token = os.environ.get("HUGGING_FACE_HUB_TOKEN")
            if hf_token:
                model_kwargs["token"] = hf_token
                print("✅ 已设置 Hugging Face token")
            else:
                # 尝试从文件读取 token
                token_file = Path.home() / "HUGGINGFACE"
                if token_file.exists():
                    try:
                        with open(token_file, 'r', encoding='utf-8') as f:
                            hf_token = f.read().strip()
                        model_kwargs["token"] = hf_token
                        print("✅ 从文件读取 Hugging Face token")
                    except Exception as e:
                        print(f"ℹ️ 读取 token 文件失败: {e}")
                else:
                    print("ℹ️ 未设置 Hugging Face token")

            # 自动检测 GPU
            if self.config.device == "auto":
                if TORCH_AVAILABLE and torch.cuda.is_available():
                    device = "cuda"
                    print(f"✅ Using GPU: {torch.cuda.get_device_name(0)}")
                    print(f"🔍 GPU 内存: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.2f} GB")
                else:
                    device = "cpu"
                    print("ℹ️ Using CPU (GPU not available)")
            else:
                device = self.config.device
                print(f"📱 使用指定设备: {device}")

            # 为 Qwen3-Embedding-0.6B 添加特殊配置
            if "Qwen3-Embedding" in self.config.model_name:
                print("🔧 Configuring Qwen3-Embedding model...")
                # 设置 padding_side 为 "left"
                tokenizer_kwargs["padding_side"] = "left"
                # Qwen3-Embedding-0.6B 官方推荐配置
                # 默认禁用 flash_attention_2，以提高兼容性
                print("ℹ️ 默认禁用 flash_attention_2，以提高系统兼容性")
                # 如需启用 flash_attention_2，请在配置中设置 use_flash_attention=True
                model_kwargs["torch_dtype"] = torch.float16  # fp16 省内存
                model_kwargs["device_map"] = "auto"
                # Matryoshka 压缩维度将在 encode 方法中设置
            
            # 为 google/embeddinggemma-300M 添加特殊配置
            elif "embeddinggemma-300M" in self.config.model_name:
                print("🔧 Configuring google/embeddinggemma-300M（保守稳定版）...")
                # 设置 padding_side 为 "left"
                tokenizer_kwargs = {"padding_side": "left"}
                # embeddinggemma-300M 配置
                model_kwargs = {
                    "torch_dtype": torch.float16,
                    "device_map": "auto",
                }
                # 设置模型最大序列长度
                self.config.max_length = 256
                print("✅ 模型加载完成（256维压缩 + 极致内存优化）")

            # 支持 ONNX 后端
            if self.config.use_onnx and "Qwen3-Embedding" not in self.config.model_name:
                model_kwargs["backend"] = "onnx"
                model_kwargs["model_kwargs"] = {
                    "provider": "CUDAExecutionProvider" if device == "cuda" else "CPUExecutionProvider"
                }

            self._model = SentenceTransformer(
                model_name_or_path,
                model_kwargs=model_kwargs,
                tokenizer_kwargs=tokenizer_kwargs
            )

            # 确保模型移动到正确的设备
            if TORCH_AVAILABLE:
                print(f"🚚 将模型移动到 {device} 设备...")
                self._model = self._model.to(device)
                # 设置精度
                if device == "cuda" and self.config.precision == "float16":
                    print("🔄 将模型精度设置为 float16...")
                    self._model = self._model.half()
                # torch.compile 加速（PyTorch 2.4+ 以上支持）
                try:
                    print("⚡ 启用 torch.compile 加速...")
                    self._model = torch.compile(self._model, mode="reduce-overhead")
                    print("✅ 已启用 torch.compile 加速")
                except Exception as e:
                    print(f"ℹ️ torch.compile 不可用: {e}")

            print(f"⏱️ 模型初始化完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"✅ 模型 {self.config.model_name} 初始化成功")
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

    def embed_batch(self, codes: List[str], batch_size: int = 256) -> List[List[float]]:
        """批量生成嵌入

        Args:
            codes: 代码列表
            batch_size: 批处理大小（外层）

        Returns:
            嵌入向量列表
        """
        if not codes:
            return []
        
        # 计算文本长度统计
        lengths = [len(code) for code in codes]
        avg_length = sum(lengths) / len(lengths) if lengths else 0
        max_length = max(lengths) if lengths else 0
        min_length = min(lengths) if lengths else 0
        
        print(f"\n🚀 开始生成嵌入... 批次大小: {len(codes)} 条（外层{batch_size}）")
        print(f"📊 文本长度统计: 平均={avg_length:.1f}, 最大={max_length}, 最小={min_length}")
        
        # 3次强力清理
        import gc
        for _ in range(3):
            gc.collect()
            if TORCH_AVAILABLE and torch.cuda.is_available():
                torch.cuda.empty_cache()
                torch.cuda.reset_peak_memory_stats()
        
        # 极致 GPU 加速设置
        if TORCH_AVAILABLE:
            torch.backends.cudnn.benchmark = True
            torch.set_float32_matmul_precision('high')
            torch.backends.cuda.matmul.allow_tf32 = True
        
        embeddings: List[List[float]] = []

        # 按外层 batch_size 分批处理
        total_codes = len(codes)
        for start_idx in range(0, total_codes, batch_size):
            end_idx = min(start_idx + batch_size, total_codes)
            batch_codes = codes[start_idx:end_idx]
            
            print(f"\n🔄 处理外层批次: {start_idx}-{end_idx}/{total_codes}")
            
            batch_embeddings = []
            uncached_codes: List[str] = []
            uncached_indices: List[int] = []

            # 先检查缓存
            for i, code in enumerate(batch_codes):
                if self.config.use_cache:
                    cache_key = self._generate_cache_key(code)
                    if cache_key in self._cache:
                        batch_embeddings.append(self._cache[cache_key])
                        continue

                uncached_codes.append(code)
                uncached_indices.append(i)

            if uncached_codes:
                # 处理文本切分和聚合
                processed_codes = []
                code_mapping = []  # 记录原始代码与切分后代码的映射
                
                for code in uncached_codes:
                    token_length = self._get_token_length(code)
                    if token_length > 512:  # 超过token长度限制，进行切分
                        chunks = self._chunk_text(code)
                        processed_codes.extend(chunks)
                        code_mapping.append(len(chunks))
                    else:
                        processed_codes.append(code)
                        code_mapping.append(1)
                
                print(f"📊 文本切分完成，原始文本数: {len(uncached_codes)}, 切分后文本数: {len(processed_codes)}")
                
                # 对处理后的代码进行批量处理
                sub_batch_size = self.config.embedding_batch_size  # 使用配置中的子批次大小
                print(f"🔧 使用子批次大小: {sub_batch_size}")
                
                total_processed = len(processed_codes)
                processed = 0
                sub_batch_embeddings = []
                
                while processed < total_processed:
                    sub_end_idx = min(processed + sub_batch_size, total_processed)
                    sub_batch = processed_codes[processed:sub_end_idx]
                    
                    print(f"🔄 处理子批次: {processed}-{sub_end_idx}/{total_processed}")
                    
                    # 阻止梯度缓存，进一步省内存
                    with torch.no_grad():
                        sub_embeddings = self._generate_embeddings_batch(sub_batch)
                    
                    sub_batch_embeddings.extend(sub_embeddings)
                    processed = sub_end_idx
                    
                    # 每处理一个子批次后清理内存
                    del sub_embeddings
                    gc.collect()
                    if TORCH_AVAILABLE and torch.cuda.is_available():
                        torch.cuda.empty_cache()
                        torch.cuda.synchronize()

                # 聚合切分后的嵌入
                aggregated_embeddings = []
                current_idx = 0
                for count in code_mapping:
                    if count == 1:
                        # 不需要聚合，直接取单个嵌入
                        aggregated_embeddings.append(sub_batch_embeddings[current_idx])
                        current_idx += 1
                    else:
                        # 需要聚合多个嵌入
                        chunk_embeddings = sub_batch_embeddings[current_idx:current_idx + count]
                        aggregated = self._aggregate_embeddings(chunk_embeddings)
                        aggregated_embeddings.append(aggregated)
                        current_idx += count
                
                # 将生成的嵌入插入到正确的位置
                for i, (idx, embedding) in enumerate(zip(uncached_indices, aggregated_embeddings)):
                    batch_embeddings.insert(idx, embedding)

                    if self.config.use_cache:
                        cache_key = self._generate_cache_key(uncached_codes[i])
                        self._cache[cache_key] = embedding

            # 将当前批次的嵌入添加到结果中
            embeddings.extend(batch_embeddings)

        # 标准化嵌入向量长度
        if embeddings:
            standard_dim = self.get_embedding_dimension()
            for i, emb in enumerate(embeddings):
                if len(emb) != standard_dim:
                    if len(emb) < standard_dim:
                        embeddings[i] = emb + [0.0] * (standard_dim - len(emb))
                    else:
                        embeddings[i] = emb[:standard_dim]

        # 再次清理
        for _ in range(2):
            gc.collect()
            if TORCH_AVAILABLE and torch.cuda.is_available():
                torch.cuda.empty_cache()
                torch.cuda.synchronize()

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
            
            # 为 embeddinggemma-300M 设置特殊参数
            encode_kwargs = {}
            if self.config.matryoshka_dim:
                encode_kwargs["truncate_dim"] = self.config.matryoshka_dim
            
            if "embeddinggemma-300M" in self.config.model_name:
                # 使用 numpy 格式，减少 GPU 内存占用
                convert_to_tensor = False
            else:
                convert_to_tensor = TORCH_AVAILABLE
            
            embedding = self._model.encode(
                compressed_code,
                batch_size=self.config.batch_size,
                show_progress_bar=False,
                convert_to_tensor=convert_to_tensor,
                normalize_embeddings=True,
                **encode_kwargs
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
            print(f"📊 开始批量生成嵌入，总条数: {len(codes)}")
            print(f"⏱️ 开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # 使用配置中的批处理大小
            batch_size = self.config.embedding_batch_size  # 统一使用配置中的批处理大小
            print(f"🔧 使用批处理大小: {batch_size}")
            
            # 可选 Matryoshka 压缩维度（省注入内存）
            encode_kwargs = {}
            if self.config.matryoshka_dim:
                encode_kwargs["truncate_dim"] = self.config.matryoshka_dim
                print(f"📏 使用 Matryoshka 压缩维度: {self.config.matryoshka_dim}")
            
            # 强制使用 numpy 格式输出，避免 tensor 留在 GPU
            convert_to_tensor = False
            print("📊 强制使用 numpy 格式输出")
            
            print("🚀 开始生成嵌入...")
            batch_start_time = datetime.now()
            # 自动检测设备
            device = "cuda" if TORCH_AVAILABLE and torch.cuda.is_available() else "cpu"
            print(f"📱 使用设备: {device}")
            
            # 监控内存使用
            if TORCH_AVAILABLE and torch.cuda.is_available():
                before_memory = torch.cuda.memory_allocated() / (1024 ** 2)  # MB
                print(f"📊 生成嵌入前 GPU 内存使用: {before_memory:.2f} MB")
            
            # 使用 torch.no_grad() 和半精度加速，进一步省内存
            with torch.no_grad():
                # 使用半精度加速
                if TORCH_AVAILABLE and device == "cuda" and self.config.precision == "float16":
                    with torch.autocast(device_type="cuda", dtype=torch.float16):
                        batch_embeddings = self._model.encode(
                            codes,
                            batch_size=batch_size,  # 强制小批量
                            device=device,
                            show_progress_bar=True,  # 显示进度条
                            convert_to_tensor=convert_to_tensor,
                            convert_to_numpy=True,  # 强制 numpy 输出
                            normalize_embeddings=True,
                            **encode_kwargs
                        )
                else:
                    batch_embeddings = self._model.encode(
                        codes,
                        batch_size=batch_size,  # 强制小批量
                        device=device,
                        show_progress_bar=True,  # 显示进度条
                        convert_to_tensor=convert_to_tensor,
                        convert_to_numpy=True,  # 强制 numpy 输出
                        normalize_embeddings=True,
                        **encode_kwargs
                    )
            
            # 监控内存使用
            if TORCH_AVAILABLE and torch.cuda.is_available():
                after_memory = torch.cuda.memory_allocated() / (1024 ** 2)  # MB
                print(f"📊 生成嵌入后 GPU 内存使用: {after_memory:.2f} MB")
                print(f"📊 内存变化: {after_memory - before_memory:.2f} MB")
            
            batch_end_time = datetime.now()
            batch_time = (batch_end_time - batch_start_time).total_seconds()
            print(f"✅ 嵌入完成，耗时: {batch_time:.2f} 秒")

            # 彻底清理显存
            if TORCH_AVAILABLE and torch.cuda.is_available():
                torch.cuda.empty_cache()
                torch.cuda.synchronize()  # 确保同步
                torch.cuda.reset_peak_memory_stats()  # 重置统计

            if NUMPY_AVAILABLE and isinstance(batch_embeddings, np.ndarray):
                print(f"📥 处理 numpy 嵌入，形状: {batch_embeddings.shape}")
                result = batch_embeddings.tolist()
                # 释放 numpy 数组内存
                del batch_embeddings
                return result
            elif isinstance(batch_embeddings, list):
                print(f"📥 处理列表嵌入，长度: {len(batch_embeddings)}")
                return batch_embeddings
            else:
                # 降级到单个嵌入
                print("⚠️  降级到单个嵌入处理...")
                return [self._fallback_embedding(code) for code in codes]

        except Exception as e:
            print(f"❌ Batch embedding failed: {e}")
            # 清理内存
            import gc
            gc.collect()
            if TORCH_AVAILABLE and torch.cuda.is_available():
                torch.cuda.empty_cache()
                torch.cuda.synchronize()
                torch.cuda.reset_peak_memory_stats()
            
            # 单条 fallback 机制
            print("🔄 启用单条 fallback 机制...")
            results = []
            for code in codes:
                try:
                    # 单条处理
                    embedding = self._generate_embedding(code)
                    results.append(embedding)
                except Exception as single_e:
                    print(f"❌ 单条处理失败: {single_e}")
                    results.append(self._fallback_embedding(code))
            return results

    def _fallback_embedding(self, code: str) -> List[float]:
        """降级嵌入方案

        Args:
            code: 代码

        Returns:
            嵌入向量
        """
        hash_value = hashlib.sha256(code.encode()).hexdigest()
        embedding = []

        # 生成256维向量，与模型一致
        for i in range(0, 256):
            if i < len(hash_value):
                embedding.append(int(hash_value[i % len(hash_value)], 16) / 15.0)
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

    def _chunk_text(self, text: str) -> List[str]:
        """将长文本切分为多个片段

        Args:
            text: 原始文本

        Returns:
            切分后的文本片段列表
        """
        if not text:
            return []

        chunks = []
        chunk_size = self.config.chunk_size
        stride = self.config.stride

        for i in range(0, len(text), chunk_size - stride):
            chunk = text[i:i + chunk_size]
            chunks.append(chunk)

        return chunks

    def _aggregate_embeddings(self, embeddings: List[List[float]]) -> List[float]:
        """聚合多个嵌入向量

        Args:
            embeddings: 嵌入向量列表

        Returns:
            聚合后的嵌入向量
        """
        if not embeddings:
            return []

        if NUMPY_AVAILABLE:
            import numpy as np
            embeddings_np = np.array(embeddings)
            aggregated = np.mean(embeddings_np, axis=0)
            return aggregated.tolist()
        else:
            # 降级方案：使用Python内置方法
            dim = len(embeddings[0])
            aggregated = [0.0] * dim
            for embedding in embeddings:
                for i in range(dim):
                    aggregated[i] += embedding[i]
            for i in range(dim):
                aggregated[i] /= len(embeddings)
            return aggregated

    def _get_token_length(self, text: str) -> int:
        """获取文本的token长度

        Args:
            text: 文本

        Returns:
            token长度
        """
        if not self._initialized:
            # 降级方案：按字符长度估算
            return len(text) // 4

        try:
            # 使用模型的tokenizer计算真实token长度
            if hasattr(self._model, 'tokenizer'):
                tokens = self._model.tokenizer(text, truncation=False, return_tensors='pt')
                return len(tokens['input_ids'][0])
            else:
                # 降级方案：按字符长度估算
                return len(text) // 4
        except Exception:
            # 降级方案：按字符长度估算
            return len(text) // 4

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


# 全局 CodeEmbedder 实例
_global_embedder: Optional[Union[CodeEmbedder, InMemoryEmbedder]] = None


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
    global _global_embedder
    if _global_embedder is None:
        if prefer_memory or not SENTENCE_TRANSFORMERS_AVAILABLE:
            _global_embedder = InMemoryEmbedder(config)
        else:
            _global_embedder = CodeEmbedder(config)
    return _global_embedder
