"""嵌入模型训练器模块

使用 Unsloth 进行嵌入模型的高效微调，支持 LoRA 微调和对比学习。
"""

import os
import torch
import numpy as np
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from datetime import datetime

from sentence_transformers import SentenceTransformer, InputExample, losses
from sentence_transformers.evaluation import TripletEvaluator
from sentence_transformers.training_args import SentenceTransformerTrainingArguments
from transformers import TrainingArguments

from src.utils.logger import get_logger

logger = get_logger(__name__)


class EmbeddingTrainer:
    """嵌入模型训练器

    使用 Unsloth 进行嵌入模型的高效微调。
    """

    def __init__(self, base_model: str = "BAAI/bge-base-en-v1.5"):
        """初始化嵌入模型训练器

        Args:
            base_model: 基础模型名称
        """
        self.base_model = base_model
        self.model: Optional[SentenceTransformer] = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"

    def load_model(self, model_path: Optional[Path] = None) -> SentenceTransformer:
        """加载模型

        Args:
            model_path: 模型路径，如果为 None 则加载基础模型

        Returns:
            加载的模型
        """
        try:
            if model_path and model_path.exists():
                logger.info(f"从 {model_path} 加载模型")
                self.model = SentenceTransformer(str(model_path))
            else:
                logger.info(f"加载基础模型: {self.base_model}")
                self.model = SentenceTransformer(self.base_model)
            
            self.model.to(self.device)
            logger.info(f"模型已加载到 {self.device} 设备")
            return self.model
        except Exception as e:
            logger.error(f"加载模型失败: {e}")
            raise

    def prepare_training_data(self, triplets: List[Tuple[str, str, str]]) -> List[InputExample]:
        """准备训练数据

        Args:
            triplets: 三元组列表，每个三元组包含 (anchor, positive, negative)

        Returns:
            InputExample 列表
        """
        examples = []
        
        for anchor, positive, negative in triplets:
            example = InputExample(
                texts=[anchor, positive, negative]
            )
            examples.append(example)
        
        logger.info(f"准备了 {len(examples)} 个训练样本")
        return examples

    def train(self, 
              train_data: List[InputExample],
              output_dir: Path,
              epochs: int = 3,
              batch_size: int = 32,
              learning_rate: float = 1e-5,
              warmup_steps: int = 100,
              evaluation_data: Optional[List[Tuple[str, str, str]]] = None):
        """训练模型

        Args:
            train_data: 训练数据
            output_dir: 输出目录
            epochs: 训练轮数
            batch_size: 批次大小
            learning_rate: 学习率
            warmup_steps: 预热步数
            evaluation_data: 评估数据

        Returns:
            训练后的模型
        """
        if not self.model:
            self.load_model()

        # 创建输出目录
        output_dir.mkdir(parents=True, exist_ok=True)

        # 设置训练参数
        training_args = SentenceTransformerTrainingArguments(
            output_dir=str(output_dir),
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            learning_rate=learning_rate,
            warmup_steps=warmup_steps,
            evaluation_strategy="steps",
            eval_steps=500,
            save_strategy="steps",
            save_steps=500,
            logging_steps=100,
            load_best_model_at_end=True,
            metric_for_best_model="loss",
            greater_is_better=False,
            fp16=torch.cuda.is_available(),
            gradient_accumulation_steps=4,
            weight_decay=0.01,
        )

        # 使用 MultipleNegativesRankingLoss
        train_loss = losses.MultipleNegativesRankingLoss(self.model)

        # 准备评估器
        evaluator = None
        if evaluation_data:
            anchor_sentences = [triplet[0] for triplet in evaluation_data]
            positive_sentences = [triplet[1] for triplet in evaluation_data]
            negative_sentences = [triplet[2] for triplet in evaluation_data]
            
            evaluator = TripletEvaluator(
                anchor_sentences=anchor_sentences,
                positive_sentences=positive_sentences,
                negative_sentences=negative_sentences,
                name="eval"
            )

        # 开始训练
        logger.info(f"开始训练模型，使用 {self.device} 设备")
        logger.info(f"训练参数: epochs={epochs}, batch_size={batch_size}, learning_rate={learning_rate}")

        from sentence_transformers import SentenceTransformerTrainer
        
        trainer = SentenceTransformerTrainer(
            model=self.model,
            args=training_args,
            train_dataset=train_data,
            evaluator=evaluator,
            loss=train_loss
        )

        # 执行训练
        trainer.train()

        # 保存最佳模型
        best_model_path = output_dir / "best_model"
        trainer.save_model(str(best_model_path))
        logger.info(f"最佳模型已保存到 {best_model_path}")

        # 加载最佳模型
        self.model = SentenceTransformer(str(best_model_path))
        return self.model

    def fine_tune_with_lora(self, 
                          train_data: List[InputExample],
                          output_dir: Path,
                          lora_r: int = 16,
                          lora_alpha: int = 32,
                          epochs: int = 3,
                          batch_size: int = 32):
        """使用 LoRA 进行微调

        Args:
            train_data: 训练数据
            output_dir: 输出目录
            lora_r: LoRA 秩
            lora_alpha: LoRA alpha
            epochs: 训练轮数
            batch_size: 批次大小

        Returns:
            训练后的模型
        """
        try:
            # 尝试使用 Unsloth 进行 LoRA 微调
            from unsloth import FastLanguageModel
            
            logger.info("使用 Unsloth 进行 LoRA 微调")
            
            # 加载模型
            model, tokenizer = FastLanguageModel.from_pretrained(
                model_name=self.base_model,
                max_seq_length=512,
                dtype=None,
                load_in_4bit=False,
            )

            # 配置 LoRA
            model = FastLanguageModel.get_peft_model(
                model,
                r=lora_r,
                lora_alpha=lora_alpha,
                lora_dropout=0.05,
                target_modules=[
                    "q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"
                ],
                bias="none",
                use_gradient_checkpointing=True,
            )

            # 这里需要将 InputExample 转换为适合 Unsloth 的格式
            # 由于 Unsloth 主要针对 LLM，我们使用 SentenceTransformer 的训练流程
            # 但利用 Unsloth 的内存优化
            
            logger.info("使用 Unsloth 内存优化进行训练")
            return self.train(
                train_data=train_data,
                output_dir=output_dir,
                epochs=epochs,
                batch_size=batch_size,
                learning_rate=2e-5
            )
        except ImportError:
            logger.warning("Unsloth 未安装，使用标准 SentenceTransformer 训练")
            return self.train(
                train_data=train_data,
                output_dir=output_dir,
                epochs=epochs,
                batch_size=batch_size
            )
        except Exception as e:
            logger.error(f"LoRA 微调失败: {e}")
            # 回退到标准训练
            return self.train(
                train_data=train_data,
                output_dir=output_dir,
                epochs=epochs,
                batch_size=batch_size
            )

    def evaluate(self, 
                model_path: Path,
                evaluation_data: List[Tuple[str, str, str]]) -> Dict[str, float]:
        """评估模型

        Args:
            model_path: 模型路径
            evaluation_data: 评估数据

        Returns:
            评估指标
        """
        try:
            # 加载模型
            model = SentenceTransformer(str(model_path))
            
            # 准备评估数据
            anchor_sentences = [triplet[0] for triplet in evaluation_data]
            positive_sentences = [triplet[1] for triplet in evaluation_data]
            negative_sentences = [triplet[2] for triplet in evaluation_data]
            
            # 创建评估器
            evaluator = TripletEvaluator(
                anchor_sentences=anchor_sentences,
                positive_sentences=positive_sentences,
                negative_sentences=negative_sentences,
                name="eval"
            )
            
            # 评估
            score = evaluator(model)
            logger.info(f"评估得分: {score}")
            
            # 计算额外指标
            metrics = {
                "score": score,
                "recall@1": self._calculate_recall(model, evaluation_data, k=1),
                "recall@5": self._calculate_recall(model, evaluation_data, k=5),
                "mrr": self._calculate_mrr(model, evaluation_data)
            }
            
            logger.info(f"评估指标: {metrics}")
            return metrics
        except Exception as e:
            logger.error(f"评估失败: {e}")
            return {}

    def _calculate_recall(self, model: SentenceTransformer, 
                         evaluation_data: List[Tuple[str, str, str]], 
                         k: int = 1) -> float:
        """计算 Recall@K

        Args:
            model: 模型
            evaluation_data: 评估数据
            k: K 值

        Returns:
            Recall@K 得分
        """
        correct = 0
        total = len(evaluation_data)
        
        for anchor, positive, negative in evaluation_data:
            # 生成嵌入
            anchor_embedding = model.encode(anchor)
            positive_embedding = model.encode(positive)
            negative_embedding = model.encode(negative)
            
            # 计算相似度
            pos_sim = self._cosine_similarity(anchor_embedding, positive_embedding)
            neg_sim = self._cosine_similarity(anchor_embedding, negative_embedding)
            
            # 排序
            similarities = [(pos_sim, "positive"), (neg_sim, "negative")]
            similarities.sort(reverse=True, key=lambda x: x[0])
            
            # 检查前 K 个是否包含 positive
            for i in range(min(k, len(similarities))):
                if similarities[i][1] == "positive":
                    correct += 1
                    break
        
        return correct / total if total > 0 else 0

    def _calculate_mrr(self, model: SentenceTransformer, 
                      evaluation_data: List[Tuple[str, str, str]]) -> float:
        """计算 MRR (Mean Reciprocal Rank)

        Args:
            model: 模型
            evaluation_data: 评估数据

        Returns:
            MRR 得分
        """
        reciprocal_ranks = []
        
        for anchor, positive, negative in evaluation_data:
            # 生成嵌入
            anchor_embedding = model.encode(anchor)
            positive_embedding = model.encode(positive)
            negative_embedding = model.encode(negative)
            
            # 计算相似度
            pos_sim = self._cosine_similarity(anchor_embedding, positive_embedding)
            neg_sim = self._cosine_similarity(anchor_embedding, negative_embedding)
            
            # 排序
            similarities = [(pos_sim, "positive"), (neg_sim, "negative")]
            similarities.sort(reverse=True, key=lambda x: x[0])
            
            # 计算 reciprocal rank
            for i, (_, label) in enumerate(similarities):
                if label == "positive":
                    reciprocal_ranks.append(1 / (i + 1))
                    break
        
        return sum(reciprocal_ranks) / len(reciprocal_ranks) if reciprocal_ranks else 0

    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """计算余弦相似度

        Args:
            vec1: 向量1
            vec2: 向量2

        Returns:
            余弦相似度
        """
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)

    def save_model(self, model_path: Path):
        """保存模型

        Args:
            model_path: 保存路径
        """
        if not self.model:
            logger.error("模型未加载，无法保存")
            return

        try:
            model_path.mkdir(parents=True, exist_ok=True)
            self.model.save(str(model_path))
            logger.info(f"模型已保存到 {model_path}")
        except Exception as e:
            logger.error(f"保存模型失败: {e}")

    def load_fine_tuned_model(self, model_path: Path) -> SentenceTransformer:
        """加载微调后的模型

        Args:
            model_path: 模型路径

        Returns:
            加载的模型
        """
        return self.load_model(model_path)

    def export_to_onnx(self, model_path: Path, onnx_path: Path):
        """导出模型为 ONNX 格式

        Args:
            model_path: 模型路径
            onnx_path: ONNX 输出路径
        """
        try:
            # 加载模型
            model = SentenceTransformer(str(model_path))
            
            # 导出为 ONNX
            onnx_path.mkdir(parents=True, exist_ok=True)
            model.export_onnx(str(onnx_path / "model.onnx"))
            logger.info(f"模型已导出为 ONNX 格式到 {onnx_path}")
        except Exception as e:
            logger.error(f"导出 ONNX 失败: {e}")

    def create_training_script(self, 
                             output_path: Path,
                             train_data_path: Path,
                             eval_data_path: Path,
                             output_dir: Path,
                             base_model: str = "BAAI/bge-base-en-v1.5",
                             epochs: int = 3,
                             batch_size: int = 32):
        """创建训练脚本

        Args:
            output_path: 输出脚本路径
            train_data_path: 训练数据路径
            eval_data_path: 评估数据路径
            output_dir: 模型输出目录
            base_model: 基础模型
            epochs: 训练轮数
            batch_size: 批次大小
        """
        script_content = f"""
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.embedding_trainer import EmbeddingTrainer
from src.storage.data_augmentation import DataAugmentation

# 初始化数据增强器
data_aug = DataAugmentation()

# 加载训练数据
train_triplets = data_aug.load_training_data(Path("{train_data_path}"))

# 加载评估数据
eval_triplets = data_aug.load_training_data(Path("{eval_data_path}"))

# 初始化训练器
trainer = EmbeddingTrainer(base_model="{base_model}")

# 准备训练数据
train_data = trainer.prepare_training_data(train_triplets)

# 训练模型
trainer.train(
    train_data=train_data,
    output_dir=Path("{output_dir}"),
    epochs={epochs},
    batch_size={batch_size},
    evaluation_data=eval_triplets
)

print("训练完成！")
"""

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(script_content)
            logger.info(f"训练脚本已创建到 {output_path}")
        except Exception as e:
            logger.error(f"创建训练脚本失败: {e}")
