"""嵌入模型优化器模块

实现自动优化系统，包括 RAG 失败检测、数据收集和模型重训练。
"""

import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from src.storage.embedding_evaluator import EmbeddingEvaluator
from src.storage.embedding_trainer import EmbeddingTrainer
from src.storage.data_augmentation import DataAugmentation
from src.utils.logger import get_logger

logger = get_logger(__name__)


class EmbeddingOptimizer:
    """嵌入模型优化器

    实现自动优化系统，包括 RAG 失败检测、数据收集和模型重训练。
    """

    def __init__(self, 
                 model_path: Path,
                 data_dir: Path,
                 output_dir: Path):
        """初始化嵌入模型优化器

        Args:
            model_path: 模型路径
            data_dir: 数据目录
            output_dir: 输出目录
        """
        self.model_path = model_path
        self.data_dir = data_dir
        self.output_dir = output_dir
        
        # 创建必要的目录
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 初始化组件
        self.evaluator = EmbeddingEvaluator(model_path)
        self.trainer = EmbeddingTrainer()
        self.data_aug = DataAugmentation()
        
        # 失败案例存储路径
        self.failures_path = self.data_dir / "rag_failures.json"
        self.training_data_path = self.data_dir / "training_data.json"
        
        # 加载现有失败案例
        self.failures = self._load_failures()

    def monitor_rag_performance(self, 
                              queries: List[str],
                              ground_truths: List[List[str]],
                              documents: List[str]) -> Dict[str, float]:
        """监控 RAG 性能

        Args:
            queries: 查询列表
            ground_truths: 每个查询的真实相关文档列表
            documents: 文档库

        Returns:
            性能指标
        """
        # 评估 RAG 性能
        metrics = self.evaluator.evaluate_rag_performance(
            queries=queries,
            ground_truths=ground_truths,
            documents=documents
        )
        
        # 检测失败案例
        failures = self.evaluator.detect_rag_failures(
            queries=queries,
            ground_truths=ground_truths,
            documents=documents
        )
        
        # 保存失败案例
        if failures:
            self._save_failures(failures)
            logger.info(f"检测到 {len(failures)} 个 RAG 失败案例，已保存")
        
        return metrics

    def generate_training_data_from_failures(self) -> List[tuple]:
        """从失败案例生成训练数据

        Returns:
            训练数据三元组列表
        """
        if not self.failures:
            logger.info("没有失败案例可用于生成训练数据")
            return []
        
        triplets = []
        
        for failure in self.failures:
            # 从失败案例创建三元组
            anchor = failure['query']
            
            # 正样本：真实相关文档
            for ground_truth_doc in failure['ground_truth']:
                positive = f"相关文档: {ground_truth_doc}"
                
                # 负样本：检索到的不相关文档
                for retrieved_doc in failure['retrieved_docs']:
                    if retrieved_doc not in failure['ground_truth']:
                        negative = f"不相关文档: {retrieved_doc}"
                        triplets.append((anchor, positive, negative))
        
        logger.info(f"从 {len(self.failures)} 个失败案例生成了 {len(triplets)} 个训练三元组")
        
        # 增强数据
        augmented_triplets = self.data_aug.augment_data(triplets)
        
        # 验证数据
        valid_triplets = self.data_aug.validate_data(augmented_triplets)
        
        # 保存训练数据
        self.data_aug.save_training_data(valid_triplets, self.training_data_path)
        
        return valid_triplets

    def retrain_model(self, 
                     epochs: int = 3,
                     batch_size: int = 32,
                     learning_rate: float = 1e-5) -> Path:
        """重训练模型

        Args:
            epochs: 训练轮数
            batch_size: 批次大小
            learning_rate: 学习率

        Returns:
            新模型路径
        """
        # 加载训练数据
        triplets = self.data_aug.load_training_data(self.training_data_path)
        
        if not triplets:
            logger.error("没有训练数据，无法重训练模型")
            return self.model_path
        
        # 准备训练数据
        train_data = self.trainer.prepare_training_data(triplets)
        
        # 创建输出目录
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_model_dir = self.output_dir / f"model_{timestamp}"
        
        # 重训练模型
        logger.info(f"开始重训练模型，输出目录: {new_model_dir}")
        model = self.trainer.train(
            train_data=train_data,
            output_dir=new_model_dir,
            epochs=epochs,
            batch_size=batch_size,
            learning_rate=learning_rate
        )
        
        # 保存模型
        best_model_path = new_model_dir / "best_model"
        logger.info(f"重训练完成，最佳模型保存到: {best_model_path}")
        
        return best_model_path

    def evaluate_and_replace_model(self, 
                                 new_model_path: Path,
                                 evaluation_data: Dict[str, Any]) -> bool:
        """评估并替换模型

        Args:
            new_model_path: 新模型路径
            evaluation_data: 评估数据

        Returns:
            是否替换模型
        """
        # 评估现有模型
        current_evaluator = EmbeddingEvaluator(self.model_path)
        current_metrics = current_evaluator.evaluate_rag_performance(
            queries=evaluation_data.get('queries', []),
            ground_truths=evaluation_data.get('ground_truths', []),
            documents=evaluation_data.get('documents', [])
        )
        
        # 评估新模型
        new_evaluator = EmbeddingEvaluator(new_model_path)
        new_metrics = new_evaluator.evaluate_rag_performance(
            queries=evaluation_data.get('queries', []),
            ground_truths=evaluation_data.get('ground_truths', []),
            documents=evaluation_data.get('documents', [])
        )
        
        # 比较性能
        current_score = current_metrics.get('average_f1', 0)
        new_score = new_metrics.get('average_f1', 0)
        
        logger.info(f"现有模型 F1 分数: {current_score}")
        logger.info(f"新模型 F1 分数: {new_score}")
        
        # 如果新模型性能更好，替换现有模型
        if new_score > current_score + 0.05:  # 至少提高 5%
            logger.info("新模型性能更好，替换现有模型")
            # 这里可以实现模型替换逻辑
            # 例如：复制新模型到当前模型路径
            return True
        else:
            logger.info("新模型性能未显著提高，保持现有模型")
            return False

    def run_optimization_cycle(self, 
                             evaluation_data: Dict[str, Any],
                             epochs: int = 3,
                             batch_size: int = 32) -> Dict[str, Any]:
        """运行优化周期

        Args:
            evaluation_data: 评估数据
            epochs: 训练轮数
            batch_size: 批次大小

        Returns:
            优化结果
        """
        start_time = time.time()
        
        # 1. 监控 RAG 性能
        logger.info("步骤 1: 监控 RAG 性能")
        metrics = self.monitor_rag_performance(
            queries=evaluation_data.get('queries', []),
            ground_truths=evaluation_data.get('ground_truths', []),
            documents=evaluation_data.get('documents', [])
        )
        
        # 2. 从失败案例生成训练数据
        logger.info("步骤 2: 从失败案例生成训练数据")
        training_data = self.generate_training_data_from_failures()
        
        if not training_data:
            logger.info("没有足够的训练数据，跳过重训练")
            return {
                "status": "skipped",
                "reason": "insufficient_training_data",
                "metrics": metrics,
                "duration": time.time() - start_time
            }
        
        # 3. 重训练模型
        logger.info("步骤 3: 重训练模型")
        new_model_path = self.retrain_model(
            epochs=epochs,
            batch_size=batch_size
        )
        
        # 4. 评估并替换模型
        logger.info("步骤 4: 评估并替换模型")
        replaced = self.evaluate_and_replace_model(
            new_model_path=new_model_path,
            evaluation_data=evaluation_data
        )
        
        end_time = time.time()
        
        return {
            "status": "completed",
            "replaced": replaced,
            "new_model_path": str(new_model_path),
            "metrics": metrics,
            "training_data_size": len(training_data),
            "duration": end_time - start_time
        }

    def _load_failures(self) -> List[Dict[str, Any]]:
        """加载失败案例

        Returns:
            失败案例列表
        """
        if not self.failures_path.exists():
            return []
        
        try:
            with open(self.failures_path, 'r', encoding='utf-8') as f:
                failures = json.load(f)
            logger.info(f"加载了 {len(failures)} 个失败案例")
            return failures
        except Exception as e:
            logger.error(f"加载失败案例失败: {e}")
            return []

    def _save_failures(self, new_failures: List[Dict[str, Any]]):
        """保存失败案例

        Args:
            new_failures: 新的失败案例
        """
        # 合并现有失败案例和新失败案例
        all_failures = self.failures + new_failures
        
        # 去重
        seen_queries = set()
        unique_failures = []
        
        for failure in all_failures:
            query = failure.get('query', '')
            if query not in seen_queries:
                seen_queries.add(query)
                unique_failures.append(failure)
        
        # 保存
        try:
            with open(self.failures_path, 'w', encoding='utf-8') as f:
                json.dump(unique_failures, f, indent=2, ensure_ascii=False)
            
            # 更新内存中的失败案例
            self.failures = unique_failures
            logger.info(f"保存了 {len(unique_failures)} 个失败案例")
        except Exception as e:
            logger.error(f"保存失败案例失败: {e}")

    def clear_failures(self):
        """清除失败案例"""
        try:
            if self.failures_path.exists():
                self.failures_path.unlink()
            self.failures = []
            logger.info("失败案例已清除")
        except Exception as e:
            logger.error(f"清除失败案例失败: {e}")

    def get_optimization_history(self) -> List[Dict[str, Any]]:
        """获取优化历史

        Returns:
            优化历史列表
        """
        history_path = self.output_dir / "optimization_history.json"
        
        if not history_path.exists():
            return []
        
        try:
            with open(history_path, 'r', encoding='utf-8') as f:
                history = json.load(f)
            return history
        except Exception as e:
            logger.error(f"加载优化历史失败: {e}")
            return []

    def save_optimization_history(self, result: Dict[str, Any]):
        """保存优化历史

        Args:
            result: 优化结果
        """
        history_path = self.output_dir / "optimization_history.json"
        
        # 加载现有历史
        history = self.get_optimization_history()
        
        # 添加新记录
        record = {
            "timestamp": datetime.now().isoformat(),
            "result": result
        }
        history.append(record)
        
        # 保存
        try:
            with open(history_path, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
            logger.info("优化历史已保存")
        except Exception as e:
            logger.error(f"保存优化历史失败: {e}")
