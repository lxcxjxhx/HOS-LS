"""嵌入模型评估器模块

用于评估嵌入模型的有效性，包括 RAG 性能评估、相似度计算和模型比较。
"""

import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from sentence_transformers import SentenceTransformer
from sklearn.metrics import precision_recall_fscore_support
from sklearn.neighbors import NearestNeighbors

from src.utils.logger import get_logger

logger = get_logger(__name__)


class EmbeddingEvaluator:
    """嵌入模型评估器

    用于评估嵌入模型的有效性和 RAG 性能。
    """

    def __init__(self, model_path: Optional[Path] = None):
        """初始化嵌入模型评估器

        Args:
            model_path: 模型路径
        """
        self.model_path = model_path
        self.model: Optional[SentenceTransformer] = None
        if model_path:
            self.load_model(model_path)

    def load_model(self, model_path: Path) -> SentenceTransformer:
        """加载模型

        Args:
            model_path: 模型路径

        Returns:
            加载的模型
        """
        try:
            self.model = SentenceTransformer(str(model_path))
            logger.info(f"模型已加载: {model_path}")
            return self.model
        except Exception as e:
            logger.error(f"加载模型失败: {e}")
            raise

    def evaluate_rag_performance(self, 
                               queries: List[str],
                               ground_truths: List[List[str]],
                               documents: List[str],
                               top_k: int = 5) -> Dict[str, float]:
        """评估 RAG 性能

        Args:
            queries: 查询列表
            ground_truths: 每个查询的真实相关文档列表
            documents: 文档库
            top_k: 检索前 K 个结果

        Returns:
            评估指标
        """
        if not self.model:
            logger.error("模型未加载，无法评估")
            return {}

        try:
            # 生成文档嵌入
            document_embeddings = self.model.encode(documents)
            
            # 构建 KNN 索引
            knn = NearestNeighbors(n_neighbors=top_k, metric='cosine')
            knn.fit(document_embeddings)

            # 评估每个查询
            recalls = []
            precisions = []
            f1_scores = []
            mrrs = []

            for query, ground_truth in zip(queries, ground_truths):
                # 生成查询嵌入
                query_embedding = self.model.encode([query])[0]
                
                # 检索相关文档
                distances, indices = knn.kneighbors([query_embedding])
                retrieved_docs = [documents[idx] for idx in indices[0]]

                # 计算评估指标
                recall = self._calculate_recall(retrieved_docs, ground_truth)
                precision = self._calculate_precision(retrieved_docs, ground_truth)
                f1 = self._calculate_f1(precision, recall)
                mrr = self._calculate_mrr(retrieved_docs, ground_truth)

                recalls.append(recall)
                precisions.append(precision)
                f1_scores.append(f1)
                mrrs.append(mrr)

            # 计算平均指标
            metrics = {
                "average_recall": np.mean(recalls),
                "average_precision": np.mean(precisions),
                "average_f1": np.mean(f1_scores),
                "average_mrr": np.mean(mrrs),
                "recall@k": np.mean(recalls),
                "precision@k": np.mean(precisions),
                "f1@k": np.mean(f1_scores),
                "mrr": np.mean(mrrs)
            }

            logger.info(f"RAG 性能评估结果: {metrics}")
            return metrics
        except Exception as e:
            logger.error(f"评估 RAG 性能失败: {e}")
            return {}

    def evaluate_semantic_similarity(self, 
                                   pairs: List[Tuple[str, str]],
                                   expected_similarities: List[float]) -> Dict[str, float]:
        """评估语义相似度

        Args:
            pairs: 文本对列表
            expected_similarities: 预期相似度列表

        Returns:
            评估指标
        """
        if not self.model:
            logger.error("模型未加载，无法评估")
            return {}

        try:
            predicted_similarities = []
            
            for text1, text2 in pairs:
                # 生成嵌入
                embedding1 = self.model.encode(text1)
                embedding2 = self.model.encode(text2)
                
                # 计算相似度
                similarity = self._cosine_similarity(embedding1, embedding2)
                predicted_similarities.append(similarity)

            # 计算评估指标
            correlation = np.corrcoef(predicted_similarities, expected_similarities)[0, 1]
            mse = np.mean((np.array(predicted_similarities) - np.array(expected_similarities)) ** 2)
            mae = np.mean(np.abs(np.array(predicted_similarities) - np.array(expected_similarities)))

            metrics = {
                "correlation": correlation,
                "mse": mse,
                "mae": mae
            }

            logger.info(f"语义相似度评估结果: {metrics}")
            return metrics
        except Exception as e:
            logger.error(f"评估语义相似度失败: {e}")
            return {}

    def evaluate_security_awareness(self, 
                                   security_queries: List[str],
                                   vulnerability_types: List[str]) -> Dict[str, float]:
        """评估模型的安全意识

        Args:
            security_queries: 安全相关查询
            vulnerability_types: 对应的漏洞类型

        Returns:
            评估指标
        """
        if not self.model:
            logger.error("模型未加载，无法评估")
            return {}

        try:
            # 为每个漏洞类型生成嵌入
            type_embeddings = {}
            for vuln_type in set(vulnerability_types):
                type_embeddings[vuln_type] = self.model.encode(vuln_type)

            # 评估每个查询
            correct_predictions = 0
            total_queries = len(security_queries)

            for query, true_type in zip(security_queries, vulnerability_types):
                # 生成查询嵌入
                query_embedding = self.model.encode(query)
                
                # 找到最相似的漏洞类型
                max_similarity = -1
                predicted_type = None
                
                for vuln_type, embedding in type_embeddings.items():
                    similarity = self._cosine_similarity(query_embedding, embedding)
                    if similarity > max_similarity:
                        max_similarity = similarity
                        predicted_type = vuln_type

                # 检查预测是否正确
                if predicted_type == true_type:
                    correct_predictions += 1

            # 计算准确率
            accuracy = correct_predictions / total_queries if total_queries > 0 else 0

            metrics = {
                "accuracy": accuracy,
                "correct_predictions": correct_predictions,
                "total_queries": total_queries
            }

            logger.info(f"安全意识评估结果: {metrics}")
            return metrics
        except Exception as e:
            logger.error(f"评估安全意识失败: {e}")
            return {}

    def compare_models(self, 
                     model_paths: List[Path],
                     evaluation_data: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
        """比较多个模型

        Args:
            model_paths: 模型路径列表
            evaluation_data: 评估数据

        Returns:
            每个模型的评估指标
        """
        results = {}

        for model_path in model_paths:
            try:
                # 加载模型
                model = SentenceTransformer(str(model_path))
                self.model = model

                # 评估 RAG 性能
                rag_metrics = self.evaluate_rag_performance(
                    queries=evaluation_data.get('queries', []),
                    ground_truths=evaluation_data.get('ground_truths', []),
                    documents=evaluation_data.get('documents', []),
                    top_k=5
                )

                # 评估语义相似度
                similarity_metrics = self.evaluate_semantic_similarity(
                    pairs=evaluation_data.get('similarity_pairs', []),
                    expected_similarities=evaluation_data.get('expected_similarities', [])
                )

                # 评估安全意识
                security_metrics = self.evaluate_security_awareness(
                    security_queries=evaluation_data.get('security_queries', []),
                    vulnerability_types=evaluation_data.get('vulnerability_types', [])
                )

                # 整合结果
                results[str(model_path)] = {
                    **rag_metrics,
                    **similarity_metrics,
                    **security_metrics
                }

                logger.info(f"模型 {model_path} 评估完成")
            except Exception as e:
                logger.error(f"评估模型 {model_path} 失败: {e}")
                results[str(model_path)] = {"error": str(e)}

        return results

    def detect_rag_failures(self, 
                           queries: List[str],
                           ground_truths: List[List[str]],
                           documents: List[str],
                           threshold: float = 0.5) -> List[Dict[str, Any]]:
        """检测 RAG 失败案例

        Args:
            queries: 查询列表
            ground_truths: 每个查询的真实相关文档列表
            documents: 文档库
            threshold: 召回率阈值，低于此值视为失败

        Returns:
            失败案例列表
        """
        if not self.model:
            logger.error("模型未加载，无法检测失败")
            return []

        try:
            # 生成文档嵌入
            document_embeddings = self.model.encode(documents)
            
            # 构建 KNN 索引
            knn = NearestNeighbors(n_neighbors=5, metric='cosine')
            knn.fit(document_embeddings)

            failures = []

            for i, (query, ground_truth) in enumerate(zip(queries, ground_truths)):
                # 生成查询嵌入
                query_embedding = self.model.encode([query])[0]
                
                # 检索相关文档
                distances, indices = knn.kneighbors([query_embedding])
                retrieved_docs = [documents[idx] for idx in indices[0]]

                # 计算召回率
                recall = self._calculate_recall(retrieved_docs, ground_truth)

                # 检查是否失败
                if recall < threshold:
                    failures.append({
                        "query": query,
                        "ground_truth": ground_truth,
                        "retrieved_docs": retrieved_docs,
                        "recall": recall,
                        "index": i
                    })

            logger.info(f"检测到 {len(failures)} 个 RAG 失败案例")
            return failures
        except Exception as e:
            logger.error(f"检测 RAG 失败案例失败: {e}")
            return []

    def generate_failure_report(self, 
                              failures: List[Dict[str, Any]],
                              output_path: Path):
        """生成失败报告

        Args:
            failures: 失败案例列表
            output_path: 输出路径
        """
        try:
            report = {
                "timestamp": datetime.now().isoformat(),
                "failure_count": len(failures),
                "failures": failures,
                "summary": {
                    "average_recall": np.mean([f['recall'] for f in failures]) if failures else 0,
                    "min_recall": min([f['recall'] for f in failures]) if failures else 0,
                    "max_recall": max([f['recall'] for f in failures]) if failures else 0
                }
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            logger.info(f"失败报告已生成到 {output_path}")
        except Exception as e:
            logger.error(f"生成失败报告失败: {e}")

    def _calculate_recall(self, retrieved: List[str], ground_truth: List[str]) -> float:
        """计算召回率

        Args:
            retrieved: 检索到的文档
            ground_truth: 真实相关文档

        Returns:
            召回率
        """
        if not ground_truth:
            return 0.0
        
        relevant_retrieved = [doc for doc in retrieved if doc in ground_truth]
        return len(relevant_retrieved) / len(ground_truth)

    def _calculate_precision(self, retrieved: List[str], ground_truth: List[str]) -> float:
        """计算精确率

        Args:
            retrieved: 检索到的文档
            ground_truth: 真实相关文档

        Returns:
            精确率
        """
        if not retrieved:
            return 0.0
        
        relevant_retrieved = [doc for doc in retrieved if doc in ground_truth]
        return len(relevant_retrieved) / len(retrieved)

    def _calculate_f1(self, precision: float, recall: float) -> float:
        """计算 F1 分数

        Args:
            precision: 精确率
            recall: 召回率

        Returns:
            F1 分数
        """
        if precision + recall == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)

    def _calculate_mrr(self, retrieved: List[str], ground_truth: List[str]) -> float:
        """计算 MRR (Mean Reciprocal Rank)

        Args:
            retrieved: 检索到的文档
            ground_truth: 真实相关文档

        Returns:
            MRR 得分
        """
        for i, doc in enumerate(retrieved):
            if doc in ground_truth:
                return 1 / (i + 1)
        return 0.0

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

    def evaluate_embedding_quality(self, 
                                 documents: List[str]) -> Dict[str, float]:
        """评估嵌入质量

        Args:
            documents: 文档列表

        Returns:
            嵌入质量指标
        """
        if not self.model:
            logger.error("模型未加载，无法评估")
            return {}

        try:
            # 生成嵌入
            embeddings = self.model.encode(documents)
            
            # 计算嵌入统计信息
            mean_embedding = np.mean(embeddings, axis=0)
            std_embedding = np.std(embeddings, axis=0)
            
            # 计算嵌入之间的相似度分布
            similarities = []
            for i in range(len(embeddings)):
                for j in range(i + 1, len(embeddings)):
                    similarity = self._cosine_similarity(embeddings[i], embeddings[j])
                    similarities.append(similarity)

            metrics = {
                "embedding_dimension": embeddings.shape[1],
                "mean_similarity": np.mean(similarities) if similarities else 0,
                "std_similarity": np.std(similarities) if similarities else 0,
                "min_similarity": min(similarities) if similarities else 0,
                "max_similarity": max(similarities) if similarities else 0,
                "mean_norm": np.mean(np.linalg.norm(embeddings, axis=1)),
                "std_norm": np.std(np.linalg.norm(embeddings, axis=1))
            }

            logger.info(f"嵌入质量评估结果: {metrics}")
            return metrics
        except Exception as e:
            logger.error(f"评估嵌入质量失败: {e}")
            return {}
