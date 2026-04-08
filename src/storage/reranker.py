"""重排序器

实现基于 bge-reranker 或 cross-encoder 的结果重排序，提高检索结果的相关性。
"""

from typing import List, Dict, Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


try:
    from sentence_transformers import CrossEncoder
except ImportError:
    logger.warning("sentence-transformers not installed, using fallback implementation")
    CrossEncoder = None


class Reranker:
    """重排序器

    使用 bge-reranker 或 cross-encoder 对检索结果进行精排，提高命中率。
    """

    def __init__(self, model_name: str = None, device: str = "auto"):
        """初始化重排序器

        Args:
            model_name: 重排序模型名称，None 表示禁用
            device: 运行设备 (auto, cpu, cuda)
        """
        self.model_name = model_name
        self.device = device if device != "auto" else ("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        if model_name:
            self._load_model()

    def _load_model(self) -> None:
        """加载重排序模型"""
        if CrossEncoder is not None and self.model_name:
            try:
                logger.info(f"加载重排序模型: {self.model_name}")
                self.model = CrossEncoder(self.model_name, device=self.device)
                logger.info("重排序模型加载成功")
            except Exception as e:
                logger.error(f"加载重排序模型失败: {e}")
                self.model = None
        else:
            if not self.model_name:
                logger.info("重排序功能已禁用")
            else:
                logger.warning("sentence-transformers 未安装，使用回退实现")
            self.model = None

    def rerank(self, query: str, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """重排序候选结果

        Args:
            query: 查询文本
            candidates: 候选结果列表

        Returns:
            重排序后的结果列表
        """
        if not candidates:
            return []
        
        # 使用模型进行重排序（如果可用）
        if self.model is not None:
            try:
                return self._model_rerank(query, candidates)
            except Exception as e:
                logger.error(f"模型重排序失败: {e}")
                # 失败时回退到原始结果
                return candidates
        else:
            # 未启用重排序，返回原始结果
            return candidates

    def _model_rerank(self, query: str, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """使用模型进行重排序

        Args:
            query: 查询文本
            candidates: 候选结果列表

        Returns:
            重排序后的结果列表
        """
        try:
            # 准备输入对
            input_pairs = [(query, candidate["content"]) for candidate in candidates]
            
            # 计算得分
            scores = self.model.predict(input_pairs)
            
            # 按得分排序
            sorted_candidates = sorted(
                zip(candidates, scores),
                key=lambda x: x[1],
                reverse=True
            )
            
            # 转换为结果列表
            results = []
            for candidate, score in sorted_candidates:
                candidate["rerank_score"] = float(score)
                results.append(candidate)
            
            return results
        except Exception as e:
            logger.error(f"模型重排序失败: {e}")
            # 失败时回退到简单排序
            return self._fallback_rerank(query, candidates)

    def _fallback_rerank(self, query: str, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """回退到简单排序

        Args:
            query: 查询文本
            candidates: 候选结果列表

        Returns:
            重排序后的结果列表
        """
        # 简单的关键词匹配得分
        def calculate_score(query: str, content: str) -> float:
            query_tokens = set(query.lower().split())
            content_tokens = set(content.lower().split())
            intersection = query_tokens & content_tokens
            if not query_tokens:
                return 0.0
            return len(intersection) / len(query_tokens)
        
        # 计算得分并排序
        scored_candidates = []
        for candidate in candidates:
            score = calculate_score(query, candidate["content"])
            candidate["rerank_score"] = score
            scored_candidates.append(candidate)
        
        # 按得分排序
        scored_candidates.sort(key=lambda x: x["rerank_score"], reverse=True)
        
        return scored_candidates

    def score(self, query: str, texts: List[str]) -> List[float]:
        """为文本列表评分

        Args:
            query: 查询文本
            texts: 文本列表

        Returns:
            得分列表
        """
        if not texts:
            return []
        
        if self.model is not None:
            try:
                input_pairs = [(query, text) for text in texts]
                scores = self.model.predict(input_pairs)
                return [float(score) for score in scores]
            except Exception as e:
                logger.error(f"模型评分失败: {e}")
                # 失败时回退到简单评分
                return [self._calculate_simple_score(query, text) for text in texts]
        else:
            # 回退到简单评分
            return [self._calculate_simple_score(query, text) for text in texts]

    def _calculate_simple_score(self, query: str, text: str) -> float:
        """计算简单的文本匹配得分

        Args:
            query: 查询文本
            text: 待评分文本

        Returns:
            得分
        """
        query_tokens = set(query.lower().split())
        text_tokens = set(text.lower().split())
        intersection = query_tokens & text_tokens
        if not query_tokens:
            return 0.0
        return len(intersection) / len(query_tokens)

    def is_available(self) -> bool:
        """检查重排序模型是否可用

        Returns:
            是否可用
        """
        return self.model is not None

    def get_model_info(self) -> Dict[str, Any]:
        """获取模型信息

        Returns:
            模型信息
        """
        return {
            "model_name": self.model_name,
            "device": self.device,
            "is_available": self.is_available()
        }
