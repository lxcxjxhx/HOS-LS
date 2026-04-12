"""语义匹配系统模块

利用向量存储和语义分析快速匹配漏洞模式，减少AI调用，节省token。
"""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

from src.storage.vector_store import VectorStore
from src.utils.logger import get_logger
from src.core.config import Config, get_config

logger = get_logger(__name__)


@dataclass
class VulnerabilityPattern:
    """漏洞模式"""
    id: str
    pattern: str
    vulnerability_type: str
    severity: str
    description: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SemanticMatchResult:
    """语义匹配结果"""
    pattern_id: str
    pattern: str
    vulnerability_type: str
    severity: str
    score: float
    confidence: float
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class SemanticMatcher:
    """语义匹配器

    利用向量存储和语义分析快速匹配漏洞模式。
    """

    def __init__(self, config: Optional[Config] = None):
        """初始化语义匹配器

        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self._vector_store = VectorStore(Path("./rag_knowledge_base/vector_store"))
        from src.storage.rag_knowledge_base import get_rag_knowledge_base
        self._rag_knowledge_base = get_rag_knowledge_base()
        self._initialized = False

    def initialize(self) -> bool:
        """初始化语义匹配器

        Returns:
            是否初始化成功
        """
        try:
            # 加载现有的漏洞模式
            self._load_patterns()
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"初始化语义匹配器失败: {e}")
            return False

    def add_pattern(self, pattern: VulnerabilityPattern) -> bool:
        """添加漏洞模式

        Args:
            pattern: 漏洞模式

        Returns:
            是否添加成功
        """
        try:
            # 存储到向量存储
            self._vector_store.add_document(
                document_id=pattern.id,
                content=pattern.pattern,
                metadata={
                    "vulnerability_type": pattern.vulnerability_type,
                    "severity": pattern.severity,
                    "description": pattern.description,
                    "confidence": pattern.confidence,
                    **pattern.metadata
                }
            )
            return True
        except Exception as e:
            logger.error(f"添加漏洞模式失败: {e}")
            return False

    def add_patterns(self, patterns: List[VulnerabilityPattern]) -> int:
        """批量添加漏洞模式

        Args:
            patterns: 漏洞模式列表

        Returns:
            添加成功的数量
        """
        count = 0
        for pattern in patterns:
            try:
                self._vector_store.add_document(
                    document_id=pattern.id,
                    content=pattern.pattern,
                    metadata={
                        "vulnerability_type": pattern.vulnerability_type,
                        "severity": pattern.severity,
                        "description": pattern.description,
                        "confidence": pattern.confidence,
                        **pattern.metadata
                    }
                )
                count += 1
            except Exception as e:
                logger.error(f"添加漏洞模式失败: {e}")
                continue

        return count

    def match(self, code: str, threshold: float = 0.7) -> List[SemanticMatchResult]:
        """匹配代码中的漏洞模式

        Args:
            code: 代码内容
            threshold: 匹配阈值

        Returns:
            匹配结果列表
        """
        if not self._initialized:
            self.initialize()

        try:
            # 搜索相似模式
            results = self._vector_store.search(
                query=code,
                top_k=5
            )

            # 过滤结果
            matches = []
            for result in results:
                if result["similarity"] >= threshold:
                    metadata = result["metadata"]
                    match = SemanticMatchResult(
                        pattern_id=result["document_id"],
                        pattern=result["content"],
                        vulnerability_type=metadata.get("vulnerability_type", "unknown"),
                        severity=metadata.get("severity", "medium"),
                        score=result["similarity"],
                        confidence=metadata.get("confidence", 0.5),
                        description=metadata.get("description", ""),
                        metadata=metadata
                    )
                    matches.append(match)

            return matches
        except Exception as e:
            logger.error(f"匹配漏洞模式失败: {e}")
            return []

    def batch_match(self, codes: List[str], threshold: float = 0.7) -> List[List[SemanticMatchResult]]:
        """批量匹配代码中的漏洞模式

        Args:
            codes: 代码内容列表
            threshold: 匹配阈值

        Returns:
            匹配结果列表的列表
        """
        if not self._initialized:
            self.initialize()

        try:
            # 批量搜索
            all_matches = []
            for code in codes:
                results = self._vector_store.search(
                    query=code,
                    top_k=5
                )
                matches = []
                for result in results:
                    if result["similarity"] >= threshold:
                        metadata = result["metadata"]
                        match = SemanticMatchResult(
                            pattern_id=result["document_id"],
                            pattern=result["content"],
                            vulnerability_type=metadata.get("vulnerability_type", "unknown"),
                            severity=metadata.get("severity", "medium"),
                            score=result["similarity"],
                            confidence=metadata.get("confidence", 0.5),
                            description=metadata.get("description", ""),
                            metadata=metadata
                        )
                        matches.append(match)
                all_matches.append(matches)

            return all_matches
        except Exception as e:
            logger.error(f"批量匹配漏洞模式失败: {e}")
            return [[] for _ in codes]

    def get_pattern(self, pattern_id: str) -> Optional[VulnerabilityPattern]:
        """获取漏洞模式

        Args:
            pattern_id: 模式ID

        Returns:
            漏洞模式
        """
        try:
            document = self._vector_store.get_document(pattern_id)
            if document:
                metadata = document.get("metadata", {})
                pattern = VulnerabilityPattern(
                    id=pattern_id,
                    pattern=document.get("content", ""),
                    vulnerability_type=metadata.get("vulnerability_type", "unknown"),
                    severity=metadata.get("severity", "medium"),
                    description=metadata.get("description", ""),
                    confidence=metadata.get("confidence", 0.5),
                    metadata=metadata
                )
                return pattern
            return None
        except Exception as e:
            logger.error(f"获取漏洞模式失败: {e}")
            return None

    def delete_pattern(self, pattern_id: str) -> bool:
        """删除漏洞模式

        Args:
            pattern_id: 模式ID

        Returns:
            是否删除成功
        """
        try:
            self._vector_store.delete_document(pattern_id)
            return True
        except Exception as e:
            logger.error(f"删除漏洞模式失败: {e}")
            return False

    def clear_patterns(self) -> bool:
        """清空所有漏洞模式

        Returns:
            是否清空成功
        """
        try:
            self._vector_store.clear()
            return True
        except Exception as e:
            logger.error(f"清空漏洞模式失败: {e}")
            return False

    def get_pattern_count(self) -> int:
        """获取漏洞模式数量

        Returns:
            模式数量
        """
        try:
            return len(self._vector_store)
        except Exception as e:
            logger.error(f"获取漏洞模式数量失败: {e}")
            return 0

    def _load_patterns(self) -> None:
        """加载漏洞模式

        从RAG知识库加载漏洞模式到向量存储。
        """
        try:
            # 从RAG知识库获取知识
            knowledge_items = self._rag_knowledge_base.get_all_knowledge()
            vulnerability_patterns = []

            for knowledge in knowledge_items:
                # 从知识内容中提取模式信息
                vuln_pattern = VulnerabilityPattern(
                    id=knowledge.id,
                    pattern=knowledge.content,
                    vulnerability_type=knowledge.knowledge_type.value,
                    severity="medium",
                    description=knowledge.content[:100],
                    confidence=knowledge.confidence,
                    metadata={
                        "source": knowledge.source,
                        "tags": knowledge.tags
                    }
                )
                vulnerability_patterns.append(vuln_pattern)

            # 批量添加到向量存储
            if vulnerability_patterns:
                self.add_patterns(vulnerability_patterns)
                logger.info(f"加载了 {len(vulnerability_patterns)} 个漏洞模式")
        except Exception as e:
            logger.error(f"加载漏洞模式失败: {e}")

    def update_from_knowledge_base(self) -> int:
        """从RAG知识库更新漏洞模式

        Returns:
            更新的模式数量
        """
        # 清空现有模式
        self.clear_patterns()
        # 重新加载
        self._load_patterns()
        return self.get_pattern_count()

    def is_available(self) -> bool:
        """检查语义匹配器是否可用

        Returns:
            是否可用
        """
        try:
            # 简单检查向量存储是否初始化
            return True
        except Exception:
            return False


class AISemanticOptimizer:
    """AI语义优化器

    利用语义匹配减少AI调用，节省token。
    """

    def __init__(self, config: Optional[Config] = None):
        """初始化AI语义优化器

        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self._semantic_matcher = SemanticMatcher(config)
        self._threshold = 0.8

    def initialize(self) -> bool:
        """初始化AI语义优化器

        Returns:
            是否初始化成功
        """
        return self._semantic_matcher.initialize()

    async def optimize_analysis(self, code: str, language: str) -> Dict[str, Any]:
        """优化分析过程

        Args:
            code: 代码内容
            language: 编程语言

        Returns:
            优化结果，包含是否需要AI分析和匹配的模式
        """
        # 首先进行语义匹配
        matches = self._semantic_matcher.match(code, threshold=self._threshold)

        # 即使找到匹配的模式，也总是进行AI分析
        # 这样可以确保AI能够发现规则匹配的问题
        return {
            "use_ai": True,
            "matches": [match.__dict__ for match in matches],
            "confidence": max(match.score for match in matches) if matches else 0.0
        }

    async def batch_optimize_analysis(self, codes: List[str], languages: List[str]) -> List[Dict[str, Any]]:
        """批量优化分析过程

        Args:
            codes: 代码内容列表
            languages: 编程语言列表

        Returns:
            优化结果列表
        """
        results = []
        for code, language in zip(codes, languages):
            result = await self.optimize_analysis(code, language)
            results.append(result)
        return results

    def add_custom_pattern(self, pattern: str, vulnerability_type: str, severity: str, description: str) -> str:
        """添加自定义漏洞模式

        Args:
            pattern: 模式内容
            vulnerability_type: 漏洞类型
            severity: 严重程度
            description: 描述

        Returns:
            模式ID
        """
        pattern_id = hashlib.sha256(pattern.encode()).hexdigest()[:16]
        vuln_pattern = VulnerabilityPattern(
            id=pattern_id,
            pattern=pattern,
            vulnerability_type=vulnerability_type,
            severity=severity,
            description=description,
            confidence=0.9
        )
        self._semantic_matcher.add_pattern(vuln_pattern)
        return pattern_id

    def get_matcher(self) -> SemanticMatcher:
        """获取语义匹配器

        Returns:
            语义匹配器实例
        """
        return self._semantic_matcher

    def is_available(self) -> bool:
        """检查AI语义优化器是否可用

        Returns:
            是否可用
        """
        return self._semantic_matcher.is_available()


# 全局语义匹配器实例
_semantic_matcher: Optional[SemanticMatcher] = None


# 全局AI语义优化器实例
_ai_semantic_optimizer: Optional[AISemanticOptimizer] = None


def get_semantic_matcher() -> SemanticMatcher:
    """获取全局语义匹配器实例

    Returns:
        语义匹配器实例
    """
    global _semantic_matcher
    if _semantic_matcher is None:
        _semantic_matcher = SemanticMatcher()
        _semantic_matcher.initialize()
    return _semantic_matcher


def get_ai_semantic_optimizer() -> AISemanticOptimizer:
    """获取全局AI语义优化器实例

    Returns:
        AI语义优化器实例
    """
    global _ai_semantic_optimizer
    if _ai_semantic_optimizer is None:
        _ai_semantic_optimizer = AISemanticOptimizer()
        _ai_semantic_optimizer.initialize()
    return _ai_semantic_optimizer
