"""图检索模块

负责 Graph + Vector 混合检索、图遍历、子图构建和漏洞链推理。
"""

from typing import Dict, List, Optional, Any, Tuple

from src.db.neo4j_connection import get_neo4j_manager
from src.storage.vector_store import VectorStore
from src.storage.faiss_vector_store import FAISSVectorStore


class GraphRetriever:
    """图检索器

    负责 Graph + Vector 混合检索、图遍历、子图构建和漏洞链推理。
    """

    def __init__(self, vector_store: Optional[VectorStore] = None):
        # 确保 Neo4j 100% 可用
        self._neo4j_manager = get_neo4j_manager()
        self._neo4j_available = True
        if vector_store:
            self._vector_store = vector_store
        else:
            from pathlib import Path
            storage_path = Path(".") / "vector_store"
            self._vector_store = FAISSVectorStore(storage_path)
        self._cache: Dict[str, Any] = {}

    def hybrid_retrieve(self, query: str, top_k: int = 5, k_hop: int = 2) -> List[Dict[str, Any]]:
        """混合检索

        Args:
            query: 查询文本
            top_k: 向量召回数量
            k_hop: 图遍历深度

        Returns:
            检索结果
        """
        # 步骤 1: 向量召回
        vector_results = self._vector_retrieve(query, top_k)

        # 步骤 2: 图扩展
        graph_results = self._graph_expand(vector_results, k_hop)

        # 步骤 3: 子图构建
        subgraph = self._build_subgraph(graph_results)

        # 步骤 4: 推理
        reasoning_results = self._reasoning(subgraph)

        return reasoning_results

    def _vector_retrieve(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """向量召回

        Args:
            query: 查询文本
            top_k: 召回数量

        Returns:
            向量召回结果
        """
        # 使用向量存储进行召回
        results = self._vector_store.search(query, top_k)

        # 转换为统一格式
        vector_results = []
        for result in results:
            vector_results.append({
                "id": result.get("id"),
                "content": result.get("content"),
                "score": result.get("score"),
                "type": "vector"
            })

        # 同时使用 Neo4j 的向量搜索
        neo4j_results = self._neo4j_manager.rag_query(query, top_k)
        for result in neo4j_results:
            vector_results.append({
                "id": result.get("cve_id"),
                "content": result.get("description"),
                "score": result.get("similarity"),
                "type": "neo4j"
            })

        # 按分数排序并返回前 top_k 个
        vector_results.sort(key=lambda x: x.get("score", 0), reverse=True)
        return vector_results[:top_k]

    def _graph_expand(self, vector_results: List[Dict[str, Any]], k_hop: int = 2) -> List[Dict[str, Any]]:
        """图扩展

        Args:
            vector_results: 向量召回结果
            k_hop: 图遍历深度

        Returns:
            图扩展结果
        """
        graph_results = []

        for result in vector_results:
            node_id = result.get("id")
            if not node_id:
                continue

            # 执行图遍历
            paths = self._traverse_graph(node_id, k_hop)
            graph_results.extend(paths)

        return graph_results

    def _traverse_graph(self, node_id: str, k_hop: int = 2) -> List[Dict[str, Any]]:
        """图遍历

        Args:
            node_id: 起始节点 ID
            k_hop: 遍历深度

        Returns:
            遍历结果
        """
        query = f"""
        MATCH path = (n {{id: $node_id}})-[*1..{k_hop}]->(m)
        RETURN path
        LIMIT 10
        """
        result = self._neo4j_manager.execute_cypher(query, {"node_id": node_id})
        return result

    def _build_subgraph(self, graph_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """构建子图

        Args:
            graph_results: 图扩展结果

        Returns:
            子图
        """
        nodes = set()
        edges = []

        for result in graph_results:
            # 解析路径，提取节点和边
            # 注意：实际实现需要根据 Neo4j 返回的路径格式进行解析
            # 这里简化处理
            pass

        return {
            "nodes": list(nodes),
            "edges": edges
        }

    def _reasoning(self, subgraph: Dict[str, Any]) -> List[Dict[str, Any]]:
        """推理

        Args:
            subgraph: 子图

        Returns:
            推理结果
        """
        # 检查是否形成完整漏洞链
        attack_chains = self._find_attack_chains()
        return attack_chains

    def find_attack_chains(self, sink_types: List[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """查找攻击链

        Args:
            sink_types: 危险点类型列表
            limit: 返回数量限制

        Returns:
            攻击链列表
        """
        return self._neo4j_manager.find_attack_chains(sink_types)

    def find_vulnerability_paths(self, source_id: str, max_depth: int = 5) -> List[Dict[str, Any]]:
        """查找漏洞路径

        Args:
            source_id: 源节点 ID
            max_depth: 最大深度

        Returns:
            漏洞路径列表
        """
        query = f"""
        MATCH path = (s {{id: $source_id}})-[*1..{max_depth}]->(v:Vulnerability)
        RETURN path
        LIMIT 10
        """
        result = self._neo4j_manager.execute_cypher(
            query, 
            {"source_id": source_id}
        )
        return result

    def get_vulnerability_context(self, vulnerability_id: str, k_hop: int = 2) -> Dict[str, Any]:
        """获取漏洞上下文

        Args:
            vulnerability_id: 漏洞 ID
            k_hop: 图遍历深度

        Returns:
            漏洞上下文
        """
        # 检查缓存
        cache_key = f"vuln_context_{vulnerability_id}_{k_hop}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # 构建查询
        query = f"""
        MATCH (v {{id: $vulnerability_id}})
        CALL apoc.path.expand(v, "*", "", 1, {k_hop})
        YIELD path
        RETURN path
        """

        try:
            result = self._neo4j_manager.execute_cypher(
                query, 
                {"vulnerability_id": vulnerability_id}
            )
        except Exception:
            # 如果 APOC 不可用，使用普通查询
            query = f"""
            MATCH path = (v {{id: $vulnerability_id}})-[*1..{k_hop}]->(n)
            RETURN path
            LIMIT 10
            """
            result = self._neo4j_manager.execute_cypher(
                query, 
                {"vulnerability_id": vulnerability_id}
            )

        # 构建上下文
        context = {
            "vulnerability_id": vulnerability_id,
            "paths": result,
            "context_size": len(result)
        }

        # 缓存结果
        self._cache[cache_key] = context
        return context

    def rank_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """排序结果

        Args:
            results: 检索结果

        Returns:
            排序后的结果
        """
        # 基于多个因素排序：
        # 1. 分数（相似度）
        # 2. 路径长度（越短越相关）
        # 3. 漏洞严重程度

        def rank_score(result):
            score = 0.0

            # 相似度分数
            if "score" in result:
                score += result["score"] * 0.5

            # 路径长度（假设结果中包含路径信息）
            if "path" in result:
                path_length = len(result["path"]) if isinstance(result["path"], list) else 0
                score += (1.0 / (path_length + 1)) * 0.3

            # 漏洞严重程度
            if "severity" in result:
                severity_score = {
                    "critical": 1.0,
                    "high": 0.8,
                    "medium": 0.6,
                    "low": 0.4,
                    "info": 0.2
                }.get(result["severity"], 0.0)
                score += severity_score * 0.2

            return score

        results.sort(key=rank_score, reverse=True)
        return results

    def get_similar_vulnerabilities(self, vulnerability_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """获取相似漏洞

        Args:
            vulnerability_id: 漏洞 ID
            limit: 返回数量限制

        Returns:
            相似漏洞列表
        """
        # 检查是否为 CVE ID
        if vulnerability_id.startswith("CVE-"):
            return self._neo4j_manager.find_similar_cves(vulnerability_id, limit)

        # 对于普通漏洞，使用向量搜索
        # 这里简化处理，实际需要根据漏洞信息构建查询
        return []

    def generate_attack_chain(self, cve_id: str) -> Dict[str, Any]:
        """生成攻击链

        Args:
            cve_id: CVE ID

        Returns:
            攻击链信息
        """
        return self._neo4j_manager.generate_attack_chain(cve_id)

    def clear_cache(self) -> None:
        """清空缓存"""
        self._cache.clear()

    def close(self) -> None:
        """关闭连接"""
        if self._neo4j_manager:
            self._neo4j_manager.close()
        if self._vector_store:
            self._vector_store.close()
