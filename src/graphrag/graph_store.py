"""图存储模块

负责将构建好的图谱存储到 Neo4j 数据库中。
"""

from typing import Dict, List, Optional, Any

from src.db.neo4j_connection import get_neo4j_manager
from src.graphrag.graph_builder import GraphNode, GraphEdge


class GraphStore:
    """图存储

    负责将构建好的图谱存储到 Neo4j 数据库中。
    """

    def __init__(self):
        # 确保 Neo4j 100% 可用
        self._neo4j_manager = get_neo4j_manager()
        self._neo4j_available = True
        self._cache: Dict[str, Any] = {}

    def store_graph(self, nodes: List[GraphNode], edges: List[GraphEdge]) -> None:
        """存储图谱

        Args:
            nodes: 节点列表
            edges: 边列表
        """
        # 存储节点
        self._store_nodes(nodes)
        # 存储边
        self._store_edges(edges)
        # 清空缓存，因为图谱已更新
        self.clear_cache()

    def _store_nodes(self, nodes: List[GraphNode]) -> None:
        """存储节点

        Args:
            nodes: 节点列表
        """
        queries = []
        parameters_list = []

        for node in nodes:
            # 生成 MERGE 查询
            properties = node.properties
            # 确保 id 存在
            if "id" not in properties:
                properties["id"] = node.id

            # 构建参数
            parameters = {
                "node_id": node.id,
                "label": node.label,
                "properties": properties
            }

            # 构建查询
            query = f"""
            MERGE (n:{node.label} {{id: $node_id}})
            SET n += $properties
            """

            queries.append(query)
            parameters_list.append(parameters)

        # 批量执行
        if queries:
            self._neo4j_manager.batch_write(queries, parameters_list)

    def _store_edges(self, edges: List[GraphEdge]) -> None:
        """存储边

        Args:
            edges: 边列表
        """
        queries = []
        parameters_list = []

        for edge in edges:
            # 构建参数
            parameters = {
                "source_id": edge.source,
                "target_id": edge.target,
                "edge_type": edge.type,
                "properties": edge.properties
            }

            # 构建查询
            query = f"""
            MATCH (s {{id: $source_id}}), (t {{id: $target_id}})
            MERGE (s)-[r:{edge.type}]->(t)
            SET r += $properties
            """

            queries.append(query)
            parameters_list.append(parameters)

        # 批量执行
        if queries:
            self._neo4j_manager.batch_write(queries, parameters_list)

    def clear_graph(self) -> None:
        """清空图谱"""
        query = """
        MATCH (n)
        DETACH DELETE n
        """
        self._neo4j_manager.execute_cypher(query)

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """获取节点

        Args:
            node_id: 节点 ID

        Returns:
            节点信息
        """
        # 检查缓存
        cache_key = f"node_{node_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        query = """
        MATCH (n {{id: $node_id}})
        RETURN n
        """
        result = self._neo4j_manager.execute_cypher(query, {"node_id": node_id})

        if result:
            node_data = result[0].get("n", {})
            self._cache[cache_key] = node_data
            return node_data
        return None

    def get_nodes_by_label(self, label: str, limit: int = 100) -> List[Dict[str, Any]]:
        """根据标签获取节点

        Args:
            label: 节点标签
            limit: 返回数量限制

        Returns:
            节点列表
        """
        # 检查缓存
        cache_key = f"nodes_by_label_{label}_{limit}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        query = f"""
        MATCH (n:{label})
        RETURN n
        LIMIT $limit
        """
        result = self._neo4j_manager.execute_cypher(query, {"limit": limit})
        nodes = [record.get("n", {}) for record in result]

        # 缓存结果
        self._cache[cache_key] = nodes
        return nodes

    def get_nodes_by_ids(self, node_ids: List[str]) -> List[Dict[str, Any]]:
        """批量获取节点

        Args:
            node_ids: 节点 ID 列表

        Returns:
            节点列表
        """
        if not node_ids:
            return []

        # 构建参数
        parameters = {"node_ids": node_ids}

        # 构建查询
        query = """
        MATCH (n)
        WHERE n.id IN $node_ids
        RETURN n
        """

        result = self._neo4j_manager.execute_cypher(query, parameters)
        return [record.get("n", {}) for record in result]

    def find_nodes_by_property(self, label: str, property_name: str, property_value: Any, limit: int = 100) -> List[Dict[str, Any]]:
        """根据属性查询节点

        Args:
            label: 节点标签
            property_name: 属性名
            property_value: 属性值
            limit: 返回数量限制

        Returns:
            节点列表
        """
        # 构建参数
        parameters = {
            "property_value": property_value,
            "limit": limit
        }

        # 构建查询
        query = f"""
        MATCH (n:{label})
        WHERE n.{property_name} = $property_value
        RETURN n
        LIMIT $limit
        """

        result = self._neo4j_manager.execute_cypher(query, parameters)
        return [record.get("n", {}) for record in result]

    def get_edges(self, node_id: str, edge_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取节点的边

        Args:
            node_id: 节点 ID
            edge_type: 边类型

        Returns:
            边列表
        """
        if edge_type:
            query = f"""
            MATCH (s {{id: $node_id}})-[r:{edge_type}]->(t)
            RETURN r, t
            """
        else:
            query = """
            MATCH (s {{id: $node_id}})-[r]->(t)
            RETURN r, t
            """

        result = self._neo4j_manager.execute_cypher(query, {"node_id": node_id})
        edges = []
        for record in result:
            edge = record.get("r", {})
            target = record.get("t", {})
            edges.append({
                "type": type(edge).__name__,  # 边类型
                "properties": dict(edge),  # 边属性
                "target": target  # 目标节点
            })
        return edges

    def find_paths(self, source_id: str, target_id: str, max_depth: int = 5) -> List[Dict[str, Any]]:
        """查找路径

        Args:
            source_id: 源节点 ID
            target_id: 目标节点 ID
            max_depth: 最大深度

        Returns:
            路径列表
        """
        # 构建带深度的查询
        query = f"""
        MATCH path = (s {{id: $source_id}})-[*1..{max_depth}]->(t {{id: $target_id}})
        RETURN path
        LIMIT 10
        """
        result = self._neo4j_manager.execute_cypher(
            query, 
            {"source_id": source_id, "target_id": target_id}
        )
        return result

    def find_attack_chains(self, sink_types: List[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """查找攻击链

        Args:
            sink_types: 危险点类型列表
            limit: 返回数量限制

        Returns:
            攻击链列表
        """
        if sink_types is None:
            sink_types = ["eval", "exec", "sql", "system"]

        query = """
        MATCH path = (source:Source)-[:TAINT_FLOW]->(sink:Sink)-[:CAUSES]->(vuln:Vulnerability)
        WHERE sink.name IN $sink_types
        RETURN path
        LIMIT $limit
        """
        result = self._neo4j_manager.execute_cypher(
            query, 
            {"sink_types": sink_types, "limit": limit}
        )
        return result

    def find_vulnerabilities(self, severity: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """查找漏洞

        Args:
            severity: 严重程度
            limit: 返回数量限制

        Returns:
            漏洞列表
        """
        if severity:
            query = """
            MATCH (v:Vulnerability)
            WHERE v.severity = $severity
            RETURN v
            LIMIT $limit
            """
            result = self._neo4j_manager.execute_cypher(
                query, 
                {"severity": severity, "limit": limit}
            )
        else:
            query = """
            MATCH (v:Vulnerability)
            RETURN v
            LIMIT $limit
            """
            result = self._neo4j_manager.execute_cypher(
                query, 
                {"limit": limit}
            )

        return [record.get("v", {}) for record in result]

    def get_graph_statistics(self) -> Dict[str, Any]:
        """获取图谱统计信息

        Returns:
            统计信息
        """
        # 检查缓存
        cache_key = "graph_statistics"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # 统计节点数量
        node_count_query = """
        MATCH (n)
        RETURN count(n) AS total_nodes
        """
        node_count_result = self._neo4j_manager.execute_cypher(node_count_query)
        total_nodes = node_count_result[0].get("total_nodes", 0)

        # 统计边数量
        edge_count_query = """
        MATCH ()-[r]->()
        RETURN count(r) AS total_edges
        """
        edge_count_result = self._neo4j_manager.execute_cypher(edge_count_query)
        total_edges = edge_count_result[0].get("total_edges", 0)

        # 统计节点类型
        node_types_query = """
        MATCH (n)
        RETURN labels(n)[0] AS label, count(n) AS count
        """
        node_types_result = self._neo4j_manager.execute_cypher(node_types_query)
        node_counts = {}
        for record in node_types_result:
            label = record.get("label", "Unknown")
            count = record.get("count", 0)
            node_counts[label] = count

        # 统计边类型
        edge_types_query = """
        MATCH ()-[r]->()
        RETURN type(r) AS type, count(r) AS count
        """
        edge_types_result = self._neo4j_manager.execute_cypher(edge_types_query)
        edge_counts = {}
        for record in edge_types_result:
            edge_type = record.get("type", "Unknown")
            count = record.get("count", 0)
            edge_counts[edge_type] = count

        statistics = {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "node_counts": node_counts,
            "edge_counts": edge_counts
        }

        # 缓存结果
        self._cache[cache_key] = statistics
        return statistics

    def clear_cache(self) -> None:
        """清空缓存"""
        self._cache.clear()

    def close(self) -> None:
        """关闭连接"""
        if self._neo4j_manager:
            self._neo4j_manager.close()
