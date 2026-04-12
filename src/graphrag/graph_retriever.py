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
            storage_path = Path(".") / "rag_knowledge_base" / "vector_store"
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
        nodes = {}
        edges = []

        for result in graph_results:
            # 解析路径，提取节点和边
            # 这里假设 Neo4j 返回的是路径对象，实际实现需要根据具体格式调整
            # 简化处理：从结果中提取节点和边信息
            if isinstance(result, dict):
                # 处理路径信息
                if 'path' in result:
                    path = result['path']
                    # 假设 path 包含 nodes 和 relationships
                    if hasattr(path, 'nodes'):
                        for node in path.nodes:
                            node_id = getattr(node, 'id', str(id(node)))
                            nodes[node_id] = {
                                'id': node_id,
                                'labels': getattr(node, 'labels', []),
                                'properties': dict(node)
                            }
                    if hasattr(path, 'relationships'):
                        for rel in path.relationships:
                            edges.append({
                                'source': getattr(rel, 'start_node', {}).get('id', ''),
                                'target': getattr(rel, 'end_node', {}).get('id', ''),
                                'type': getattr(rel, 'type', ''),
                                'properties': dict(rel)
                            })

        return {
            "nodes": list(nodes.values()),
            "edges": edges
        }

    def _reasoning(self, subgraph: Dict[str, Any]) -> List[Dict[str, Any]]:
        """推理

        Args:
            subgraph: 子图

        Returns:
            推理结果
        """
        reasoning_results = []

        # 1. 分析子图中的节点和边
        nodes = subgraph.get('nodes', [])
        edges = subgraph.get('edges', [])

        # 2. 识别潜在的攻击路径
        attack_paths = self._identify_attack_paths(nodes, edges)
        reasoning_results.extend(attack_paths)

        # 3. 执行多跳推理链
        multi_hop_results = self._execute_multi_hop_reasoning(nodes, edges)
        reasoning_results.extend(multi_hop_results)

        # 4. 识别漏洞模式
        vulnerability_patterns = self._identify_vulnerability_patterns(nodes, edges)
        reasoning_results.extend(vulnerability_patterns)

        # 5. 排序结果
        return self.rank_results(reasoning_results)

    def _identify_attack_paths(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """识别攻击路径

        Args:
            nodes: 节点列表
            edges: 边列表

        Returns:
            攻击路径列表
        """
        attack_paths = []

        # 构建节点映射
        node_map = {node['id']: node for node in nodes}

        # 构建边映射
        edge_map = {}
        for edge in edges:
            source = edge['source']
            if source not in edge_map:
                edge_map[source] = []
            edge_map[source].append(edge)

        # 寻找从 Source 到 Vulnerability 的路径
        for node in nodes:
            if 'Source' in node.get('labels', []):
                paths = self._find_paths_from_source(node['id'], node_map, edge_map)
                attack_paths.extend(paths)

        return attack_paths

    def _find_paths_from_source(self, source_id: str, node_map: Dict[str, Dict[str, Any]], edge_map: Dict[str, List[Dict[str, Any]]], current_path: List[str] = None, visited: set = None) -> List[Dict[str, Any]]:
        """从源节点寻找路径

        Args:
            source_id: 源节点 ID
            node_map: 节点映射
            edge_map: 边映射
            current_path: 当前路径
            visited: 已访问节点

        Returns:
            路径列表
        """
        if current_path is None:
            current_path = [source_id]
        if visited is None:
            visited = set([source_id])

        paths = []

        # 检查当前节点是否是漏洞节点
        current_node = node_map.get(source_id)
        if current_node and 'Vulnerability' in current_node.get('labels', []):
            # 找到完整路径
            paths.append({
                'path': current_path.copy(),
                'type': 'attack_path',
                'severity': current_node.get('properties', {}).get('severity', 'medium'),
                'score': 1.0  # 完整攻击路径分数最高
            })

        # 继续遍历
        if source_id in edge_map:
            for edge in edge_map[source_id]:
                target_id = edge['target']
                if target_id not in visited:
                    new_path = current_path.copy()
                    new_path.append(target_id)
                    new_visited = visited.copy()
                    new_visited.add(target_id)
                    child_paths = self._find_paths_from_source(target_id, node_map, edge_map, new_path, new_visited)
                    paths.extend(child_paths)

        return paths

    def _execute_multi_hop_reasoning(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """执行多跳推理

        Args:
            nodes: 节点列表
            edges: 边列表

        Returns:
            推理结果
        """
        reasoning_results = []

        # 构建节点映射
        node_map = {node['id']: node for node in nodes}

        # 1. 推理漏洞之间的关系
        vulnerabilities = [node for node in nodes if 'Vulnerability' in node.get('labels', [])]
        for vuln in vulnerabilities:
            # 查找相关的其他漏洞
            related_vulns = self._find_related_vulnerabilities(vuln['id'], nodes, edges)
            if related_vulns:
                reasoning_results.append({
                    'type': 'multi_hop_reasoning',
                    'vulnerability': vuln['id'],
                    'related_vulnerabilities': related_vulns,
                    'reasoning': f"漏洞 {vuln['id']} 与其他 {len(related_vulns)} 个漏洞相关联，可能形成攻击链",
                    'score': 0.8
                })

        # 2. 推理攻击路径的可行性
        for node in nodes:
            if 'Source' in node.get('labels', []):
                # 分析从该源节点到漏洞的路径可行性
                paths = self._find_paths_from_source(node['id'], node_map, {edge['source']: [edge for edge in edges if edge['source'] == edge['source']] for edge in edges})
                for path in paths:
                    feasibility = self._evaluate_path_feasibility(path['path'], node_map, edges)
                    reasoning_results.append({
                        'type': 'path_feasibility',
                        'path': path['path'],
                        'feasibility': feasibility,
                        'reasoning': f"从 {node['id']} 到漏洞的路径可行性评估: {feasibility}",
                        'score': 0.7
                    })

        return reasoning_results

    def _find_related_vulnerabilities(self, vuln_id: str, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[str]:
        """查找相关漏洞

        Args:
            vuln_id: 漏洞 ID
            nodes: 节点列表
            edges: 边列表

        Returns:
            相关漏洞列表
        """
        related_vulns = []

        # 构建边映射
        edge_map = {}
        for edge in edges:
            source = edge['source']
            target = edge['target']
            if source not in edge_map:
                edge_map[source] = []
            edge_map[source].append(target)
            if target not in edge_map:
                edge_map[target] = []
            edge_map[target].append(source)  # 双向关系

        # 广度优先搜索查找相关漏洞
        visited = set()
        queue = [vuln_id]

        while queue:
            current_id = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)

            # 检查是否是漏洞节点
            current_node = next((node for node in nodes if node['id'] == current_id), None)
            if current_node and 'Vulnerability' in current_node.get('labels', []) and current_id != vuln_id:
                related_vulns.append(current_id)

            # 继续搜索
            if current_id in edge_map:
                for neighbor_id in edge_map[current_id]:
                    if neighbor_id not in visited:
                        queue.append(neighbor_id)

        return related_vulns

    def _evaluate_path_feasibility(self, path: List[str], node_map: Dict[str, Dict[str, Any]], edges: List[Dict[str, Any]]) -> str:
        """评估路径可行性

        Args:
            path: 路径节点 ID 列表
            node_map: 节点映射
            edges: 边列表

        Returns:
            可行性评估结果
        """
        # 简单的可行性评估逻辑
        # 1. 检查路径长度
        if len(path) > 5:
            return '低可行性（路径过长）'

        # 2. 检查路径中的节点类型
        node_types = []
        for node_id in path:
            node = node_map.get(node_id)
            if node:
                node_types.extend(node.get('labels', []))

        # 检查是否包含必要的节点类型
        if 'Source' in node_types and 'Sink' in node_types and 'Vulnerability' in node_types:
            return '高可行性（包含完整攻击链要素）'
        elif 'Source' in node_types and 'Sink' in node_types:
            return '中可行性（缺少漏洞节点）'
        else:
            return '低可行性（缺少关键要素）'

    def _identify_vulnerability_patterns(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """识别漏洞模式

        Args:
            nodes: 节点列表
            edges: 边列表

        Returns:
            漏洞模式列表
        """
        patterns = []

        # 构建节点映射
        node_map = {node['id']: node for node in nodes}

        # 1. 识别 SQL 注入模式
        sql_injection_patterns = self._identify_sql_injection_patterns(nodes, edges)
        patterns.extend(sql_injection_patterns)

        # 2. 识别 XSS 模式
        xss_patterns = self._identify_xss_patterns(nodes, edges)
        patterns.extend(xss_patterns)

        # 3. 识别命令注入模式
        command_injection_patterns = self._identify_command_injection_patterns(nodes, edges)
        patterns.extend(command_injection_patterns)

        return patterns

    def _identify_sql_injection_patterns(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """识别 SQL 注入模式

        Args:
            nodes: 节点列表
            edges: 边列表

        Returns:
            SQL 注入模式列表
        """
        patterns = []

        # 查找包含 SQL 相关 sink 的路径
        for node in nodes:
            if 'Sink' in node.get('labels', []):
                properties = node.get('properties', {})
                sink_name = properties.get('name', '').lower()
                if any(keyword in sink_name for keyword in ['sql', 'query', 'execute', 'prepare']):
                    # 查找指向该 sink 的路径
                    for edge in edges:
                        if edge['target'] == node['id'] and edge['type'] == 'TRIGGERS':
                            source_node = next((n for n in nodes if n['id'] == edge['source']), None)
                            if source_node:
                                patterns.append({
                                    'type': 'vulnerability_pattern',
                                    'pattern': 'SQL注入',
                                    'sink': node['id'],
                                    'source': edge['source'],
                                    'reasoning': f"检测到 SQL 注入模式：{source_node.get('properties', {}).get('name', 'Source')} → {sink_name}",
                                    'score': 0.9
                                })

        return patterns

    def _identify_xss_patterns(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """识别 XSS 模式

        Args:
            nodes: 节点列表
            edges: 边列表

        Returns:
            XSS 模式列表
        """
        patterns = []

        # 查找包含 XSS 相关 sink 的路径
        for node in nodes:
            if 'Sink' in node.get('labels', []):
                properties = node.get('properties', {})
                sink_type = properties.get('type', '').lower()
                if 'xss' in sink_type:
                    # 查找指向该 sink 的路径
                    for edge in edges:
                        if edge['target'] == node['id'] and edge['type'] == 'TRIGGERS':
                            source_node = next((n for n in nodes if n['id'] == edge['source']), None)
                            if source_node:
                                patterns.append({
                                    'type': 'vulnerability_pattern',
                                    'pattern': 'XSS',
                                    'sink': node['id'],
                                    'source': edge['source'],
                                    'reasoning': f"检测到 XSS 模式：{source_node.get('properties', {}).get('name', 'Source')} → {sink_type}",
                                    'score': 0.8
                                })

        return patterns

    def _identify_command_injection_patterns(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """识别命令注入模式

        Args:
            nodes: 节点列表
            edges: 边列表

        Returns:
            命令注入模式列表
        """
        patterns = []

        # 查找包含命令注入相关 sink 的路径
        for node in nodes:
            if 'Sink' in node.get('labels', []):
                properties = node.get('properties', {})
                sink_name = properties.get('name', '').lower()
                if any(keyword in sink_name for keyword in ['system', 'exec', 'shell', 'popen']):
                    # 查找指向该 sink 的路径
                    for edge in edges:
                        if edge['target'] == node['id'] and edge['type'] == 'TRIGGERS':
                            source_node = next((n for n in nodes if n['id'] == edge['source']), None)
                            if source_node:
                                patterns.append({
                                    'type': 'vulnerability_pattern',
                                    'pattern': '命令注入',
                                    'sink': node['id'],
                                    'source': edge['source'],
                                    'reasoning': f"检测到命令注入模式：{source_node.get('properties', {}).get('name', 'Source')} → {sink_name}",
                                    'score': 0.95
                                })

        return patterns

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
