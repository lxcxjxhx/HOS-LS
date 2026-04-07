"""Neo4j 连接模块

提供 Neo4j 图数据库连接管理功能，支持图模型操作和增量写入。
"""

from typing import Dict, List, Optional, Any

from neo4j import GraphDatabase
from neo4j_graphrag.generation import GraphRAG
from neo4j_graphrag.embeddings import OpenAIEmbeddings

from src.core.config import Config, get_config


class Neo4jManager:
    """Neo4j 管理器

    管理 Neo4j 数据库连接和图操作。
    """

    _instance: Optional["Neo4jManager"] = None
    _initialized: bool = False

    def __new__(cls) -> "Neo4jManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            self._config: Optional[Config] = None
            self._driver: Optional[GraphDatabase.driver] = None
            self._graphrag: Optional[GraphRAG] = None
            self._initialized = True

    def initialize(self, config: Optional[Config] = None) -> None:
        """初始化 Neo4j 连接

        Args:
            config: 配置对象
        """
        self._config = config or get_config()

        # 获取 Neo4j 配置
        neo4j_config = self._config.database.get("neo4j", {})
        uri = neo4j_config.get("uri", "bolt://localhost:7687")
        username = neo4j_config.get("username", "neo4j")
        password = neo4j_config.get("password", "password")

        # 创建驱动
        self._driver = GraphDatabase.driver(
            uri=uri,
            auth=(username, password)
        )

        # 测试连接
        self._test_connection()

        # 初始化 GraphRAG
        self._initialize_graphrag(uri, username, password)

    def _test_connection(self) -> None:
        """测试 Neo4j 连接"""
        if self._driver is None:
            raise RuntimeError("Neo4j 驱动未初始化")

        with self._driver.session() as session:
            session.run("RETURN 1")

    def _initialize_graphrag(self, uri: str, username: str, password: str) -> None:
        """初始化 GraphRAG

        Args:
            uri: Neo4j URI
            username: Neo4j 用户名
            password: Neo4j 密码
        """
        try:
            # 配置 OpenAI 嵌入
            openai_api_key = self._config.ai.get("api_key")
            if openai_api_key:
                embeddings = OpenAIEmbeddings(
                    model="text-embedding-3-small",
                    api_key=openai_api_key
                )
            else:
                # 使用默认嵌入
                embeddings = None

            # 初始化 GraphRAG
            self._graphrag = GraphRAG(
                neo4j_uri=uri,
                neo4j_username=username,
                neo4j_password=password,
                embeddings=embeddings
            )
        except Exception as e:
            print(f"GraphRAG 初始化失败: {e}")
            self._graphrag = None

    def close(self) -> None:
        """关闭 Neo4j 连接"""
        if self._driver:
            self._driver.close()
            self._driver = None

    def execute_cypher(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """执行 Cypher 查询

        Args:
            query: Cypher 查询语句
            parameters: 查询参数

        Returns:
            查询结果列表
        """
        if self._driver is None:
            raise RuntimeError("Neo4j 驱动未初始化")

        with self._driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

    def batch_write(self, queries: List[str], parameters_list: List[Dict[str, Any]]) -> None:
        """批量执行写入操作

        Args:
            queries: Cypher 查询语句列表
            parameters_list: 参数列表
        """
        if self._driver is None:
            raise RuntimeError("Neo4j 驱动未初始化")

        with self._driver.session() as session:
            for query, parameters in zip(queries, parameters_list):
                session.run(query, parameters)

    def batch_merge_cve(self, cves: List[Dict[str, Any]]) -> None:
        """批量合并 CVE 数据

        Args:
            cves: CVE 数据列表
        """
        if self._driver is None:
            raise RuntimeError("Neo4j 驱动未初始化")

        # 使用 UNWIND 批量写入，优化性能
        query = """
        UNWIND $batch AS cve
        MERGE (c:CVE {id: cve.cve_id})
        SET c.title = cve.title,
            c.description = cve.description,
            c.cvss = cve.cvss,
            c.source = cve.source,
            c.published_date = cve.published_date,
            c.embedding = CASE WHEN c.embedding IS NULL THEN 
                ai.embed(c.description, {model: 'text-embedding-3-small'})
            ELSE c.embedding END

        // 处理 CWE
        WITH c, cve
        WHERE cve.cwe IS NOT NULL AND cve.cwe <> ''
        MERGE (w:CWE {id: cve.cwe})
        SET w.name = cve.cwe
        MERGE (c)-[:BELONGS_TO]->(w)

        // 处理受影响产品
        WITH c, cve
        UNWIND cve.affected_products AS product
        MERGE (p:Product {name: product})
        MERGE (c)-[:AFFECTS]->(p)

        // 处理 Sink
        WITH c, cve
        UNWIND cve.sinks AS sink
        MERGE (s:Sink {type: sink})
        MERGE (c)-[:HAS_SINK]->(s)

        // 处理 Source
        WITH c, cve
        UNWIND cve.sources AS source
        MERGE (src:Source {type: source})
        MERGE (src)-[:TRIGGERS]->(s)

        // 创建相似性连接
        WITH c
        MATCH (other:CVE)
        WHERE other.id <> c.id
        WITH c, other, 
             gds.similarity.cosine(c.embedding, other.embedding) AS similarity
        WHERE similarity > 0.8
        MERGE (c)-[:SIMILAR_TO {score: similarity}]->(other)
        """

        with self._driver.session() as session:
            session.run(query, {"batch": cves})

    def find_attack_chains(self, sink_types: List[str] = None) -> List[Dict[str, Any]]:
        """查找攻击链

        Args:
            sink_types: 危险点类型列表

        Returns:
            攻击链列表
        """
        if sink_types is None:
            sink_types = ["eval", "exec", "sql"]

        query = """
        MATCH path = (source:Source)-[:TRIGGERS]->(sink:Sink)<-[:HAS_SINK]-(cve:CVE)
        WHERE sink.type IN $sink_types
        RETURN path
        LIMIT 10
        """

        return self.execute_cypher(query, {"sink_types": sink_types})

    def find_similar_cves(self, cve_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """查找相似 CVE

        Args:
            cve_id: CVE ID
            limit: 返回数量限制

        Returns:
            相似 CVE 列表
        """
        # 使用 ai.* 函数和向量相似度查找相似 CVE
        query = """
        MATCH (c1:CVE {id: $cve_id})
        MATCH (c2:CVE)
        WHERE c2.id <> c1.id
        WITH c1, c2, 
             gds.similarity.cosine(c1.embedding, c2.embedding) AS similarity
        ORDER BY similarity DESC
        RETURN c2.id AS cve_id, c2.title AS title, c2.description AS description, similarity
        LIMIT $limit
        """

        return self.execute_cypher(query, {"cve_id": cve_id, "limit": limit})

    def rag_query(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """使用 GraphRAG 进行查询

        Args:
            query: 查询文本
            limit: 返回数量限制

        Returns:
            查询结果列表
        """
        if self._graphrag:
            # 使用 GraphRAG 进行查询
            result = self._graphrag.query(
                query=query,
                limit=limit
            )
            return result
        else:
            # 使用 Cypher 进行向量搜索
            cypher_query = """
            WITH ai.embed($query, {model: 'text-embedding-3-small'}) AS query_embedding
            MATCH (c:CVE)
            WHERE c.embedding IS NOT NULL
            WITH c, gds.similarity.cosine(query_embedding, c.embedding) AS similarity
            ORDER BY similarity DESC
            RETURN c.id AS cve_id, c.title AS title, c.description AS description, similarity
            LIMIT $limit
            """
            return self.execute_cypher(cypher_query, {"query": query, "limit": limit})

    def generate_attack_chain(self, cve_id: str) -> Dict[str, Any]:
        """生成攻击链

        Args:
            cve_id: CVE ID

        Returns:
            攻击链信息
        """
        query = """
        MATCH (c:CVE {id: $cve_id})
        CALL ai.complete(
            'Generate attack chain for CVE ' + c.id + ': ' + c.description,
            {model: 'gpt-4o'}
        ) YIELD result
        RETURN c.id AS cve_id, result AS attack_chain
        """
        result = self.execute_cypher(query, {"cve_id": cve_id})
        return result[0] if result else {"cve_id": cve_id, "attack_chain": ""}

    @property
    def driver(self) -> Optional[GraphDatabase.driver]:
        """获取 Neo4j 驱动"""
        return self._driver


# 全局实例
_neo4j_manager: Optional[Neo4jManager] = None


def get_neo4j_manager(config: Optional[Config] = None) -> Neo4jManager:
    """获取 Neo4j 管理器实例

    Args:
        config: 配置对象

    Returns:
        Neo4j 管理器实例
    """
    global _neo4j_manager
    if _neo4j_manager is None:
        _neo4j_manager = Neo4jManager()
        _neo4j_manager.initialize(config)
    return _neo4j_manager
