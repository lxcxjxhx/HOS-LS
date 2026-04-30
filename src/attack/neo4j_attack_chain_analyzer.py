"""Neo4j 攻击链分析器

基于 Neo4j 图数据库实现攻击链查询和分析。
"""

from typing import Dict, List, Optional, Any

from src.db import get_neo4j_manager


class Neo4jAttackChainAnalyzer:
    """Neo4j 攻击链分析器

    使用 Neo4j 图数据库分析攻击链。
    """

    def __init__(self):
        """初始化攻击链分析器"""
        self._neo4j_manager = get_neo4j_manager()

    def find_rce_chains(self, limit: int = 10) -> List[Dict[str, Any]]:
        """查找 RCE 攻击链

        Args:
            limit: 返回数量限制

        Returns:
            RCE 攻击链列表
        """
        query = """
        MATCH path = (source:Source)-[:TRIGGERS]->(sink:Sink)<-[:HAS_SINK]-(cve:CVE)
        WHERE sink.type IN ['eval', 'exec', 'system', 'subprocess']
        RETURN path
        LIMIT $limit
        """

        return self._neo4j_manager.execute_cypher(query, {"limit": limit})

    def find_sql_injection_chains(self, limit: int = 10) -> List[Dict[str, Any]]:
        """查找 SQL 注入攻击链

        Args:
            limit: 返回数量限制

        Returns:
            SQL 注入攻击链列表
        """
        query = """
        MATCH path = (source:Source)-[:TRIGGERS]->(sink:Sink)<-[:HAS_SINK]-(cve:CVE)
        WHERE sink.type IN ['sql', 'database']
        RETURN path
        LIMIT $limit
        """

        return self._neo4j_manager.execute_cypher(query, {"limit": limit})

    def find_xss_chains(self, limit: int = 10) -> List[Dict[str, Any]]:
        """查找 XSS 攻击链

        Args:
            limit: 返回数量限制

        Returns:
            XSS 攻击链列表
        """
        query = """
        MATCH path = (source:Source)-[:TRIGGERS]->(sink:Sink)<-[:HAS_SINK]-(cve:CVE)
        WHERE sink.type IN ['xss', 'html', 'javascript']
        RETURN path
        LIMIT $limit
        """

        return self._neo4j_manager.execute_cypher(query, {"limit": limit})

    def find_attack_chains_by_sink_type(self, sink_types: List[str], limit: int = 10) -> List[Dict[str, Any]]:
        """根据 sink 类型查找攻击链

        Args:
            sink_types: sink 类型列表
            limit: 返回数量限制

        Returns:
            攻击链列表
        """
        query = """
        MATCH path = (source:Source)-[:TRIGGERS]->(sink:Sink)<-[:HAS_SINK]-(cve:CVE)
        WHERE sink.type IN $sink_types
        RETURN path
        LIMIT $limit
        """

        return self._neo4j_manager.execute_cypher(query, {"sink_types": sink_types, "limit": limit})

    def find_attack_chains_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """查找与特定 CVE 相关的攻击链

        Args:
            cve_id: CVE ID

        Returns:
            攻击链列表
        """
        query = """
        MATCH path = (source:Source)-[:TRIGGERS]->(sink:Sink)<-[:HAS_SINK]-(cve:CVE {id: $cve_id})
        RETURN path
        """

        return self._neo4j_manager.execute_cypher(query, {"cve_id": cve_id})

    def find_attack_chains_by_product(self, product_name: str, limit: int = 10) -> List[Dict[str, Any]]:
        """查找影响特定产品的攻击链

        Args:
            product_name: 产品名称
            limit: 返回数量限制

        Returns:
            攻击链列表
        """
        query = """
        MATCH path = (source:Source)-[:TRIGGERS]->(sink:Sink)<-[:HAS_SINK]-(cve:CVE)-[:AFFECTS]->(product:Product {name: $product_name})
        RETURN path
        LIMIT $limit
        """

        return self._neo4j_manager.execute_cypher(query, {"product_name": product_name, "limit": limit})

    def analyze_attack_chain_risk(self, chain: Dict[str, Any]) -> float:
        """分析攻击链风险评分

        Args:
            chain: 攻击链数据

        Returns:
            风险评分 (0-10)
        """
        # 简单的风险评分算法
        # 基于 sink 类型和 CVE 严重性
        risk_score = 0.0

        # 解析攻击链数据
        # 这里需要根据实际的返回格式进行调整
        # 暂时返回默认值
        return risk_score

    def get_attack_chain_statistics(self) -> Dict[str, Any]:
        """获取攻击链统计信息

        Returns:
            统计信息
        """
        # 统计不同类型的攻击链数量
        rce_count = len(self.find_rce_chains(limit=1000))
        sql_count = len(self.find_sql_injection_chains(limit=1000))
        xss_count = len(self.find_xss_chains(limit=1000))

        return {
            "rce_chains": rce_count,
            "sql_injection_chains": sql_count,
            "xss_chains": xss_count,
            "total_chains": rce_count + sql_count + xss_count
        }

    def export_attack_chains(self, chain_type: str = "all", file_path: str = "attack_chains.json") -> bool:
        """导出攻击链到文件

        Args:
            chain_type: 攻击链类型 (all, rce, sql, xss)
            file_path: 文件路径

        Returns:
            是否成功
        """
        try:
            import json

            chains = []
            if chain_type == "all" or chain_type == "rce":
                chains.extend(self.find_rce_chains(limit=100))
            if chain_type == "all" or chain_type == "sql":
                chains.extend(self.find_sql_injection_chains(limit=100))
            if chain_type == "all" or chain_type == "xss":
                chains.extend(self.find_xss_chains(limit=100))

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(chains, f, indent=2, ensure_ascii=False)

            return True
        except Exception:
            return False
