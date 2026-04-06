"""RAG + 图融合集成模块

集成 RAG、Neo4j 图数据库和 GPU 加速功能。
"""

from typing import Dict, List, Optional, Any
from pathlib import Path

from src.db import get_neo4j_manager
from src.storage import FAISSVectorStore, EmbedConfig, ModelType
from src.attack.neo4j_attack_chain_analyzer import Neo4jAttackChainAnalyzer
from src.utils.logger import get_logger

logger = get_logger(__name__)


class RAGGraphIntegrator:
    """RAG + 图融合集成器

    集成 RAG、Neo4j 图数据库和 GPU 加速功能。
    """

    def __init__(self, vector_store_path: Optional[Path] = None):
        """初始化 RAG + 图融合集成器

        Args:
            vector_store_path: 向量存储路径
        """
        # 初始化 Neo4j 管理器
        self._neo4j_manager = get_neo4j_manager()
        
        # 初始化攻击链分析器
        self._attack_chain_analyzer = Neo4jAttackChainAnalyzer()
        
        # 初始化向量存储
        self._vector_store = None
        if vector_store_path:
            embed_config = EmbedConfig(
                model_name=ModelType.BGE_SMALL.value,
                device="auto"
            )
            self._vector_store = FAISSVectorStore(vector_store_path, embed_config)
        
        logger.info("✅ RAG + Graph integrator initialized")

    def add_vulnerability_to_graph(self, vulnerability: Dict[str, Any]) -> bool:
        """添加漏洞到图数据库

        Args:
            vulnerability: 漏洞数据

        Returns:
            是否成功
        """
        try:
            # 准备数据
            cve_data = {
                "cve_id": vulnerability.get("cve_id", ""),
                "title": vulnerability.get("title", ""),
                "description": vulnerability.get("description", ""),
                "cvss": vulnerability.get("cvss", 0.0),
                "source": vulnerability.get("source", ""),
                "published_date": vulnerability.get("published_date", ""),
                "cwe": vulnerability.get("cwe", ""),
                "affected_products": vulnerability.get("affected_products", []),
                "sinks": vulnerability.get("sinks", [])
            }
            
            # 批量写入到 Neo4j
            self._neo4j_manager.batch_merge_cve([cve_data])
            
            # 如果有向量存储，添加到向量存储
            if self._vector_store and cve_data["cve_id"]:
                content = f"{cve_data['title']}\n{cve_data['description']}"
                self._vector_store.add_document(
                    document_id=cve_data["cve_id"],
                    content=content,
                    metadata=cve_data
                )
            
            return True
        except Exception as e:
            logger.error(f"添加漏洞到图数据库失败: {e}")
            return False

    def add_vulnerabilities_batch(self, vulnerabilities: List[Dict[str, Any]]) -> bool:
        """批量添加漏洞到图数据库

        Args:
            vulnerabilities: 漏洞数据列表

        Returns:
            是否成功
        """
        try:
            # 准备 Neo4j 数据
            cve_data_list = []
            vector_documents = []
            
            for vuln in vulnerabilities:
                cve_data = {
                    "cve_id": vuln.get("cve_id", ""),
                    "title": vuln.get("title", ""),
                    "description": vuln.get("description", ""),
                    "cvss": vuln.get("cvss", 0.0),
                    "source": vuln.get("source", ""),
                    "published_date": vuln.get("published_date", ""),
                    "cwe": vuln.get("cwe", ""),
                    "affected_products": vuln.get("affected_products", []),
                    "sinks": vuln.get("sinks", [])
                }
                cve_data_list.append(cve_data)
                
                # 准备向量存储数据
                if self._vector_store and cve_data["cve_id"]:
                    content = f"{cve_data['title']}\n{cve_data['description']}"
                    vector_documents.append({
                        "document_id": cve_data["cve_id"],
                        "content": content,
                        "metadata": cve_data
                    })
            
            # 批量写入到 Neo4j
            if cve_data_list:
                self._neo4j_manager.batch_merge_cve(cve_data_list)
            
            # 批量添加到向量存储
            if self._vector_store and vector_documents:
                self._vector_store.add_documents(vector_documents)
            
            return True
        except Exception as e:
            logger.error(f"批量添加漏洞失败: {e}")
            return False

    def search_vulnerabilities(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """搜索漏洞

        Args:
            query: 查询文本
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        results = []
        
        # 向量搜索
        if self._vector_store:
            vector_results = self._vector_store.search(query, top_k)
            results.extend(vector_results)
        
        # 图数据库搜索（可选）
        # 这里可以添加基于图的搜索逻辑
        
        return results

    def find_attack_chains(self, chain_type: str = "all", limit: int = 10) -> List[Dict[str, Any]]:
        """查找攻击链

        Args:
            chain_type: 攻击链类型 (all, rce, sql, xss)
            limit: 返回数量限制

        Returns:
            攻击链列表
        """
        if chain_type == "rce":
            return self._attack_chain_analyzer.find_rce_chains(limit)
        elif chain_type == "sql":
            return self._attack_chain_analyzer.find_sql_injection_chains(limit)
        elif chain_type == "xss":
            return self._attack_chain_analyzer.find_xss_chains(limit)
        else:
            # 返回所有类型的攻击链
            chains = []
            chains.extend(self._attack_chain_analyzer.find_rce_chains(limit))
            chains.extend(self._attack_chain_analyzer.find_sql_injection_chains(limit))
            chains.extend(self._attack_chain_analyzer.find_xss_chains(limit))
            return chains[:limit]

    def get_vulnerability_context(self, cve_id: str) -> Dict[str, Any]:
        """获取漏洞上下文信息

        Args:
            cve_id: CVE ID

        Returns:
            漏洞上下文信息
        """
        context = {}
        
        # 从图数据库获取信息
        query = """
        MATCH (c:CVE {id: $cve_id})
        OPTIONAL MATCH (c)-[:BELONGS_TO]->(w:CWE)
        OPTIONAL MATCH (c)-[:AFFECTS]->(p:Product)
        OPTIONAL MATCH (c)-[:HAS_SINK]->(s:Sink)
        RETURN c as cve, collect(DISTINCT w) as cwes, collect(DISTINCT p) as products, collect(DISTINCT s) as sinks
        """
        
        result = self._neo4j_manager.execute_cypher(query, {"cve_id": cve_id})
        
        if result:
            data = result[0]
            context["cve"] = {
                "id": data["cve"].get("id"),
                "title": data["cve"].get("title"),
                "description": data["cve"].get("description"),
                "cvss": data["cve"].get("cvss"),
                "source": data["cve"].get("source"),
                "published_date": data["cve"].get("published_date")
            }
            context["cwes"] = [w.get("id") for w in data["cwes"]]
            context["products"] = [p.get("name") for p in data["products"]]
            context["sinks"] = [s.get("type") for s in data["sinks"]]
        
        # 从向量存储获取相似漏洞
        if self._vector_store:
            similar_vulns = self._vector_store.search(context.get("cve", {}).get("description", ""), top_k=3)
            context["similar_vulnerabilities"] = [
                {
                    "id": vuln["document_id"],
                    "title": vuln["metadata"].get("title"),
                    "similarity": vuln["similarity"]
                }
                for vuln in similar_vulns if vuln["document_id"] != cve_id
            ]
        
        return context

    def get_attack_chain_statistics(self) -> Dict[str, Any]:
        """获取攻击链统计信息

        Returns:
            统计信息
        """
        return self._attack_chain_analyzer.get_attack_chain_statistics()

    def export_attack_chains(self, chain_type: str = "all", file_path: str = "attack_chains.json") -> bool:
        """导出攻击链到文件

        Args:
            chain_type: 攻击链类型 (all, rce, sql, xss)
            file_path: 文件路径

        Returns:
            是否成功
        """
        return self._attack_chain_analyzer.export_attack_chains(chain_type, file_path)

    def close(self) -> None:
        """关闭资源"""
        # 关闭 Neo4j 连接
        if self._neo4j_manager:
            self._neo4j_manager.close()
        logger.info("✅ RAG + Graph integrator closed")


# 全局实例
_rag_graph_integrator: Optional[RAGGraphIntegrator] = None


def get_rag_graph_integrator(vector_store_path: Optional[Path] = None) -> RAGGraphIntegrator:
    """获取 RAG + 图融合集成器实例

    Args:
        vector_store_path: 向量存储路径

    Returns:
        RAG + 图融合集成器实例
    """
    global _rag_graph_integrator
    if _rag_graph_integrator is None:
        _rag_graph_integrator = RAGGraphIntegrator(vector_store_path)
    return _rag_graph_integrator
