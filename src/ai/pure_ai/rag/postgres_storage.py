"""PostgreSQL存储模块

实现PostgreSQL存储功能，用于存储CVE的结构化数据。
"""

import asyncio
from dataclasses import asdict
from typing import Dict, List, Optional, Any

import psycopg2
from psycopg2.extras import DictCursor

from src.utils.logger import get_logger
from src.integration.nvd_processor import CVEStructuredData

logger = get_logger(__name__)


class PostgresStorage:
    """PostgreSQL存储"""

    def __init__(self, config: Dict[str, Any]):
        """初始化PostgreSQL存储

        Args:
            config: PostgreSQL配置
                - host: 主机地址
                - port: 端口
                - user: 用户名
                - password: 密码
                - database: 数据库名
        """
        self.config = config
        self.connection = None
        self.cursor = None

    def connect(self):
        """连接PostgreSQL数据库"""
        try:
            self.connection = psycopg2.connect(
                host=self.config.get('host', 'localhost'),
                port=self.config.get('port', 5432),
                user=self.config.get('user', 'postgres'),
                password=self.config.get('password', ''),
                database=self.config.get('database', 'hos_ls'),
                cursor_factory=DictCursor
            )
            self.cursor = self.connection.cursor()
            logger.info("成功连接到PostgreSQL数据库")
            self._create_tables()
        except Exception as e:
            logger.error(f"连接PostgreSQL失败: {e}")
            raise

    def close(self):
        """关闭数据库连接"""
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
        logger.info("PostgreSQL连接已关闭")

    def _create_tables(self):
        """创建数据库表"""
        try:
            # CVE表
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    id SERIAL PRIMARY KEY,
                    cve_id VARCHAR(20) UNIQUE NOT NULL,
                    description TEXT,
                    cwe VARCHAR(20),
                    cvss_v3_score FLOAT,
                    cvss_v3_vector VARCHAR(100),
                    cvss_v2_score FLOAT,
                    cvss_v2_vector VARCHAR(100),
                    attack_vector VARCHAR(50),
                    published_date TIMESTAMP,
                    last_modified_date TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # CVE标签表
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_tags (
                    id SERIAL PRIMARY KEY,
                    cve_id VARCHAR(20) NOT NULL,
                    tag VARCHAR(50) NOT NULL,
                    FOREIGN KEY (cve_id) REFERENCES cves(cve_id),
                    UNIQUE(cve_id, tag)
                )
            """)

            # CPE表
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS cpe_info (
                    id SERIAL PRIMARY KEY,
                    cve_id VARCHAR(20) NOT NULL,
                    cpe_uri VARCHAR(255) NOT NULL,
                    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
                )
            """)

            # 引用表
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_references (
                    id SERIAL PRIMARY KEY,
                    cve_id VARCHAR(20) NOT NULL,
                    url VARCHAR(512) NOT NULL,
                    name VARCHAR(255),
                    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
                )
            """)

            # 创建索引
            self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id)")
            self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss_v3_score ON cves(cvss_v3_score)")
            self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves(published_date)")
            self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_tags_cve_id ON cve_tags(cve_id)")
            self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_tags_tag ON cve_tags(tag)")
            self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpe_info_cve_id ON cpe_info(cve_id)")
            self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_references_cve_id ON cve_references(cve_id)")

            self.connection.commit()
            logger.info("数据库表创建成功")
        except Exception as e:
            logger.error(f"创建数据库表失败: {e}")
            self.connection.rollback()
            raise

    def store_cve(self, structured_data: CVEStructuredData) -> bool:
        """存储CVE结构化数据

        Args:
            structured_data: CVE结构化数据

        Returns:
            是否存储成功
        """
        try:
            # 开始事务
            self.connection.autocommit = False

            # 检查CVE是否已存在
            self.cursor.execute("SELECT cve_id FROM cves WHERE cve_id = %s", (structured_data.cve_id,))
            existing = self.cursor.fetchone()

            if existing:
                # 更新现有CVE
                self.cursor.execute("""
                    UPDATE cves SET 
                        description = %s,
                        cwe = %s,
                        cvss_v3_score = %s,
                        cvss_v3_vector = %s,
                        cvss_v2_score = %s,
                        cvss_v2_vector = %s,
                        attack_vector = %s,
                        published_date = %s,
                        last_modified_date = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE cve_id = %s
                """, (
                    structured_data.description,
                    structured_data.cwe,
                    structured_data.cvss_v3_score,
                    structured_data.cvss_v3_vector,
                    structured_data.cvss_v2_score,
                    structured_data.cvss_v2_vector,
                    structured_data.attack_vector,
                    structured_data.published_date,
                    structured_data.last_modified_date,
                    structured_data.cve_id
                ))

                # 删除旧标签
                self.cursor.execute("DELETE FROM cve_tags WHERE cve_id = %s", (structured_data.cve_id,))
                # 删除旧CPE
                self.cursor.execute("DELETE FROM cpe_info WHERE cve_id = %s", (structured_data.cve_id,))
                # 删除旧引用
                self.cursor.execute("DELETE FROM cve_references WHERE cve_id = %s", (structured_data.cve_id,))
            else:
                # 插入新CVE
                self.cursor.execute("""
                    INSERT INTO cves (
                        cve_id, description, cwe, cvss_v3_score, cvss_v3_vector,
                        cvss_v2_score, cvss_v2_vector, attack_vector, published_date, last_modified_date
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    structured_data.cve_id,
                    structured_data.description,
                    structured_data.cwe,
                    structured_data.cvss_v3_score,
                    structured_data.cvss_v3_vector,
                    structured_data.cvss_v2_score,
                    structured_data.cvss_v2_vector,
                    structured_data.attack_vector,
                    structured_data.published_date,
                    structured_data.last_modified_date
                ))

            # 插入标签
            for tag in structured_data.tags:
                self.cursor.execute(
                    "INSERT INTO cve_tags (cve_id, tag) VALUES (%s, %s) ON CONFLICT (cve_id, tag) DO NOTHING",
                    (structured_data.cve_id, tag)
                )

            # 插入CPE
            for cpe in structured_data.cpe_list:
                self.cursor.execute(
                    "INSERT INTO cpe_info (cve_id, cpe_uri) VALUES (%s, %s)",
                    (structured_data.cve_id, cpe)
                )

            # 插入引用
            for ref in structured_data.references:
                self.cursor.execute(
                    "INSERT INTO cve_references (cve_id, url, name) VALUES (%s, %s, %s)",
                    (structured_data.cve_id, ref.get('url', ''), ref.get('name', ''))
                )

            # 提交事务
            self.connection.commit()
            self.connection.autocommit = True
            return True
        except Exception as e:
            logger.error(f"存储CVE失败: {e}")
            if self.connection:
                self.connection.rollback()
                self.connection.autocommit = True
            return False

    def store_cves_batch(self, cve_list: List[CVEStructuredData]) -> int:
        """批量存储CVE数据

        Args:
            cve_list: CVE结构化数据列表

        Returns:
            成功存储的数量
        """
        success_count = 0
        try:
            self.connection.autocommit = False

            for structured_data in cve_list:
                if self.store_cve(structured_data):
                    success_count += 1

            self.connection.commit()
            self.connection.autocommit = True
        except Exception as e:
            logger.error(f"批量存储CVE失败: {e}")
            if self.connection:
                self.connection.rollback()
                self.connection.autocommit = True
        finally:
            self.connection.autocommit = True

        return success_count

    def get_cve(self, cve_id: str) -> Optional[CVEStructuredData]:
        """获取CVE数据

        Args:
            cve_id: CVE ID

        Returns:
            CVE结构化数据或None
        """
        try:
            # 获取CVE基本信息
            self.cursor.execute("""
                SELECT 
                    cve_id, description, cwe, cvss_v3_score, cvss_v3_vector,
                    cvss_v2_score, cvss_v2_vector, attack_vector, published_date, last_modified_date
                FROM cves 
                WHERE cve_id = %s
            """, (cve_id,))
            cve_data = self.cursor.fetchone()

            if not cve_data:
                return None

            # 获取标签
            self.cursor.execute("SELECT tag FROM cve_tags WHERE cve_id = %s", (cve_id,))
            tags = [row[0] for row in self.cursor.fetchall()]

            # 获取CPE
            self.cursor.execute("SELECT cpe_uri FROM cpe_info WHERE cve_id = %s", (cve_id,))
            cpe_list = [row[0] for row in self.cursor.fetchall()]

            # 获取引用
            self.cursor.execute("SELECT url, name FROM cve_references WHERE cve_id = %s", (cve_id,))
            references = [{'url': row[0], 'name': row[1]} for row in self.cursor.fetchall()]

            # 构建结构化数据
            structured_data = CVEStructuredData(
                cve_id=cve_data['cve_id'],
                description=cve_data['description'],
                cwe=cve_data['cwe'],
                cvss_v3_score=cve_data['cvss_v3_score'],
                cvss_v3_vector=cve_data['cvss_v3_vector'],
                cvss_v2_score=cve_data['cvss_v2_score'],
                cvss_v2_vector=cve_data['cvss_v2_vector'],
                attack_vector=cve_data['attack_vector'],
                tags=tags,
                published_date=cve_data['published_date'],
                last_modified_date=cve_data['last_modified_date'],
                cpe_list=cpe_list,
                references=references
            )

            return structured_data
        except Exception as e:
            logger.error(f"获取CVE失败: {e}")
            return None

    def search_cves(self, filters: Dict[str, Any], limit: int = 100) -> List[CVEStructuredData]:
        """搜索CVE

        Args:
            filters: 搜索过滤器
                - cve_id: CVE ID（支持部分匹配）
                - cwe: CWE ID
                - min_score: 最小CVSS分数
                - max_score: 最大CVSS分数
                - tags: 标签列表
                - start_date: 开始日期
                - end_date: 结束日期
            limit: 返回结果数量限制

        Returns:
            CVE结构化数据列表
        """
        try:
            # 构建查询
            where_clauses = []
            params = []

            if filters.get('cve_id'):
                where_clauses.append("c.cve_id LIKE %s")
                params.append(f"{filters['cve_id']}%")

            if filters.get('cwe'):
                where_clauses.append("c.cwe = %s")
                params.append(filters['cwe'])

            if filters.get('min_score'):
                where_clauses.append("c.cvss_v3_score >= %s")
                params.append(filters['min_score'])

            if filters.get('max_score'):
                where_clauses.append("c.cvss_v3_score <= %s")
                params.append(filters['max_score'])

            if filters.get('start_date'):
                where_clauses.append("c.published_date >= %s")
                params.append(filters['start_date'])

            if filters.get('end_date'):
                where_clauses.append("c.published_date <= %s")
                params.append(filters['end_date'])

            # 构建完整查询
            query = """
                SELECT DISTINCT c.cve_id
                FROM cves c
            """

            # 添加标签过滤
            if filters.get('tags'):
                query += " JOIN cve_tags ct ON c.cve_id = ct.cve_id"
                tag_conditions = []
                for tag in filters['tags']:
                    tag_conditions.append("ct.tag = %s")
                    params.append(tag)
                where_clauses.append(f"({' OR '.join(tag_conditions)})")

            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)

            query += f" LIMIT {limit}"

            # 执行查询
            self.cursor.execute(query, params)
            cve_ids = [row[0] for row in self.cursor.fetchall()]

            # 获取完整CVE数据
            cves = []
            for cve_id in cve_ids:
                cve = self.get_cve(cve_id)
                if cve:
                    cves.append(cve)

            return cves
        except Exception as e:
            logger.error(f"搜索CVE失败: {e}")
            return []

    def get_cve_count(self) -> int:
        """获取CVE数量

        Returns:
            CVE数量
        """
        try:
            self.cursor.execute("SELECT COUNT(*) FROM cves")
            count = self.cursor.fetchone()[0]
            return count
        except Exception as e:
            logger.error(f"获取CVE数量失败: {e}")
            return 0

    def delete_cve(self, cve_id: str) -> bool:
        """删除CVE

        Args:
            cve_id: CVE ID

        Returns:
            是否删除成功
        """
        try:
            self.connection.autocommit = False

            # 删除相关数据
            self.cursor.execute("DELETE FROM cve_references WHERE cve_id = %s", (cve_id,))
            self.cursor.execute("DELETE FROM cpe_info WHERE cve_id = %s", (cve_id,))
            self.cursor.execute("DELETE FROM cve_tags WHERE cve_id = %s", (cve_id,))
            self.cursor.execute("DELETE FROM cves WHERE cve_id = %s", (cve_id,))

            affected = self.cursor.rowcount
            self.connection.commit()
            self.connection.autocommit = True

            return affected > 0
        except Exception as e:
            logger.error(f"删除CVE失败: {e}")
            if self.connection:
                self.connection.rollback()
                self.connection.autocommit = True
            return False

    def vacuum(self):
        """执行数据库清理"""
        try:
            self.cursor.execute("VACUUM ANALYZE")
            self.connection.commit()
            logger.info("数据库清理完成")
        except Exception as e:
            logger.error(f"数据库清理失败: {e}")
            if self.connection:
                self.connection.rollback()