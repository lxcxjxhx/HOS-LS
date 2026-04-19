from dataclasses import dataclass
from typing import List, Optional
from .connection import NVDConnection

@dataclass
class TableSchema:
    """表结构定义"""
    name: str
    create_sql: str
    indexes: List[str] = None

class NVDSche:
    """NVD漏洞数据库Schema管理器"""

    CVE_TABLE = """
        CREATE TABLE IF NOT EXISTS cve (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            published_date TIMESTAMP,
            last_modified TIMESTAMP
        )
    """

    CVSS_TABLE = """
        CREATE TABLE IF NOT EXISTS cvss (
            cve_id TEXT PRIMARY KEY REFERENCES cve(cve_id) ON DELETE CASCADE,
            score FLOAT,
            severity TEXT,
            vector TEXT,
            version TEXT DEFAULT '3.1'
        )
    """

    CPE_TABLE = """
        CREATE TABLE IF NOT EXISTS cpe (
            id SERIAL PRIMARY KEY,
            cve_id TEXT REFERENCES cve(cve_id) ON DELETE CASCADE,
            vendor TEXT,
            product TEXT,
            version VARCHAR(128),
            version_start VARCHAR(128),
            version_end VARCHAR(128),
            version_start_type TEXT CHECK (version_start_type IN ('including', 'excluding')),
            version_end_type TEXT CHECK (version_end_type IN ('including', 'excluding')),
            created_at TIMESTAMP DEFAULT NOW()
        )
    """

    CWE_TABLE = """
        CREATE TABLE IF NOT EXISTS cwe (
            cwe_id TEXT PRIMARY KEY,
            name TEXT,
            weakness_abstraction TEXT,
            status TEXT,
            description TEXT
        )
    """

    CVE_CWE_TABLE = """
        CREATE TABLE IF NOT EXISTS cve_cwe (
            cve_id TEXT REFERENCES cve(cve_id) ON DELETE CASCADE,
            cwe_id TEXT REFERENCES cwe(cwe_id) ON DELETE CASCADE,
            is_primary BOOLEAN DEFAULT FALSE,
            PRIMARY KEY (cve_id, cwe_id)
        )
    """

    KEV_TABLE = """
        CREATE TABLE IF NOT EXISTS kev (
            cve_id TEXT PRIMARY KEY REFERENCES cve(cve_id) ON DELETE CASCADE,
            exploited BOOLEAN DEFAULT TRUE,
            due_date DATE,
            short_description TEXT,
            notes TEXT
        )
    """

    EXPLOIT_TABLE = """
        CREATE TABLE IF NOT EXISTS exploit (
            id SERIAL PRIMARY KEY,
            cve_id TEXT REFERENCES cve(cve_id) ON DELETE SET NULL,
            source TEXT DEFAULT 'exploitdb',
            exploit_type TEXT,
            platform TEXT,
            port TEXT,
            description TEXT,
            file_path TEXT,
            verified BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """

    POC_TABLE = """
        CREATE TABLE IF NOT EXISTS poc (
            id SERIAL PRIMARY KEY,
            cve_id TEXT REFERENCES cve(cve_id) ON DELETE SET NULL,
            repo_url TEXT,
            stars INT DEFAULT 0,
            language TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            last_updated TIMESTAMP
        )
    """

    DOWNLOAD_RECORDS_TABLE = """
        CREATE TABLE IF NOT EXISTS download_records (
            id SERIAL PRIMARY KEY,
            source TEXT NOT NULL,
            file_name TEXT NOT NULL,
            downloaded_at TIMESTAMP DEFAULT NOW(),
            file_size BIGINT,
            checksum TEXT,
            version TEXT
        )
    """

    ETL_RECORDS_TABLE = """
        CREATE TABLE IF NOT EXISTS etl_records (
            id SERIAL PRIMARY KEY,
            etl_name TEXT NOT NULL,
            records_processed INT DEFAULT 0,
            records_inserted INT DEFAULT 0,
            records_updated INT DEFAULT 0,
            records_skipped INT DEFAULT 0,
            started_at TIMESTAMP DEFAULT NOW(),
            completed_at TIMESTAMP,
            status TEXT DEFAULT 'running',
            error_message TEXT
        )
    """

    INDEXES = [
        "CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe(product)",
        "CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe(vendor, product)",
        "CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_exploit_cve ON exploit(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_poc_cve ON poc(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_poc_stars ON poc(stars DESC)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_download_source_file ON download_records(source, file_name)",
    ]

    CVE_SUMMARY_VIEW = """
        CREATE MATERIALIZED VIEW IF NOT EXISTS cve_summary AS
        SELECT
            c.cve_id,
            c.published_date,
            cvss.score AS cvss_score,
            cvss.severity AS cvss_severity,
            kev.exploited AS kev_exploited,
            COALESCE(e.exploit_count, 0) AS exploit_count,
            COALESCE(p.poc_count, 0) AS poc_count,
            COALESCE(p.max_stars, 0) AS max_poc_stars,
            array_agg(DISTINCT cc.cwe_id) FILTER (WHERE cc.cwe_id IS NOT NULL) AS cwe_ids
        FROM cve c
        LEFT JOIN cvss ON c.cve_id = cvss.cve_id
        LEFT JOIN kev ON c.cve_id = kev.cve_id
        LEFT JOIN LATERAL (SELECT COUNT(*) AS exploit_count FROM exploit WHERE exploit.cve_id = c.cve_id) e ON TRUE
        LEFT JOIN LATERAL (
            SELECT COUNT(*) AS poc_count, MAX(stars) AS max_stars
            FROM poc WHERE poc.cve_id = c.cve_id
        ) p ON TRUE
        LEFT JOIN cve_cwe cc ON c.cve_id = cc.cve_id
        GROUP BY c.cve_id, c.published_date, cvss.score, cvss.severity, kev.exploited, e.exploit_count, p.poc_count, p.max_stars
    """

    CVE_SUMMARY_INDEXES = [
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_summary_cve ON cve_summary(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_score ON cve_summary(cvss_score DESC)",
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_exploited ON cve_summary(kev_exploited DESC)",
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_stars ON cve_summary(max_poc_stars DESC)",
    ]

    def __init__(self, connection: Optional[NVDConnection] = None):
        self.conn = connection or NVDConnection.get_instance()

    def create_all_tables(self) -> None:
        """创建所有表"""
        tables = [
            self.CVE_TABLE,
            self.CVSS_TABLE,
            self.CPE_TABLE,
            self.CWE_TABLE,
            self.CVE_CWE_TABLE,
            self.KEV_TABLE,
            self.EXPLOIT_TABLE,
            self.POC_TABLE,
            self.DOWNLOAD_RECORDS_TABLE,
            self.ETL_RECORDS_TABLE,
        ]

        with self.conn.get_cursor() as cursor:
            for table_sql in tables:
                cursor.execute(table_sql)

    def create_all_indexes(self) -> None:
        """创建所有索引"""
        with self.conn.get_cursor() as cursor:
            for index_sql in self.INDEXES:
                cursor.execute(index_sql)

    def create_materialized_view(self) -> None:
        """创建物化视图"""
        with self.conn.get_cursor() as cursor:
            cursor.execute(self.CVE_SUMMARY_VIEW)
            for index_sql in self.CVE_SUMMARY_INDEXES:
                cursor.execute(index_sql)

    def refresh_materialized_view(self) -> None:
        """刷新物化视图"""
        with self.conn.get_cursor() as cursor:
            cursor.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY cve_summary")

    def create_database(self, database_name: str) -> bool:
        """创建数据库（如果不存在）"""
        try:
            import psycopg2
            from psycopg2 import sql

            conn = psycopg2.connect(
                host=self.conn.config.host,
                port=self.conn.config.port,
                user=self.conn.config.user,
                password=self.conn.config.password,
                database='postgres'
            )
            conn.autocommit = True
            cursor = conn.cursor()

            cursor.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s",
                (database_name,)
            )
            if not cursor.fetchone():
                cursor.execute(sql.SQL("CREATE DATABASE {}").format(
                    sql.Identifier(database_name)
                ))
                cursor.close()
                conn.close()
                return True
            cursor.close()
            conn.close()
            return False
        except Exception as e:
            print(f"创建数据库时出错: {e}")
            return False

    def init_schema(self) -> None:
        """初始化完整Schema"""
        self.create_all_tables()
        self.create_all_indexes()
        self.create_materialized_view()

    def drop_all(self) -> None:
        """删除所有表和视图（谨慎使用）"""
        with self.conn.get_cursor() as cursor:
            cursor.execute("""
                DROP TABLE IF EXISTS cve CASCADE;
                DROP TABLE IF EXISTS cvss CASCADE;
                DROP TABLE IF EXISTS cpe CASCADE;
                DROP TABLE IF EXISTS cwe CASCADE;
                DROP TABLE IF EXISTS cve_cwe CASCADE;
                DROP TABLE IF EXISTS kev CASCADE;
                DROP TABLE IF EXISTS exploit CASCADE;
                DROP TABLE IF EXISTS poc CASCADE;
                DROP TABLE IF EXISTS download_records CASCADE;
                DROP TABLE IF EXISTS etl_records CASCADE;
                DROP MATERIALIZED VIEW IF EXISTS cve_summary CASCADE;
            """)
