from typing import List, Optional
from .sqlite_connection import SQLiteConnection

class SQLiteSche:
    """SQLite漏洞数据库Schema管理器"""

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
            cve_id TEXT PRIMARY KEY,
            score REAL,
            severity TEXT,
            vector TEXT,
            version TEXT DEFAULT '3.1'
        )
    """

    CPE_TABLE = """
        CREATE TABLE IF NOT EXISTS cpe (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            vendor TEXT,
            product TEXT,
            version TEXT,
            version_start TEXT,
            version_end TEXT,
            version_start_type TEXT,
            version_end_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            cve_id TEXT,
            cwe_id TEXT,
            is_primary INTEGER DEFAULT 0,
            PRIMARY KEY (cve_id, cwe_id)
        )
    """

    KEV_TABLE = """
        CREATE TABLE IF NOT EXISTS kev (
            cve_id TEXT PRIMARY KEY,
            exploited INTEGER DEFAULT 1,
            due_date DATE,
            short_description TEXT,
            notes TEXT
        )
    """

    EXPLOIT_TABLE = """
        CREATE TABLE IF NOT EXISTS exploit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            source TEXT,
            exploit_type TEXT,
            platform TEXT,
            port TEXT,
            description TEXT,
            file_path TEXT,
            verified INTEGER DEFAULT 0
        )
    """

    POC_TABLE = """
        CREATE TABLE IF NOT EXISTS poc (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            repo_url TEXT,
            stars INTEGER DEFAULT 0,
            language TEXT,
            description TEXT,
            last_updated TIMESTAMP,
            UNIQUE(cve_id, repo_url)
        )
    """

    ETL_RECORDS_TABLE = """
        CREATE TABLE IF NOT EXISTS etl_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            etl_name TEXT NOT NULL,
            records_processed INTEGER DEFAULT 0,
            records_inserted INTEGER DEFAULT 0,
            records_updated INTEGER DEFAULT 0,
            records_skipped INTEGER DEFAULT 0,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            status TEXT DEFAULT 'running',
            error_message TEXT
        )
    """

    ETL_PROGRESS_TABLE = """
        CREATE TABLE IF NOT EXISTS etl_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            etl_name TEXT NOT NULL UNIQUE,
            last_processed_file TEXT,
            last_processed_index INTEGER DEFAULT 0,
            processed_count INTEGER DEFAULT 0,
            inserted_count INTEGER DEFAULT 0,
            skipped_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            started_at TIMESTAMP,
            updated_at TIMESTAMP,
            completed_at TIMESTAMP,
            error_message TEXT
        )
    """

    VULNERABILITY_PATTERN_TABLE = """
        CREATE TABLE IF NOT EXISTS vulnerability_pattern (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cwe_id TEXT NOT NULL,
            language TEXT NOT NULL,
            sink_function TEXT NOT NULL,
            source_function TEXT,
            exploit_pattern TEXT NOT NULL,
            pattern_regex TEXT,
            severity TEXT DEFAULT 'HIGH',
            confidence REAL DEFAULT 0.8,
            description TEXT,
            recommendation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(cwe_id, language, sink_function, exploit_pattern)
        )
    """

    CWE_SINK_SOURCE_TABLE = """
        CREATE TABLE IF NOT EXISTS cwe_sink_source (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cwe_id TEXT NOT NULL,
            language TEXT NOT NULL,
            sink_function TEXT NOT NULL,
            source_function TEXT,
            data_flow_type TEXT DEFAULT 'direct',
            description TEXT,
            UNIQUE(cwe_id, language, sink_function, source_function)
        )
    """

    LANGUAGE_INFERENCE_TABLE = """
        CREATE TABLE IF NOT EXISTS language_inference (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cwe_id TEXT NOT NULL,
            inference_rule TEXT NOT NULL,
            confidence REAL DEFAULT 0.7,
            example_code TEXT,
            description TEXT,
            UNIQUE(cwe_id, inference_rule)
        )
    """

    INDEXES = [
        "CREATE INDEX IF NOT EXISTS idx_cve_published ON cve(published_date)",
        "CREATE INDEX IF NOT EXISTS idx_cvss_severity ON cvss(severity)",
        "CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe(vendor, product)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cve ON cve_cwe(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe ON cve_cwe(cwe_id)",
        "CREATE INDEX IF NOT EXISTS idx_kev_cve ON kev(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_exploit_cve ON exploit(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_poc_cve ON poc(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_vp_cwe ON vulnerability_pattern(cwe_id)",
        "CREATE INDEX IF NOT EXISTS idx_vp_language ON vulnerability_pattern(language)",
        "CREATE INDEX IF NOT EXISTS idx_vp_sink ON vulnerability_pattern(sink_function)",
        "CREATE INDEX IF NOT EXISTS idx_ss_cwe ON cwe_sink_source(cwe_id)",
        "CREATE INDEX IF NOT EXISTS idx_ss_language ON cwe_sink_source(language)",
        "CREATE INDEX IF NOT EXISTS idx_inference_cwe ON language_inference(cwe_id)",
    ]

    def __init__(self, connection: SQLiteConnection = None):
        self.conn = connection or SQLiteConnection.get_instance()

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
            self.ETL_RECORDS_TABLE,
            self.ETL_PROGRESS_TABLE,
            self.VULNERABILITY_PATTERN_TABLE,
            self.CWE_SINK_SOURCE_TABLE,
            self.LANGUAGE_INFERENCE_TABLE,
        ]

        with self.conn.get_cursor() as cursor:
            for table_sql in tables:
                cursor.execute(table_sql)

            for index_sql in self.INDEXES:
                cursor.execute(index_sql)

    def drop_all(self) -> None:
        """删除所有表和视图（谨慎使用）"""
        with self.conn.get_cursor() as cursor:
            cursor.execute("""
                DROP TABLE IF EXISTS cve;
                DROP TABLE IF EXISTS cvss;
                DROP TABLE IF EXISTS cpe;
                DROP TABLE IF EXISTS cwe;
                DROP TABLE IF EXISTS cve_cwe;
                DROP TABLE IF EXISTS kev;
                DROP TABLE IF EXISTS exploit;
                DROP TABLE IF EXISTS poc;
                DROP TABLE IF EXISTS etl_records;
                DROP TABLE IF EXISTS etl_progress;
            """)

    def init_schema(self) -> None:
        """初始化数据库Schema"""
        self.create_all_tables()

    def get_stats(self) -> dict:
        """获取数据库统计信息"""
        stats = {}
        tables = ['cve', 'cvss', 'cpe', 'cwe', 'cve_cwe', 'kev', 'exploit', 'poc']

        with self.conn.get_cursor() as cursor:
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    stats[table] = count
                except:
                    stats[table] = 0

        return stats
