"""VDSche Schema - 漏洞推理增强Schema"""
from typing import List, Optional
from .connection import VDConnection


class VDSche:
    """漏洞推理增强数据库Schema"""

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

    SCAN_RESULT_TABLE = """
        CREATE TABLE IF NOT EXISTS scan_result (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            cwe_id TEXT,
            vulnerability_type TEXT,
            severity TEXT,
            confidence REAL,
            sink_function TEXT,
            source_function TEXT,
            exploit_pattern TEXT,
            language TEXT,
            evidence TEXT,
            recommendation TEXT,
            source TEXT DEFAULT 'reasoning_engine',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """

    INDEXES = [
        "CREATE INDEX IF NOT EXISTS idx_sr_file ON scan_result(file_path)",
        "CREATE INDEX IF NOT EXISTS idx_sr_cwe ON scan_result(cwe_id)",
        "CREATE INDEX IF NOT EXISTS idx_sr_severity ON scan_result(severity)",
        "CREATE INDEX IF NOT EXISTS idx_sr_language ON scan_result(language)",
        "CREATE INDEX IF NOT EXISTS idx_vp_cwe ON vulnerability_pattern(cwe_id)",
        "CREATE INDEX IF NOT EXISTS idx_vp_language ON vulnerability_pattern(language)",
        "CREATE INDEX IF NOT EXISTS idx_ss_cwe ON cwe_sink_source(cwe_id)",
    ]

    def __init__(self, connection: VDConnection = None):
        self.conn = connection or VDConnection.get_instance()

    def create_all_tables(self) -> None:
        """创建所有表"""
        tables = [
            self.VULNERABILITY_PATTERN_TABLE,
            self.CWE_SINK_SOURCE_TABLE,
            self.LANGUAGE_INFERENCE_TABLE,
            self.SCAN_RESULT_TABLE,
        ]

        with self.conn.get_cursor() as cursor:
            for table_sql in tables:
                cursor.execute(table_sql)

            for index_sql in self.INDEXES:
                cursor.execute(index_sql)

    def init_schema(self) -> None:
        """初始化数据库Schema"""
        self.create_all_tables()

    def seed_patterns(self) -> None:
        """填充预定义漏洞模式"""
        patterns = [
            ("CWE-89", "java", "${", None, "mybatis_interpolation", "CRITICAL", 0.95),
            ("CWE-89", "java", "#{", None, "mybatis_parameter", "CRITICAL", 0.95),
            ("CWE-89", "java", "queryWrapper.sqlSegment", None, "wrapper_sql_concat", "CRITICAL", 0.9),
            ("CWE-89", "java", "ew.sqlSegment", None, "ew_sql_concat", "CRITICAL", 0.9),
            ("CWE-89", "python", "cursor.execute", "request.args", "string_concatenation", "CRITICAL", 0.9),
            ("CWE-89", "python", "execute(", "request.form", "string_concatenation", "CRITICAL", 0.9),
            ("CWE-79", "javascript", "innerHTML", "request.body", "innerHTML_assignment", "HIGH", 0.85),
            ("CWE-79", "javascript", "document.write", "user_input", "document_write", "HIGH", 0.85),
            ("CWE-22", "java", "new File(", "request.getParameter", "path_concatenation", "HIGH", 0.8),
            ("CWE-22", "java", "FileInputStream", "request.getParameter", "path_concatenation", "HIGH", 0.8),
            ("CWE-22", "python", "open(", "request.args", "path_concatenation", "HIGH", 0.8),
            ("CWE-259", "java", "password", None, "hardcoded_literal", "CRITICAL", 0.95),
            ("CWE-259", "yaml", "password:", None, "hardcoded_config", "CRITICAL", 0.95),
            ("CWE-321", "java", "encryptor.password", None, "hardcoded_key", "HIGH", 0.9),
        ]

        with self.conn.get_cursor() as cursor:
            for p in patterns:
                cursor.execute("""
                    INSERT OR IGNORE INTO vulnerability_pattern
                    (cwe_id, language, sink_function, source_function, exploit_pattern, severity, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, p)

    def get_stats(self) -> dict:
        """获取数据库统计信息"""
        stats = {}
        tables = ['vulnerability_pattern', 'cwe_sink_source', 'language_inference', 'scan_result']

        with self.conn.get_cursor() as cursor:
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    stats[table] = count
                except:
                    stats[table] = 0

        return stats
