from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict, Any
from ..db.connection import NVDConnection

class BaseETL(ABC):
    """ETL处理器基类"""

    ETL_NAME: str = ""

    def __init__(self, connection: Optional[NVDConnection] = None):
        self.conn = connection or NVDConnection.get_instance()
        self.records_processed = 0
        self.records_inserted = 0
        self.records_updated = 0
        self.records_skipped = 0

    @abstractmethod
    def process(self, data_path: str) -> bool:
        """处理数据的抽象方法"""
        pass

    def _start_etl(self) -> int:
        """开始ETL记录"""
        query = """
            INSERT INTO etl_records (etl_name, started_at, status)
            VALUES (%s, %s, 'running')
            RETURNING id
        """
        result = self.conn.fetch_one(query, (self.ETL_NAME, datetime.now()))
        return result[0] if result else 0

    def _complete_etl(self, etl_id: int, status: str = 'completed', error_message: str = None) -> None:
        """完成ETL记录"""
        query = """
            UPDATE etl_records
            SET completed_at = %s,
                status = %s,
                records_processed = %s,
                records_inserted = %s,
                records_updated = %s,
                records_skipped = %s,
                error_message = %s
            WHERE id = %s
        """
        self.conn.execute(query, (
            datetime.now(),
            status,
            self.records_processed,
            self.records_inserted,
            self.records_updated,
            self.records_skipped,
            error_message,
            etl_id
        ))

    def run(self, data_path: str) -> bool:
        """运行ETL"""
        etl_id = self._start_etl()
        try:
            result = self.process(data_path)
            status = 'completed' if result else 'failed'
            self._complete_etl(etl_id, status)
            return result
        except Exception as e:
            self._complete_etl(etl_id, 'failed', str(e))
            raise