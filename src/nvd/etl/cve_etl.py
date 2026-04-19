import json
import re
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from tqdm import tqdm
from .base import BaseETL

class CVEETL(BaseETL):
    """CVE数据ETL处理器 - 适配CVE 5.0单文件格式"""

    ETL_NAME = "cve"

    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}')

    def __init__(self, connection=None):
        super().__init__(connection)
        self._print_header()

    def _print_header(self) -> None:
        """打印美化标题"""
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                     CVE 数据入库                            ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║  数据源: cvelistV5 (CVE 5.0 JSON格式)                    ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    def process(self, data_path: str) -> bool:
        """处理CVE数据"""
        base_path = Path(data_path)
        cves_dir = base_path / 'cves'

        if not cves_dir.exists():
            cves_dir = base_path

        json_files = list(cves_dir.glob('**/CVE-*.json'))

        if not json_files:
            print(f"╔══════════════════════════════════════════════════════════════╗")
            print(f"║  ✗ 未找到CVE JSON文件: {data_path:<36} ║")
            print(f"╚══════════════════════════════════════════════════════════════╝")
            return False

        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║  📂 发现 {len(json_files)} 个CVE文件                              ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")

        batch_size = 1000
        batch = []

        for json_file in tqdm(json_files, desc="  处理进度", unit="文件", ncols=70):
            try:
                result = self._process_single_file_fast(json_file)
                if result:
                    batch.append(result)
                    self.records_processed += 1

                    if len(batch) >= batch_size:
                        inserted = self._batch_insert(batch)
                        self.records_inserted += inserted
                        batch = []
            except Exception:
                self.records_skipped += 1

        if batch:
            inserted = self._batch_insert(batch)
            self.records_inserted += inserted

        self._print_summary()
        return True

    def _print_summary(self) -> None:
        """打印美化汇总"""
        total = self.records_processed
        inserted = self.records_inserted
        skipped = self.records_skipped
        success_rate = (inserted / total * 100) if total > 0 else 0

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                     CVE 数据入库完成                        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║  总处理: {total:>6} 条                                              ║")
        print(f"║  插入:   {inserted:>6} 条  ({success_rate:.1f}%)                               ║")
        print(f"║  跳过:   {skipped:>6} 条                                              ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    def _process_single_file_fast(self, json_file: Path) -> Optional[Dict]:
        """快速处理单个CVE JSON文件"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return self._extract_cve_data(data)
        except:
            return None

    def _extract_cve_data(self, data: Dict) -> Optional[Dict]:
        """从CVE 5.0 JSON提取数据"""
        try:
            cve_id = data.get('cveMetadata', {}).get('cveId')
            if not cve_id or not self.CVE_PATTERN.match(cve_id):
                return None

            descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and descriptions:
                description = descriptions[0].get('value', '')

            published_date_str = data.get('cveMetadata', {}).get('datePublished', '')
            last_modified_str = data.get('cveMetadata', {}).get('dateUpdated', '')

            published_date = self._parse_date(published_date_str)
            last_modified = self._parse_date(last_modified_str)

            return {
                'cve_id': cve_id,
                'description': description,
                'published_date': published_date,
                'last_modified': last_modified
            }
        except Exception:
            return None

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """解析日期字符串"""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except:
            return None

    def _batch_insert(self, batch: List[Dict]) -> int:
        """批量插入CVE数据"""
        if not batch:
            return 0

        query = """
            INSERT INTO cve (cve_id, description, published_date, last_modified)
            VALUES (%(cve_id)s, %(description)s, %(published_date)s, %(last_modified)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                description = EXCLUDED.description,
                last_modified = EXCLUDED.last_modified
        """

        try:
            with self.conn.get_cursor() as cursor:
                cursor.executemany(query, batch)
            return len(batch)
        except Exception:
            count = 0
            for item in batch:
                try:
                    if self._insert_or_update_cve(item):
                        count += 1
                except:
                    pass
            return count

    def _insert_or_update_cve(self, cve_data: Dict) -> bool:
        """插入或更新CVE"""
        query = """
            INSERT INTO cve (cve_id, description, published_date, last_modified)
            VALUES (%(cve_id)s, %(description)s, %(published_date)s, %(last_modified)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                description = EXCLUDED.description,
                last_modified = EXCLUDED.last_modified
            RETURNING cve_id
        """
        try:
            result = self.conn.fetch_one(query, cve_data)
            return result is not None
        except Exception:
            self.records_skipped += 1
            return False
