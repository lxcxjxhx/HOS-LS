import json
import re
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List
from tqdm import tqdm
from .base import BaseETL

class KEVETL(BaseETL):
    """KEV数据ETL处理器 - 适配 known_exploited_vulnerabilities.json 格式"""

    ETL_NAME = "kev"

    def __init__(self, connection=None):
        super().__init__(connection)
        self._print_header()

    def _print_header(self) -> None:
        """打印美化标题"""
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                     KEV 数据入库                             ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║  数据源: CISA Known Exploited Vulnerabilities Catalog        ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    def process(self, data_path: str) -> bool:
        """处理KEV数据"""
        data_dir = Path(data_path)

        json_files = list(data_dir.glob("known_exploited_vulnerabilities.json"))

        if not json_files:
            json_files = list(data_dir.glob("*.json"))

        if not json_files:
            print(f"╔══════════════════════════════════════════════════════════════╗")
            print(f"║  ✗ 未找到KEV JSON文件: {data_path:<36} ║")
            print(f"╚══════════════════════════════════════════════════════════════╝")
            return False

        json_file = json_files[0]
        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║  📂 处理文件: {json_file.name:<44} ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")

        self._process_json_file(json_file)

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
        print("║                     KEV 数据入库完成                          ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║  总处理: {total:>6} 条                                              ║")
        print(f"║  插入:   {inserted:>6} 条  ({success_rate:.1f}%)                               ║")
        print(f"║  跳过:   {skipped:>6} 条                                              ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    def _process_json_file(self, json_file: Path) -> None:
        """处理KEV JSON文件"""
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        vulnerabilities = data.get('vulnerabilities', [])

        if not vulnerabilities:
            print(f"╔══════════════════════════════════════════════════════════════╗")
            print(f"║  ✗ 未找到 vulnerabilities 数据                                  ║")
            print(f"╚══════════════════════════════════════════════════════════════╝")
            return

        print(f"║  📊 发现 {len(vulnerabilities)} 个KEV条目                               ║")
        print("╠══════════════════════════════════════════════════════════════╣")

        batch_size = 1000
        batch = []

        for item in tqdm(vulnerabilities, desc="  处理进度", unit="条", ncols=70):
            self.records_processed += 1
            kev_data = self._extract_kev_data(item)

            if kev_data:
                batch.append(kev_data)

                if len(batch) >= batch_size:
                    self._batch_insert(batch)
                    batch = []
            else:
                self.records_skipped += 1

        if batch:
            self._batch_insert(batch)

    def _extract_kev_data(self, item: Dict) -> Optional[Dict]:
        """提取KEV数据"""
        try:
            cve_id = item.get('cveID', '')
            if not cve_id:
                return None

            date_added_str = item.get('dateAdded', '')
            due_date_str = item.get('dueDate', '')

            return {
                'cve_id': cve_id,
                'exploited': True,
                'due_date': self._parse_date(due_date_str),
                'short_description': item.get('shortDescription', ''),
                'notes': item.get('notes', '')
            }
        except Exception:
            return None

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """解析日期字符串"""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, '%Y-%m-%d')
        except:
            return None

    def _batch_insert(self, batch: List[Dict]) -> None:
        """批量插入KEV数据"""
        if not batch:
            return

        query = """
            INSERT INTO kev (cve_id, exploited, due_date, short_description, notes)
            VALUES (%(cve_id)s, %(exploited)s, %(due_date)s, %(short_description)s, %(notes)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                exploited = EXCLUDED.exploited,
                due_date = EXCLUDED.due_date,
                short_description = EXCLUDED.short_description,
                notes = EXCLUDED.notes
        """

        try:
            with self.conn.get_cursor() as cursor:
                cursor.executemany(query, batch)
            self.records_inserted = len(batch)
        except Exception:
            for item in batch:
                try:
                    self._insert_kev(item)
                except:
                    pass

    def _insert_kev(self, kev_data: Dict) -> bool:
        """插入KEV数据"""
        query = """
            INSERT INTO kev (cve_id, exploited, due_date, short_description, notes)
            VALUES (%(cve_id)s, %(exploited)s, %(due_date)s, %(short_description)s, %(notes)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                exploited = EXCLUDED.exploited,
                due_date = EXCLUDED.due_date,
                short_description = EXCLUDED.short_description,
                notes = EXCLUDED.notes
        """
        try:
            self.conn.execute(query, kev_data)
            return True
        except Exception:
            return False
