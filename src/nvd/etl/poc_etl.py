import json
import re
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime
from tqdm import tqdm
from .base import BaseETL

class PoCETL(BaseETL):
    """PoC-in-GitHub数据ETL处理器 - 适配GitHub API导出格式"""

    ETL_NAME = "poc"

    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}')

    def __init__(self, connection=None):
        super().__init__(connection)
        self._print_header()

    def _print_header(self) -> None:
        """打印美化标题"""
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                     PoC 数据入库                            ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║  数据源: PoC-in-GitHub (GitHub API导出)                     ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    def process(self, data_path: str) -> bool:
        """处理PoC数据"""
        data_dir = Path(data_path)

        json_files = list(data_dir.glob('**/*.json'))

        if not json_files:
            print(f"╔══════════════════════════════════════════════════════════════╗")
            print(f"║  ✗ 未找到PoC JSON文件: {data_path:<36} ║")
            print(f"╚══════════════════════════════════════════════════════════════╝")
            return False

        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║  📂 发现 {len(json_files)} 个PoC文件                                  ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")

        batch_size = 1000
        batch = []

        for json_file in tqdm(json_files, desc="  处理进度", unit="文件", ncols=70):
            try:
                results = self._process_single_file(json_file)
                for result in results:
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

    def _process_single_file(self, json_file: Path) -> List[Optional[Dict]]:
        """处理单个PoC JSON文件 - 可能包含多个PoC仓库"""
        results = []
        try:
            with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)

            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = [data]
            else:
                return results

            for item in items:
                poc_data = self._extract_poc_data(item)
                if poc_data:
                    results.append(poc_data)
        except Exception:
            pass
        return results

    def _extract_poc_data(self, item: Dict) -> Optional[Dict]:
        """从GitHub仓库信息提取PoC数据"""
        try:
            cve_id = ''

            name = item.get('name', '')
            if name:
                matches = self.CVE_PATTERN.findall(name)
                if matches:
                    cve_id = matches[0]

            if not cve_id:
                full_name = item.get('full_name', '')
                if full_name:
                    matches = self.CVE_PATTERN.findall(full_name)
                    if matches:
                        cve_id = matches[0]

            if not cve_id:
                description = str(item.get('description', ''))
                if description:
                    matches = self.CVE_PATTERN.findall(description)
                    if matches:
                        cve_id = matches[0]

            if not cve_id:
                body = str(item.get('body', ''))
                matches = self.CVE_PATTERN.findall(body)
                if matches:
                    cve_id = matches[0]

            if not cve_id:
                return None

            if not cve_id.startswith('CVE-'):
                cve_id = f'CVE-{cve_id}'

            stars = item.get('stargazers_count', 0) or item.get('stars', 0) or 0

            return {
                'cve_id': cve_id,
                'repo_url': item.get('html_url', '') or f"https://github.com/{item.get('full_name', '')}",
                'stars': int(stars),
                'language': item.get('language', ''),
                'description': item.get('description', ''),
                'last_updated': datetime.now()
            }
        except Exception:
            return None

    def _print_summary(self) -> None:
        """打印美化汇总"""
        total = self.records_processed
        inserted = self.records_inserted
        skipped = self.records_skipped
        success_rate = (inserted / total * 100) if total > 0 else 0

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                     PoC 数据入库完成                          ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║  总处理: {total:>6} 条                                              ║")
        print(f"║  插入:   {inserted:>6} 条  ({success_rate:.1f}%)                               ║")
        print(f"║  跳过:   {skipped:>6} 条                                              ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    def _batch_insert(self, batch: List[Dict]) -> int:
        """批量插入PoC数据，返回插入数量"""
        if not batch:
            return 0

        query = """
            INSERT INTO poc (cve_id, repo_url, stars, language, description, last_updated)
            VALUES (%(cve_id)s, %(repo_url)s, %(stars)s, %(language)s, %(description)s, %(last_updated)s)
            ON CONFLICT (cve_id, repo_url) DO UPDATE SET
                stars = EXCLUDED.stars,
                language = EXCLUDED.language,
                description = EXCLUDED.description,
                last_updated = EXCLUDED.last_updated
        """

        try:
            with self.conn.get_cursor() as cursor:
                cursor.executemany(query, batch)
            return len(batch)
        except Exception:
            count = 0
            for item in batch:
                try:
                    if self._insert_or_update_poc(item):
                        count += 1
                except:
                    pass
            return count

    def _insert_or_update_poc(self, poc_data: Dict) -> bool:
        """插入或更新PoC数据"""
        query = """
            INSERT INTO poc (cve_id, repo_url, stars, language, description, last_updated)
            VALUES (%(cve_id)s, %(repo_url)s, %(stars)s, %(language)s, %(description)s, %(last_updated)s)
            ON CONFLICT (cve_id, repo_url) DO UPDATE SET
                stars = EXCLUDED.stars,
                language = EXCLUDED.language,
                description = EXCLUDED.description,
                last_updated = EXCLUDED.last_updated
        """
        try:
            self.conn.execute(query, poc_data)
            return True
        except Exception:
            return False

    def _batch_insert(self, batch: List[Dict]) -> int:
        """批量插入PoC数据，返回插入数量 - SQLite兼容"""
        if not batch:
            return 0

        query = """
            INSERT INTO poc (cve_id, repo_url, stars, language, description, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
        """

        try:
            with self.conn.get_connection() as conn:
                cursor = conn.cursor()
                for item in batch:
                    try:
                        cursor.execute(query, (
                            item.get('cve_id'),
                            item.get('repo_url'),
                            item.get('stars', 0),
                            item.get('language', ''),
                            item.get('description', ''),
                            item.get('last_updated')
                        ))
                    except Exception:
                        pass
            return len(batch)
        except Exception as e:
            print(f"    ⚠ 批量插入失败: {e}")
            return 0
