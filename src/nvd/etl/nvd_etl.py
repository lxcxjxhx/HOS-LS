import json
import re
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from tqdm import tqdm
from .base import BaseETL

class NVDETL(BaseETL):
    """NVD数据ETL处理器（CVSS和CPE）- 适配NVD单文件JSON格式"""

    ETL_NAME = "nvd"

    CPE_PATTERN = re.compile(
        r'cpe:2\.3:([a-z]):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)'
    )

    def __init__(self, connection=None):
        super().__init__(connection)
        self._print_header()

    def _print_header(self) -> None:
        """打印美化标题"""
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                     NVD 数据入库                            ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║  数据源: NVD JSON feeds (CVE-年/CVE-年-xxxx/CVE-*.json)  ║")
        print("║  说明: CVSS 3.1/2.0 评分和 CPE 配置信息                   ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    def process(self, data_path: str) -> bool:
        """处理NVD数据"""
        data_dir = Path(data_path)

        json_files = list(data_dir.glob("CVE-*/CVE-*-*/CVE-*.json"))

        if not json_files:
            json_files = list(data_dir.glob("**/CVE-*.json"))

        if not json_files:
            print(f"╔══════════════════════════════════════════════════════════════╗")
            print(f"║  ✗ 未找到NVD JSON文件: {data_path:<36} ║")
            print(f"║  提示: NVD数据需要从 NIST 下载:                            ║")
            print(f"║        https://nvd.nist.gov/developers/vulnerabilities      ║")
            print(f"╚══════════════════════════════════════════════════════════════╝")
            return False

        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║  📂 发现 {len(json_files)} 个NVD文件                              ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")

        total_cvss = 0
        total_cpe = 0
        batch_cvss = []
        batch_cpe = []
        batch_size = 1000

        for json_file in tqdm(json_files, desc="  处理进度", unit="文件", ncols=70):
            try:
                self.records_processed += 1
                cve_id, cvss_data, cpe_list = self._process_json_file(json_file)

                if cvss_data:
                    batch_cvss.append(cvss_data)
                    total_cvss += 1

                batch_cpe.extend(cpe_list)
                total_cpe += len(cpe_list)

                if len(batch_cvss) >= batch_size:
                    self._batch_insert_cvss(batch_cvss)
                    batch_cvss = []

                if len(batch_cpe) >= batch_size:
                    self._batch_insert_cpe(batch_cpe)
                    batch_cpe = []

            except Exception as e:
                self.records_skipped += 1

        if batch_cvss:
            self._batch_insert_cvss(batch_cvss)

        if batch_cpe:
            self._batch_insert_cpe(batch_cpe)

        self._print_summary(total_cvss, total_cpe)
        return True

    def _print_summary(self, cvss_count: int, cpe_count: int) -> None:
        """打印美化汇总"""
        total = self.records_processed
        skipped = self.records_skipped

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                     NVD 数据入库完成                        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║  CVE文件处理: {total:>6} 个                                      ║")
        print(f"║  CVSS插入:   {cvss_count:>6} 条                                      ║")
        print(f"║  CPE插入:    {cpe_count:>6} 条                                      ║")
        print(f"║  跳过:       {skipped:>6} 条                                      ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    def _process_json_file(self, json_file: Path) -> Tuple[str, Optional[Dict], List[Dict]]:
        """处理单个NVD JSON文件，返回(cve_id, cvss_data, cpe_list)"""
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        cve_id = data.get('id', '')
        if not cve_id:
            return '', None, []

        cvss_data = self._extract_cvss(data, cve_id)
        cpe_list = self._extract_cpe(data, cve_id)

        return cve_id, cvss_data, cpe_list

    def _extract_cvss(self, data: Dict, cve_id: str) -> Optional[Dict]:
        """提取CVSS数据"""
        metrics = data.get('metrics', {})

        cvss_v31_list = metrics.get('cvssMetricV31', [])
        if cvss_v31_list:
            cvss_v31 = cvss_v31_list[0].get('cvssData', {})
            if cvss_v31:
                return {
                    'cve_id': cve_id,
                    'score': cvss_v31.get('baseScore'),
                    'severity': cvss_v31.get('baseSeverity'),
                    'vector': cvss_v31.get('vectorString', ''),
                    'version': '3.1'
                }

        cvss_v30_list = metrics.get('cvssMetricV30', [])
        if cvss_v30_list:
            cvss_v30 = cvss_v30_list[0].get('cvssData', {})
            if cvss_v30:
                return {
                    'cve_id': cve_id,
                    'score': cvss_v30.get('baseScore'),
                    'severity': cvss_v30.get('baseSeverity'),
                    'vector': cvss_v30.get('vectorString', ''),
                    'version': '3.0'
                }

        cvss_v2_list = metrics.get('cvssMetricV2', [])
        if cvss_v2_list:
            cvss_v2 = cvss_v2_list[0].get('cvssData', {})
            if cvss_v2:
                return {
                    'cve_id': cve_id,
                    'score': cvss_v2.get('baseScore'),
                    'severity': cvss_v2_list[0].get('baseSeverity', ''),
                    'vector': cvss_v2.get('vectorString', ''),
                    'version': '2.0'
                }

        return None

    def _extract_cpe(self, data: Dict, cve_id: str) -> List[Dict]:
        """提取CPE配置列表"""
        cpe_list = []
        configurations = data.get('configurations', [])

        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    cpe_data = self._parse_cpe(cpe, cve_id)
                    if cpe_data:
                        cpe_list.append(cpe_data)

        return cpe_list

    def _parse_cpe(self, cpe_match: Dict, cve_id: str) -> Optional[Dict]:
        """解析CPE字符串"""
        cpe_str = cpe_match.get('criteria', '')

        match = self.CPE_PATTERN.match(cpe_str)
        if not match:
            return None

        parts = match.groups()

        return {
            'cve_id': cve_id,
            'vendor': parts[1],
            'product': parts[2],
            'version': parts[3],
            'version_start': cpe_match.get('versionStartIncluding', ''),
            'version_end': cpe_match.get('versionEndExcluding', ''),
            'version_start_type': 'including' if cpe_match.get('versionStartIncluding') else None,
            'version_end_type': 'excluding' if cpe_match.get('versionEndExcluding') else 'including' if cpe_match.get('versionEndIncluding') else None
        }

    def _batch_insert_cvss(self, batch: List[Dict]) -> None:
        """批量插入CVSS数据"""
        if not batch:
            return

        query = """
            INSERT INTO cvss (cve_id, score, severity, vector, version)
            VALUES (%(cve_id)s, %(score)s, %(severity)s, %(vector)s, %(version)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                score = EXCLUDED.score,
                severity = EXCLUDED.severity,
                vector = EXCLUDED.vector,
                version = EXCLUDED.version
        """

        try:
            with self.conn.get_cursor() as cursor:
                cursor.executemany(query, batch)
            self.records_inserted += len(batch)
        except Exception:
            for item in batch:
                try:
                    self._insert_cvss(item)
                    self.records_inserted += 1
                except:
                    pass

    def _batch_insert_cpe(self, batch: List[Dict]) -> None:
        """批量插入CPE数据"""
        if not batch:
            return

        query = """
            INSERT INTO cpe (cve_id, vendor, product, version,
                          version_start, version_end, version_start_type, version_end_type)
            VALUES (%(cve_id)s, %(vendor)s, %(product)s, %(version)s,
                   %(version_start)s, %(version_end)s, %(version_start_type)s, %(version_end_type)s)
        """

        try:
            with self.conn.get_cursor() as cursor:
                cursor.executemany(query, batch)
        except Exception:
            for item in batch:
                try:
                    self._insert_cpe(item)
                except:
                    pass

    def _insert_cvss(self, cvss_data: Dict) -> None:
        """插入CVSS数据"""
        query = """
            INSERT INTO cvss (cve_id, score, severity, vector, version)
            VALUES (%(cve_id)s, %(score)s, %(severity)s, %(vector)s, %(version)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                score = EXCLUDED.score,
                severity = EXCLUDED.severity,
                vector = EXCLUDED.vector,
                version = EXCLUDED.version
        """
        self.conn.execute(query, cvss_data)

    def _insert_cpe(self, cpe_data: Dict) -> None:
        """插入CPE数据"""
        query = """
            INSERT INTO cpe (cve_id, vendor, product, version,
                          version_start, version_end, version_start_type, version_end_type)
            VALUES (%(cve_id)s, %(vendor)s, %(product)s, %(version)s,
                   %(version_start)s, %(version_end)s, %(version_start_type)s, %(version_end_type)s)
        """
        self.conn.execute(query, cpe_data)
