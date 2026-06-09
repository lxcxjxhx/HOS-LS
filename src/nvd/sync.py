import click
from pathlib import Path
from typing import Optional, Dict
from .downloader import DownloadManager
from .db.connection import NVDConnection
from .db.schema import NVDSche
from .etl.cve_etl import CVEETL
from .etl.nvd_etl import NVDETL
from .etl.cwe_etl import CWEETL
from .etl.kev_etl import KEVETL
from .etl.exploit_etl import ExploitETL
from .etl.poc_etl import PoCETL

class NVDDataSync:
    """NVD数据同步调度器"""

    ETL_MAPPING = {
        'cvelistV5': CVEETL,
        'nvd': NVDETL,
        'cwe': CWEETL,
        'kev': KEVETL,
        'exploitdb': ExploitETL,
        'poc': PoCETL,
    }

    DATA_DIRS = {
        'cvelistV5': 'cvelistV5',
        'nvd': 'nvd-json-data-feeds',
        'cwe': 'cwec',
        'kev': 'kev-data',
        'exploitdb': 'exploitdb',
        'poc': 'PoC-in-GitHub',
    }

    def __init__(self):
        self.connection = NVDConnection.get_instance()
        self.download_manager = DownloadManager(self.connection)
        self.schema = NVDSche(self.connection)

    def sync_all(self) -> Dict[str, bool]:
        """同步所有数据源"""
        results = {}

        print("=" * 50)
        print("NVD数据同步开始")
        print("=" * 50)

        self._download()

        print("\n开始ETL处理...")
        results['etl'] = self._run_all_etl()

        print("\n刷新物化视图...")
        self.schema.refresh_materialized_view()

        print("\n同步完成!")
        return results

    def _download(self) -> None:
        """下载数据"""
        print("\n检查本地数据源...")
        local_sources = self.download_manager.get_local_sources()

        if local_sources:
            print(f"找到本地数据源: {', '.join(local_sources)}")
            self.download_manager.download_all()
        else:
            print("未找到本地数据源，请先将压缩包放入 temp_zip 目录")

    def _run_all_etl(self) -> bool:
        """运行所有ETL"""
        base_path = r"c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\All Vulnerabilities\temp_data"

        for source, etl_class in self.ETL_MAPPING.items():
            print(f"\n处理 {source}...")
            data_path = Path(base_path) / self.DATA_DIRS[source]

            if not data_path.exists():
                print(f"  数据目录不存在: {data_path}")
                continue

            etl = etl_class(self.connection)
            try:
                etl.run(str(data_path))
                print(f"  完成: 处理 {etl.records_processed} 条, 插入 {etl.records_inserted} 条, 跳过 {etl.records_skipped} 条")
            except Exception as e:
                print(f"  错误: {e}")

        return True

    def sync_source(self, source: str) -> bool:
        """同步指定数据源"""
        if source not in self.ETL_MAPPING:
            print(f"未知数据源: {source}")
            return False

        print(f"同步数据源: {source}")

        self.download_manager.download(source)

        etl_class = self.ETL_MAPPING[source]
        data_path = Path(r"c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\All Vulnerabilities\temp_data") / self.DATA_DIRS[source]

        if not data_path.exists():
            print(f"数据目录不存在: {data_path}")
            return False

        etl = etl_class(self.connection)
        result = etl.run(str(data_path))

        if result:
            self.schema.refresh_materialized_view()

        return result
