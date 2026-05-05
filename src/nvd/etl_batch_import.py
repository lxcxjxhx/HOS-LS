import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass
from tqdm import tqdm

from .db.sqlite_connection import SQLiteConnection
from .db.sqlite_schema import SQLiteSche
from .etl.base import BaseETL
from .etl.cve_etl import CVEETL
from .etl.kev_etl import KEVETL
from .etl.nvd_etl import NVDETL
from .etl.poc_etl import PoCETL
from .etl.exploit_etl import ExploitETL
from .etl.cwe_etl import CWEETL

@dataclass
class ETLProgress:
    etl_name: str
    last_file: str
    last_index: int
    processed_count: int
    inserted_count: int
    skipped_count: int
    status: str
    started_at: datetime
    updated_at: datetime

class BatchImportManager:
    """批量入库管理器 - SQLite版本"""

    ETL_MODULES = {
        'cve': CVEETL,
        'kev': KEVETL,
        'nvd': NVDETL,
        'poc': PoCETL,
        'exploit': ExploitETL,
        'cwe': CWEETL,
    }

    ETL_ORDER = ['cve', 'kev', 'nvd', 'cwe', 'poc', 'exploit']

    DATA_PATHS = {
        'kev': 'kev-data-develop',
        'cve': 'cvelistV5-main',
        'nvd': 'nvd-json-data-feeds-main',
        'poc': 'PoC-in-GitHub-master',
        'exploit': 'exploitdb-main',
        'cwe': '',
    }

    BATCH_SIZE = 1000
    CHECKPOINT_INTERVAL = 100

    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.conn = SQLiteConnection.get_instance()
        self.schema = SQLiteSche(self.conn)
        self.progress: Dict[str, ETLProgress] = {}
        self._shutdown_requested = False
        self._current_etl = None

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """处理中断信号，优雅停止"""
        if self._shutdown_requested:
            print("\n╔══════════════════════════════════════════════════════════════╗")
            print("║  强制停止中...请等待当前批次完成                      ║")
            print("╚══════════════════════════════════════════════════════════════╝")
            sys.exit(1)

        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║  收到停止信号，正在保存断点...请稍候                      ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        self._shutdown_requested = True

        if self._current_etl:
            self._save_checkpoint(self._current_etl)

    def init_database(self) -> None:
        """初始化数据库Schema"""
        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                     初始化数据库                            ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        self.schema.init_schema()
        print("║  ✓ 数据库Schema初始化完成                                    ║")
        print("║  ✓ 数据库文件: nvd_vulnerability.db                         ║")

    def get_progress(self, etl_name: str) -> Optional[ETLProgress]:
        """获取ETL进度"""
        query = """
            SELECT etl_name, last_processed_file, last_processed_index,
                   processed_count, inserted_count, skipped_count, status,
                   started_at, updated_at
            FROM etl_progress WHERE etl_name = ?
        """
        result = self.conn.fetch_one(query, (etl_name,))
        if result:
            row = result if isinstance(result, (list, tuple)) else tuple(result)
            return ETLProgress(
                etl_name=row[0],
                last_file=row[1],
                last_index=row[2] or 0,
                processed_count=row[3] or 0,
                inserted_count=row[4] or 0,
                skipped_count=row[5] or 0,
                status=row[6],
                started_at=row[7],
                updated_at=row[8]
            )
        return None

    def get_all_progress(self) -> Dict[str, ETLProgress]:
        """获取所有ETL进度"""
        query = "SELECT * FROM etl_progress ORDER BY etl_name"
        results = self.conn.fetch_all(query)
        progress_dict = {}
        for row in results:
            row = tuple(row) if not isinstance(row, (list, tuple)) else row
            progress_dict[row[1]] = ETLProgress(
                etl_name=row[1],
                last_file=row[2],
                last_index=row[3] or 0,
                processed_count=row[4] or 0,
                inserted_count=row[5] or 0,
                skipped_count=row[6] or 0,
                status=row[7],
                started_at=row[8],
                updated_at=row[9]
            )
        return progress_dict

    def _save_checkpoint(self, etl_name: str, last_file: str = None,
                       last_index: int = 0, processed: int = 0,
                       inserted: int = 0, skipped: int = 0,
                       status: str = 'running', error: str = None) -> None:
        """保存断点 - SQLite版本"""
        now = datetime.now().isoformat()
        query = """
            INSERT INTO etl_progress (etl_name, last_processed_file, last_processed_index,
                                     processed_count, inserted_count, skipped_count,
                                     status, updated_at, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            self.conn.execute(query, (etl_name, last_file, last_index, processed,
                                    inserted, skipped, status, now, error))
        except Exception:
            update_query = """
                UPDATE etl_progress SET
                    last_processed_file = ?,
                    last_processed_index = ?,
                    processed_count = ?,
                    inserted_count = ?,
                    skipped_count = ?,
                    status = ?,
                    updated_at = ?,
                    error_message = ?
                WHERE etl_name = ?
            """
            self.conn.execute(update_query, (last_file, last_index, processed,
                                            inserted, skipped, status, now, error, etl_name))

    def reset_progress(self, etl_name: str = None) -> None:
        """重置进度"""
        if etl_name:
            query = "DELETE FROM etl_progress WHERE etl_name = ?"
            self.conn.execute(query, (etl_name,))
            print(f"║  ✓ 已重置 {etl_name} 进度                                     ║")
        else:
            query = "DELETE FROM etl_progress"
            self.conn.execute(query)
            print("║  ✓ 已重置所有进度                                          ║")

    def run_etl(self, etl_name: str, data_path: str, continue_mode: bool = False) -> bool:
        """运行单个ETL"""
        if self._shutdown_requested:
            print(f"║  ⏸ 已跳过 {etl_name} (等待停止)                              ║")
            return False

        self._current_etl = etl_name

        etl_class = self.ETL_MODULES.get(etl_name)
        if not etl_class:
            print(f"║  ✗ 未知ETL模块: {etl_name}                                    ║")
            return False

        progress = self.get_progress(etl_name) if continue_mode else None

        if progress and progress.status == 'completed':
            print(f"║  ⏩ 跳过 {etl_name} (已完成)                                   ║")
            return True

        print(f"\n╔══════════════════════════════════════════════════════════════╗")
        print(f"║               {etl_name.upper()} 数据入库                              ║")
        print(f"╠══════════════════════════════════════════════════════════════╣")

        if progress and continue_mode:
            print(f"║  📂 断点续传: {progress.last_file[:40]}...               ║")
            print(f"║  📊 已处理: {progress.processed_count} 条                                ║")
        else:
            self._save_checkpoint(etl_name, status='running')
            print(f"║  📂 数据路径: {data_path[:50]}                             ║")

        print(f"╚══════════════════════════════════════════════════════════════╝")

        try:
            etl = etl_class(self.conn)
            result = etl.process(data_path)

            if result and not self._shutdown_requested:
                self._save_checkpoint(etl_name,
                                     last_file='',
                                     last_index=0,
                                     processed=etl.records_processed,
                                     inserted=etl.records_inserted,
                                     skipped=etl.records_skipped,
                                     status='completed')
                print(f"\n║  ✓ {etl_name} 入库完成                                        ║")
            else:
                print(f"\n║  ⏸ {etl_name} 入库暂停                                        ║")

            return result

        except Exception as e:
            import traceback
            self._save_checkpoint(etl_name, status='failed', error=str(e))
            print(f"\n║  ✗ {etl_name} 入库失败: {str(e)[:50]}              ║")
            print(f"║  {traceback.format_exc()[:80]}              ║")
            return False
        finally:
            self._current_etl = None

    def run_all(self, continue_mode: bool = False) -> Dict[str, bool]:
        """运行所有ETL"""
        print("\n" + "═" * 64)
        print("                     漏洞数据批量入库系统")
        print("═" * 64)

        results = {}

        for etl_name in self.ETL_ORDER:
            if etl_name == 'cwe':
                data_path = str(self.base_path / 'cwec_v4.19.1.xml')
            else:
                data_path = str(self.base_path / self.DATA_PATHS[etl_name])

            if not Path(data_path).exists():
                print(f"║  ⚠ 路径不存在: {data_path}                      ║")
                continue

            success = self.run_etl(etl_name, data_path, continue_mode)
            results[etl_name] = success

            if self._shutdown_requested:
                print("\n╔══════════════════════════════════════════════════════════════╗")
                print("║  已暂停批量入库，已保存断点                                  ║")
                print("║  重新运行使用: python -m src.nvd.etl_batch_import --continue ║")
                print("╚══════════════════════════════════════════════════════════════╝")
                break

        return results

    def show_status(self) -> None:
        """显示当前进度状态"""
        progress_dict = self.get_all_progress()

        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                     入库进度状态                            ║")
        print("╠══════════════════════════════════════════════════════════════╣")

        if not progress_dict:
            print("║  暂无入库记录                                               ║")
        else:
            for etl_name in self.ETL_ORDER:
                if etl_name in progress_dict:
                    p = progress_dict[etl_name]
                    status_icon = {'pending': '⏳', 'running': '🔄', 'completed': '✅', 'failed': '❌'}.get(p.status, '❓')
                    print(f"║  {status_icon} {etl_name.upper():8} | {p.status:10} | 已处理: {p.processed_count:>6} | 插入: {p.inserted_count:>6}  ║")
                else:
                    print(f"║  ⬜ {etl_name.upper():8} | 未开始                                         ║")

        print("╚══════════════════════════════════════════════════════════════╝")

def main():
    import argparse

    parser = argparse.ArgumentParser(description='漏洞数据批量入库系统 (SQLite)')
    parser.add_argument('--base-path', default=r'c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\All Vulnerabilities\temp_zip',
                       help='数据根目录路径')
    parser.add_argument('--continue', dest='continue_mode', action='store_true',
                       help='从断点继续')
    parser.add_argument('--reset', action='store_true',
                       help='重置进度重新开始')
    parser.add_argument('--etl', choices=['cve', 'kev', 'nvd', 'poc', 'exploit', 'cwe'],
                       help='指定单个ETL模块')
    parser.add_argument('--status', action='store_true',
                       help='显示当前进度')

    args = parser.parse_args()

    manager = BatchImportManager(args.base_path)

    if args.status:
        manager.show_status()
        return

    if args.reset:
        if args.etl:
            manager.reset_progress(args.etl)
        else:
            manager.reset_progress()
        print("║  ✓ 进度已重置                                               ║")

    manager.init_database()

    if args.etl:
        if args.etl == 'cwe':
            data_path = str(Path(args.base_path) / 'cwec_v4.19.1.xml')
        else:
            data_path = str(Path(args.base_path) / manager.DATA_PATHS.get(args.etl, ''))
        manager.run_etl(args.etl, data_path, args.continue_mode)
    else:
        manager.run_all(args.continue_mode)

if __name__ == '__main__':
    main()
