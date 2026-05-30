import os
import hashlib
import zipfile
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List, Dict
from .db.connection import NVDConnection

DATA_SOURCES = {
    'cvelistV5': {
        'url': 'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip',
        'zip_file': 'cvelistV5-main.zip',
        'extract_dir': 'cvelistV5'
    },
    'nvd': {
        'url': 'https://github.com/fkie-cad/nvd-json-data-feeds/archive/refs/heads/main.zip',
        'zip_file': 'nvd-json-data-feeds-main.zip',
        'extract_dir': 'nvd-json-data-feeds'
    },
    'cwe': {
        'url': 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
        'zip_file': 'cwec_latest.xml.zip',
        'extract_dir': 'cwec'
    },
    'kev': {
        'url': 'https://github.com/cisagov/kev-data/archive/refs/heads/develop.zip',
        'zip_file': 'kev-data-develop.zip',
        'extract_dir': 'kev-data'
    },
    'exploitdb': {
        'url': 'https://github.com/offensive-security/exploitdb/archive/refs/heads/main.zip',
        'zip_file': 'exploitdb-main.zip',
        'extract_dir': 'exploitdb'
    },
    'poc': {
        'url': 'https://github.com/nomi-sec/PoC-in-GitHub/archive/refs/heads/master.zip',
        'zip_file': 'PoC-in-GitHub-master.zip',
        'extract_dir': 'PoC-in-GitHub'
    }
}

@dataclass
class DownloadRecord:
    """下载记录"""
    source: str
    file_name: str
    downloaded_at: datetime
    file_size: int
    checksum: str
    version: str = ""

class DownloadManager:
    """下载管理器"""

    BASE_DIR = Path(r"c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\All Vulnerabilities")
    TEMP_ZIP_DIR = BASE_DIR / "temp_zip"
    TEMP_DATA_DIR = BASE_DIR / "temp_data"

    def __init__(self, connection: Optional[NVDConnection] = None):
        self.conn = connection or NVDConnection.get_instance()
        self.TEMP_ZIP_DIR.mkdir(parents=True, exist_ok=True)
        self.TEMP_DATA_DIR.mkdir(parents=True, exist_ok=True)

    def get_zip_path(self, source: str) -> Path:
        """获取压缩包路径"""
        return self.TEMP_ZIP_DIR / DATA_SOURCES[source]['zip_file']

    def get_extract_path(self, source: str) -> Path:
        """获取解压目录路径"""
        return self.TEMP_DATA_DIR / DATA_SOURCES[source]['extract_dir']

    def calculate_checksum(self, file_path: Path) -> str:
        """计算SHA256校验和"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def is_already_downloaded(self, source: str) -> bool:
        """检查是否已下载（通过checksum验证）"""
        zip_path = self.get_zip_path(source)
        if not zip_path.exists():
            return False

        current_checksum = self.calculate_checksum(zip_path)
        query = """
            SELECT checksum FROM download_records
            WHERE source = %s AND file_name = %s
        """
        result = self.conn.fetch_one(query, (source, DATA_SOURCES[source]['zip_file']))
        return result and result[0] == current_checksum

    def download_from_local(self, source: str) -> bool:
        """从本地压缩包导入"""
        zip_path = self.get_zip_path(source)
        if not zip_path.exists():
            print(f"本地压缩包不存在: {zip_path}")
            return False

        if self.is_already_downloaded(source):
            print(f"{source} 已下载且验证通过")
            return True

        extract_path = self.get_extract_path(source)
        print(f"解压 {zip_path} 到 {extract_path}")

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(self.TEMP_DATA_DIR)

        file_size = zip_path.stat().st_size
        checksum = self.calculate_checksum(zip_path)

        self._save_download_record(source, DATA_SOURCES[source]['zip_file'], file_size, checksum)
        print(f"{source} 解压完成")
        return True

    def download(self, source: str) -> bool:
        """下载数据（优先使用本地）"""
        if self.get_zip_path(source).exists():
            return self.download_from_local(source)
        return self.download_from_local(source)

    def download_all(self) -> Dict[str, bool]:
        """下载所有数据源"""
        results = {}
        for source in DATA_SOURCES.keys():
            print(f"\n处理 {source}...")
            results[source] = self.download(source)
        return results

    def _save_download_record(self, source: str, file_name: str, file_size: int, checksum: str) -> None:
        """保存下载记录"""
        query = """
            INSERT INTO download_records (source, file_name, file_size, checksum, downloaded_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (source, file_name)
            DO UPDATE SET
                file_size = EXCLUDED.file_size,
                checksum = EXCLUDED.checksum,
                downloaded_at = EXCLUDED.downloaded_at
        """
        self.conn.execute(query, (source, file_name, file_size, checksum, datetime.now()))

    def get_local_sources(self) -> List[str]:
        """获取本地已有的数据源"""
        sources = []
        for source in DATA_SOURCES.keys():
            if self.get_zip_path(source).exists():
                sources.append(source)
        return sources
