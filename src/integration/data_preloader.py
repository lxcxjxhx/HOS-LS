"""数据预加载模块

实现从 download_source_link.txt 读取数据源 URL，自动下载和解压数据源。
支持智能增量下载和动态路径解析。
"""

import re
import os
import hashlib
import zipfile
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from tqdm import tqdm

from src.utils.logger import get_logger
from src.nvd.db.sqlite_connection import SQLiteConnection

logger = get_logger(__name__)


@dataclass
class DataPathResolver:
    """动态路径解析器"""

    _project_root: Optional[Path] = field(default=None, init=False)

    @classmethod
    def get_project_root(cls) -> Path:
        """获取项目根目录

        自动检测包含 hos-ls.yaml 或 src/ 目录的路径

        Returns:
            项目根目录路径
        """
        if cls._project_root is not None:
            return cls._project_root

        current = Path(__file__).resolve()
        for parent in [current] + list(current.parents):
            if (parent / "hos-ls.yaml").exists() or (parent / "hos-ls.yml").exists():
                cls._project_root = parent
                logger.debug(f"检测到项目根目录: {cls._project_root}")
                return cls._project_root
            if (parent / "src").is_dir() and (parent / "src" / "cli").is_dir():
                cls._project_root = parent
                logger.debug(f"检测到项目根目录 (via src/): {cls._project_root}")
                return cls._project_root

        cls._project_root = current.parent.parent.parent
        logger.warning(f"未检测到项目根目录，使用默认路径: {cls._project_root}")
        return cls._project_root

    @classmethod
    def resolve_all_vulnerabilities_path(cls, relative_path: str = "All Vulnerabilities") -> Path:
        """解析 All Vulnerabilities 目录路径

        Args:
            relative_path: 相对于项目根目录的路径

        Returns:
            绝对路径
        """
        project_root = cls.get_project_root()
        resolved = project_root / relative_path
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved

    @classmethod
    def resolve_data_path(cls, relative_path: str) -> Path:
        """解析数据路径

        Args:
            relative_path: 相对路径（相对于 All Vulnerabilities 或绝对路径）

        Returns:
            绝对路径
        """
        if Path(relative_path).is_absolute():
            return Path(relative_path)

        if relative_path.startswith("All Vulnerabilities"):
            return cls.resolve_all_vulnerabilities_path(relative_path)

        return cls.resolve_all_vulnerabilities_path() / relative_path


def get_default_base_dir() -> Path:
    """获取默认的 All Vulnerabilities 目录"""
    return DataPathResolver.resolve_all_vulnerabilities_path()


BASE_DIR = get_default_base_dir()
SOURCES_FILE = BASE_DIR / "download_source_link.txt"
TEMP_ZIP_DIR = BASE_DIR / "temp_zip"
TEMP_DATA_DIR = BASE_DIR / "temp_data"


@dataclass
class DataSourceConfig:
    """数据源配置"""
    urls: List[str] = field(default_factory=list)
    sources_file: Path = field(default_factory=lambda: SOURCES_FILE)

    def __post_init__(self):
        if self.sources_file and self.sources_file.exists():
            self.load_from_file()

    def load_from_file(self) -> None:
        """从文件加载数据源 URL

        文件格式：每行一个 URL，支持 # 注释和空行
        """
        self.urls = []
        if not self.sources_file.exists():
            logger.warning(f"数据源配置文件不存在: {self.sources_file}")
            return

        try:
            with open(self.sources_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if self._is_valid_url(line):
                        self.urls.append(line)
                    else:
                        logger.warning(f"无效的 URL 格式 (第 {line_num} 行): {line}")
            logger.info(f"从 {self.sources_file} 加载了 {len(self.urls)} 个数据源")
        except Exception as e:
            logger.error(f"读取数据源配置文件失败: {e}")

    def _is_valid_url(self, url: str) -> bool:
        """验证 URL 格式"""
        try:
            result = urlparse(url)
            return all([result.scheme in ('http', 'https', 'git'),
                       result.netloc or (url.startswith('git+') and '://' in url)])
        except Exception:
            return False

    def get_source_name(self, url: str) -> str:
        """从 URL 提取数据源名称"""
        parsed = urlparse(url)
        path = parsed.path.strip('/')
        parts = path.split('/')

        if 'github.com' in parsed.netloc and len(parts) >= 2:
            return parts[1].replace('.git', '')
        elif 'gitlab.com' in parsed.netloc and len(parts) >= 2:
            return parts[1].replace('.git', '')
        elif parsed.netloc == 'cwe.mitre.org':
            return 'cwec'
        else:
            name = parts[-1].replace('.git', '') if parts else 'unknown'
            return name

    def get_zip_file_name(self, url: str) -> str:
        """生成 ZIP 文件名"""
        name = self.get_source_name(url)
        parsed = urlparse(url)

        if 'github.com' in parsed.netloc:
            branch = self._extract_github_branch(url)
            return f"{name}-{branch}.zip"
        elif '.zip' in url.lower():
            return url.split('/')[-1]
        else:
            return f"{name}.zip"

    def _extract_github_branch(self, url: str) -> str:
        """从 GitHub URL 提取分支名"""
        if '/archive/refs/heads/' in url:
            return url.split('/archive/refs/heads/')[-1].replace('.zip', '')
        elif '/tree/' in url:
            parts = url.split('/tree/')
            if len(parts) > 1:
                branch = parts[1].split('?')[0]
                return branch
        return 'main'

    def convert_github_to_zip_url(self, url: str) -> str:
        """将 GitHub 仓库 URL 转换为 ZIP 下载 URL

        Args:
            url: GitHub 仓库 URL (如 https://github.com/user/repo)

        Returns:
            ZIP 下载 URL (如 https://github.com/user/repo/archive/refs/heads/main.zip)
        """
        parsed = urlparse(url)
        if parsed.netloc not in ('github.com', 'www.github.com'):
            return url

        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) < 2:
            return url

        repo = path_parts[1].replace('.git', '')
        branch = 'main'

        return f"https://github.com/{path_parts[0]}/{repo}/archive/refs/heads/{branch}.zip"


class SourceDownloader:
    """单个数据源下载器"""

    def __init__(
        self,
        url: str,
        temp_zip_dir: Path = TEMP_ZIP_DIR,
        temp_data_dir: Path = TEMP_DATA_DIR,
        timeout: int = 300,
        chunk_size: int = 8192,
        skip_on_checksum_match: bool = True,
        merge_strategy: str = "smart"
    ):
        self.url = url
        self.temp_zip_dir = Path(temp_zip_dir)
        self.temp_data_dir = Path(temp_data_dir)
        self.timeout = timeout
        self.chunk_size = chunk_size
        self.skip_on_checksum_match = skip_on_checksum_match
        self.merge_strategy = merge_strategy

        self.config = DataSourceConfig()
        self.source_name = self.config.get_source_name(url)
        self.zip_file_name = self.config.get_zip_file_name(url)
        self.zip_path = self.temp_zip_dir / self.zip_file_name
        self.extract_path = self.temp_data_dir / self.source_name

        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        """确保目录存在"""
        self.temp_zip_dir.mkdir(parents=True, exist_ok=True)
        self.temp_data_dir.mkdir(parents=True, exist_ok=True)

    def _convert_to_download_url(self) -> str:
        """转换 URL 为可下载的 ZIP URL"""
        parsed = urlparse(self.url)
        if parsed.netloc in ('github.com', 'www.github.com'):
            if '/archive/' not in self.url and '/tree/' not in self.url:
                return self.config.convert_github_to_zip_url(self.url)
            elif '/tree/' in self.url:
                branch = self.url.split('/tree/')[-1].split('?')[0]
                path_parts = parsed.path.strip('/').split('/')
                if len(path_parts) >= 2:
                    return f"https://github.com/{path_parts[0]}/{path_parts[1]}/archive/refs/heads/{branch}.zip"
        return self.url

    def calculate_checksum(self, file_path: Path) -> str:
        """计算 SHA256 校验和"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(self.chunk_size), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def get_local_checksum(self) -> Optional[str]:
        """获取本地文件的校验和"""
        if self.zip_path.exists():
            return self.calculate_checksum(self.zip_path)
        return None

    def should_download(self, force: bool = False) -> tuple[bool, str]:
        """智能判断是否需要下载

        Args:
            force: 是否强制下载

        Returns:
            (是否需要下载, 原因)
        """
        if force:
            return True, "强制下载"

        if not self.zip_path.exists():
            return True, "文件不存在"

        try:
            current_checksum = self.calculate_checksum(self.zip_path)
            conn = SQLiteConnection.get_instance()

            query = """
                SELECT checksum FROM download_records
                WHERE source = %s AND file_name = %s
            """
            result = conn.fetch_one(query, (self.source_name, self.zip_file_name))

            if result is None:
                return True, "无下载记录"

            recorded_checksum = result[0]
            if current_checksum != recorded_checksum:
                return True, f"校验和不一致 (本地: {current_checksum[:8]}..., 记录: {recorded_checksum[:8]}...)"

            if self.skip_on_checksum_match:
                return False, f"校验和一致，跳过下载 (已下载: {self.zip_path.name})"

            return True, "配置要求重新下载"

        except Exception as e:
            logger.warning(f"检查下载状态时出错: {e}")
            return True, f"检查失败: {e}"

    def is_downloaded(self) -> bool:
        """检查是否已下载（通过校验和验证）"""
        shouldDl, _ = self.should_download()
        return not shouldDl

    def download(self, show_progress: bool = True) -> bool:
        """下载文件

        Args:
            show_progress: 是否显示进度条

        Returns:
            下载是否成功
        """
        download_url = self._convert_to_download_url()
        logger.info(f"开始下载 {self.source_name}: {download_url}")

        try:
            response = requests.get(download_url, timeout=self.timeout, stream=True)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            file_size = 0

            if show_progress:
                with open(self.zip_path, 'wb') as f, tqdm(
                    desc=self.source_name,
                    total=total_size,
                    unit='B',
                    unit_scale=True,
                    unit_divisor=1024,
                ) as pbar:
                    for chunk in response.iter_content(chunk_size=self.chunk_size):
                        if chunk:
                            f.write(chunk)
                            file_size += len(chunk)
                            pbar.update(len(chunk))
            else:
                with open(self.zip_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=self.chunk_size):
                        if chunk:
                            f.write(chunk)
                            file_size += len(chunk)

            logger.info(f"下载完成: {self.zip_path} ({file_size} bytes)")
            return True

        except requests.exceptions.Timeout:
            logger.error(f"下载超时: {self.source_name}")
            self._cleanup_zip()
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"下载失败 ({self.source_name}): {e}")
            self._cleanup_zip()
            return False
        except IOError as e:
            logger.error(f"文件写入失败 ({self.source_name}): {e}")
            self._cleanup_zip()
            return False

    def _cleanup_zip(self) -> None:
        """清理不完整的 ZIP 文件"""
        if self.zip_path.exists():
            try:
                self.zip_path.unlink()
                logger.debug(f"已清理不完整的 ZIP 文件: {self.zip_path}")
            except Exception as e:
                logger.warning(f"清理 ZIP 文件失败: {e}")

    def extract(self, merge_strategy: Optional[str] = None) -> bool:
        """解压文件

        Args:
            merge_strategy: 合并策略，"smart" 或 "overwrite"

        Returns:
            解压是否成功
        """
        if not self.zip_path.exists():
            logger.error(f"ZIP 文件不存在: {self.zip_path}")
            return False

        strategy = merge_strategy or self.merge_strategy
        logger.info(f"开始解压: {self.zip_path} (策略: {strategy})")

        try:
            if strategy == "smart":
                self._smart_extract()
            else:
                with zipfile.ZipFile(self.zip_path, 'r') as zip_ref:
                    zip_ref.extractall(self.temp_data_dir)

            logger.info(f"解压完成: {self.extract_path}")
            return True

        except zipfile.BadZipFile as e:
            logger.error(f"无效的 ZIP 文件 ({self.zip_path}): {e}")
            return False
        except Exception as e:
            logger.error(f"解压失败 ({self.zip_path}): {e}")
            return False

    def _smart_extract(self) -> None:
        """智能解压合并

        只覆盖已变化的文件，保留未变化的文件
        """
        with zipfile.ZipFile(self.zip_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                member_path = self.temp_data_dir / member
                member_info = zip_ref.getinfo(member)

                if member_path.exists():
                    try:
                        existing_mtime = member_path.stat().st_mtime
                        zip_mtime = member_info.date_time
                        from time import mktime
                        zip_mtime_ts = mktime(zip_mtime + (0, 0, 0))

                        if existing_mtime >= zip_mtime_ts:
                            logger.debug(f"跳过未变化的文件: {member}")
                            continue
                    except Exception:
                        pass

                member_path.parent.mkdir(parents=True, exist_ok=True)
                zip_ref.extract(member, self.temp_data_dir)
                logger.debug(f"提取/更新文件: {member}")

    def verify_checksum(self, expected_checksum: Optional[str] = None) -> bool:
        """验证文件校验和

        Args:
            expected_checksum: 期望的校验和，如果为 None 则只验证文件存在

        Returns:
            校验是否通过
        """
        if not self.zip_path.exists():
            return False

        actual_checksum = self.calculate_checksum(self.zip_path)

        if expected_checksum:
            if actual_checksum != expected_checksum:
                logger.error(
                    f"校验和不匹配 ({self.source_name}): "
                    f"期望 {expected_checksum}, 实际 {actual_checksum}"
                )
                return False
            logger.info(f"校验和验证通过: {self.source_name}")

        return True

    def save_download_record(self) -> bool:
        """保存下载记录到数据库

        Returns:
            保存是否成功
        """
        if not self.zip_path.exists():
            logger.error(f"无法保存记录，ZIP 文件不存在: {self.zip_path}")
            return False

        try:
            conn = NVDConnection.get_instance()
            file_size = self.zip_path.stat().st_size
            checksum = self.calculate_checksum(self.zip_path)

            query = """
                INSERT INTO download_records (source, file_name, file_size, checksum, downloaded_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (source, file_name)
                DO UPDATE SET
                    file_size = EXCLUDED.file_size,
                    checksum = EXCLUDED.checksum,
                    downloaded_at = EXCLUDED.downloaded_at
            """
            conn.execute(query, (self.source_name, self.zip_file_name, file_size, checksum, datetime.now()))
            logger.info(f"下载记录已保存: {self.source_name}")
            return True

        except Exception as e:
            logger.error(f"保存下载记录失败 ({self.source_name}): {e}")
            return False

    def process(self, force: bool = False, show_progress: bool = True) -> bool:
        """执行完整的下载和解压流程

        Args:
            force: 是否强制下载
            show_progress: 是否显示进度条

        Returns:
            处理是否成功
        """
        should_download, reason = self.should_download(force=force)

        if not should_download:
            logger.info(f"{self.source_name} {reason}，跳过")
            if self.extract_path.exists() or self._check_extracted():
                return True
            else:
                logger.warning(f"{self.source_name} 记录存在但解压目录不存在，重新解压")
                return self.extract()

        if not self.download(show_progress=show_progress):
            return False

        if not self.verify_checksum():
            logger.error(f"校验和验证失败: {self.source_name}")
            return False

        if not self.extract():
            return False

        if not self.save_download_record():
            return False

        return True

    def _check_extracted(self) -> bool:
        """检查是否已解压"""
        if self.extract_path.exists() and any(self.extract_path.iterdir()):
            return True

        for item in self.temp_data_dir.iterdir():
            if item.is_dir() and self.source_name.lower() in item.name.lower():
                return True

        return False


class DataPreloader:
    """数据预加载器

    协调多个数据源的下载、解压和记录管理。
    """

    def __init__(
        self,
        sources_file: Optional[Path] = None,
        temp_zip_dir: Optional[Path] = None,
        temp_data_dir: Optional[Path] = None,
        max_workers: int = 4,
        timeout: int = 300,
        skip_on_checksum_match: bool = True,
        merge_strategy: str = "smart"
    ):
        self.sources_file = Path(sources_file) if sources_file else SOURCES_FILE
        self.temp_zip_dir = Path(temp_zip_dir) if temp_zip_dir else TEMP_ZIP_DIR
        self.temp_data_dir = Path(temp_data_dir) if temp_data_dir else TEMP_DATA_DIR
        self.max_workers = max_workers
        self.timeout = timeout
        self.skip_on_checksum_match = skip_on_checksum_match
        self.merge_strategy = merge_strategy

        self.config = DataSourceConfig(sources_file=self.sources_file)
        self._results: Dict[str, bool] = {}

    def _create_downloader(self, url: str) -> SourceDownloader:
        """创建下载器实例"""
        return SourceDownloader(
            url=url,
            temp_zip_dir=self.temp_zip_dir,
            temp_data_dir=self.temp_data_dir,
            timeout=self.timeout,
            skip_on_checksum_match=self.skip_on_checksum_match,
            merge_strategy=self.merge_strategy
        )

    def download_all(
        self,
        parallel: bool = True,
        force: bool = False,
        source_filter: Optional[str] = None
    ) -> Dict[str, bool]:
        """下载所有数据源

        Args:
            parallel: 是否并行下载
            force: 是否强制下载所有数据源
            source_filter: 数据源名称过滤器（部分匹配）

        Returns:
            每个数据源的下载结果
        """
        urls = self.config.urls

        if source_filter:
            urls = [url for url in urls if source_filter.lower() in url.lower()]
            logger.info(f"过滤后待下载数据源: {len(urls)} 个 (filter: {source_filter})")

        if not urls:
            logger.warning("没有数据源需要下载")
            return {}

        logger.info(f"开始下载 {len(urls)} 个数据源 (force={force}, parallel={parallel})...")

        if parallel and len(urls) > 1:
            self._results = self._download_parallel(urls, force=force)
        else:
            self._results = self._download_sequential(urls, force=force)

        return self._results

    def _download_sequential(self, urls: List[str], force: bool = False) -> Dict[str, bool]:
        """顺序下载"""
        results = {}
        for url in urls:
            downloader = self._create_downloader(url)
            source_name = downloader.source_name
            results[source_name] = downloader.process(force=force)
        return results

    def _download_parallel(self, urls: List[str], force: bool = False) -> Dict[str, bool]:
        """并行下载"""
        results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {
                executor.submit(self._create_downloader(url).process, force): url
                for url in urls
            }

            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                downloader = self._create_downloader(url)
                source_name = downloader.source_name

                try:
                    results[source_name] = future.result()
                except Exception as e:
                    logger.error(f"下载异常 ({source_name}): {e}")
                    results[source_name] = False

        return results

    def check_status(self) -> Dict[str, Any]:
        """检查所有数据源的下载状态

        Returns:
            状态信息
        """
        status = {
            "total_sources": len(self.config.urls),
            "sources": []
        }

        for url in self.config.urls:
            downloader = self._create_downloader(url)
            should_download, reason = downloader.should_download()

            source_info = {
                "name": downloader.source_name,
                "url": url,
                "zip_file": downloader.zip_file_name,
                "zip_exists": downloader.zip_path.exists(),
                "needs_download": should_download,
                "reason": reason
            }

            if downloader.zip_path.exists():
                source_info["zip_size"] = downloader.zip_path.stat().st_size

            status["sources"].append(source_info)

        return status

    def verify_all(self) -> Dict[str, bool]:
        """验证所有已下载的数据源

        Returns:
            每个数据源的验证结果
        """
        results = {}
        zip_files = list(self.temp_zip_dir.glob('*.zip'))

        for zip_file in zip_files:
            try:
                downloader = SourceDownloader(
                    url=f"file://{zip_file}",
                    temp_zip_dir=self.temp_zip_dir,
                    temp_data_dir=self.temp_data_dir
                )
                downloader.zip_path = zip_file
                results[zip_file.stem] = downloader.verify_checksum()
            except Exception as e:
                logger.error(f"验证失败 ({zip_file.name}): {e}")
                results[zip_file.stem] = False

        return results

    def get_download_status(self) -> Dict[str, Any]:
        """获取下载状态

        Returns:
            下载状态信息
        """
        conn = NVDConnection.get_instance()

        query = """
            SELECT source, file_name, file_size, checksum, downloaded_at
            FROM download_records
            ORDER BY downloaded_at DESC
        """
        records = conn.fetch_all(query)

        status = {
            "total_sources": len(self.config.urls),
            "records": []
        }

        for record in records:
            status["records"].append({
                "source": record[0],
                "file_name": record[1],
                "file_size": record[2],
                "checksum": record[3],
                "downloaded_at": record[4].isoformat() if record[4] else None
            })

        return status

    def get_temp_data_dirs(self) -> List[Path]:
        """获取已解压的数据目录列表

        Returns:
            数据目录列表
        """
        if not self.temp_data_dir.exists():
            return []

        dirs = []
        for item in self.temp_data_dir.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                dirs.append(item)

        return dirs

    def cleanup_zip_files(self) -> int:
        """清理临时 ZIP 文件

        Returns:
            清理的文件数量
        """
        count = 0
        if self.temp_zip_dir.exists():
            for zip_file in self.temp_zip_dir.glob('*.zip'):
                try:
                    zip_file.unlink()
                    count += 1
                    logger.debug(f"已删除: {zip_file}")
                except Exception as e:
                    logger.warning(f"删除失败 ({zip_file}): {e}")

        logger.info(f"清理完成，删除了 {count} 个 ZIP 文件")
        return count

    def get_statistics(self) -> Dict[str, Any]:
        """获取预加载统计信息

        Returns:
            统计信息
        """
        zip_count = len(list(self.temp_zip_dir.glob('*.zip'))) if self.temp_zip_dir.exists() else 0
        data_dir_count = len(self.get_temp_data_dirs())

        conn = NVDConnection.get_instance()
        query = "SELECT COUNT(*) FROM download_records"
        record_count = conn.fetch_one(query)
        total_records = record_count[0] if record_count else 0

        return {
            "configured_sources": len(self.config.urls),
            "downloaded_zips": zip_count,
            "extracted_dirs": data_dir_count,
            "total_records": total_records,
            "zip_dir": str(self.temp_zip_dir),
            "data_dir": str(self.temp_data_dir),
            "skip_on_checksum_match": self.skip_on_checksum_match,
            "merge_strategy": self.merge_strategy
        }


def create_data_preloader(
    sources_file: Optional[Path] = None,
    temp_zip_dir: Optional[Path] = None,
    temp_data_dir: Optional[Path] = None,
    max_workers: int = 4,
    skip_on_checksum_match: bool = True,
    merge_strategy: str = "smart"
) -> DataPreloader:
    """创建数据预加载器

    Args:
        sources_file: 数据源配置文件路径
        temp_zip_dir: ZIP 文件临时目录
        temp_data_dir: 解压数据临时目录
        max_workers: 最大并行下载数
        skip_on_checksum_match: 校验和一致时跳过下载
        merge_strategy: 解压合并策略

    Returns:
        DataPreloader 实例
    """
    return DataPreloader(
        sources_file=sources_file,
        temp_zip_dir=temp_zip_dir,
        temp_data_dir=temp_data_dir,
        max_workers=max_workers,
        skip_on_checksum_match=skip_on_checksum_match,
        merge_strategy=merge_strategy
    )
