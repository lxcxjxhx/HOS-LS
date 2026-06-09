"""CVE 同步管理器模块

实现定时增量同步系统。
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

from src.integration.nvd_feed_fetcher import NVDFeedFetcher, NVDConfig
from src.exploit.exploitdb_mapper import ExploitDBMapper, ExploitDBConfig
from src.db.models import CVECollection
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SyncState:
    """同步状态"""

    last_sync_time: Optional[datetime] = None
    last_full_sync_time: Optional[datetime] = None
    sync_count: int = 0
    total_cves: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CVESyncConfig:
    """CVE 同步配置"""

    sync_interval_hours: int = 2
    full_sync_interval_days: int = 7
    nvd_enabled: bool = True
    exploitdb_enabled: bool = True
    state_file: str = "~/.hos-ls/cve_sync_state.json"
    data_dir: str = "~/.hos-ls/cve_data"


class CVESyncManager:
    """CVE 同步管理器"""

    def __init__(self, config: Optional[CVESyncConfig] = None):
        self.config = config or CVESyncConfig()
        self.state_file = Path(os.path.expanduser(self.config.state_file))
        self.data_dir = Path(os.path.expanduser(self.config.data_dir))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.state: SyncState = SyncState()
        self._load_state()
        
        self.nvd_fetcher: Optional[NVDFeedFetcher] = None
        self.exploitdb_mapper: Optional[ExploitDBMapper] = None

    def _load_state(self) -> None:
        """加载同步状态"""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.state.last_sync_time = (
                    datetime.fromisoformat(data["last_sync_time"])
                    if data.get("last_sync_time")
                    else None
                )
                self.state.last_full_sync_time = (
                    datetime.fromisoformat(data["last_full_sync_time"])
                    if data.get("last_full_sync_time")
                    else None
                )
                self.state.sync_count = data.get("sync_count", 0)
                self.state.total_cves = data.get("total_cves", 0)
                self.state.metadata = data.get("metadata", {})
                logger.info(f"Loaded sync state: {self.state}")
        except Exception as e:
            logger.warning(f"Failed to load sync state: {e}")

    def _save_state(self) -> None:
        """保存同步状态"""
        try:
            data = {
                "last_sync_time": (
                    self.state.last_sync_time.isoformat()
                    if self.state.last_sync_time
                    else None
                ),
                "last_full_sync_time": (
                    self.state.last_full_sync_time.isoformat()
                    if self.state.last_full_sync_time
                    else None
                ),
                "sync_count": self.state.sync_count,
                "total_cves": self.state.total_cves,
                "metadata": self.state.metadata,
            }
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info("Saved sync state")
        except Exception as e:
            logger.error(f"Failed to save sync state: {e}")

    def _should_full_sync(self) -> bool:
        """判断是否需要全量同步"""
        if not self.state.last_full_sync_time:
            return True
        return (
            datetime.now() - self.state.last_full_sync_time
            > timedelta(days=self.config.full_sync_interval_days)
        )

    async def _initialize_nvd(self) -> None:
        """初始化 NVD 获取器"""
        if not self.nvd_fetcher:
            nvd_config = NVDConfig()
            self.nvd_fetcher = NVDFeedFetcher(nvd_config)

    async def _initialize_exploitdb(self) -> None:
        """初始化 ExploitDB 映射器"""
        if not self.exploitdb_mapper and self.config.exploitdb_enabled:
            exploitdb_config = ExploitDBConfig()
            self.exploitdb_mapper = ExploitDBMapper(exploitdb_config)
            await self.exploitdb_mapper.clone_or_pull_repo()
            await self.exploitdb_mapper.load_exploits()

    async def perform_incremental_sync(self) -> CVECollection:
        """执行增量同步"""
        logger.info("Starting incremental sync")
        
        await self._initialize_nvd()
        
        since = self.state.last_sync_time
        if not since:
            since = datetime.now() - timedelta(days=7)
        
        collection = await self.nvd_fetcher.incremental_sync(since)
        
        if self.exploitdb_mapper:
            for cve in collection.cves:
                self.exploitdb_mapper.update_cve_with_exploits(cve)
        
        self.state.last_sync_time = datetime.now()
        self.state.sync_count += 1
        self.state.total_cves += len(collection.cves)
        self._save_state()
        
        await self._save_collection(collection, f"incremental_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        logger.info(f"Incremental sync completed: {len(collection.cves)} CVEs")
        return collection

    async def perform_full_sync(self) -> CVECollection:
        """执行全量同步"""
        logger.info("Starting full sync")
        
        await self._initialize_nvd()
        await self._initialize_exploitdb()
        
        all_cves = []
        
        current_year = datetime.now().year
        for year in range(2002, current_year + 1):
            logger.info(f"Fetching CVE feed for {year}")
            collection = await self.nvd_fetcher.fetch_and_parse_feed("year", year)
            all_cves.extend(collection.cves)
            await asyncio.sleep(1)
        
        if self.exploitdb_mapper:
            for cve in all_cves:
                self.exploitdb_mapper.update_cve_with_exploits(cve)
        
        full_collection = CVECollection(
            cves=all_cves,
            last_sync_time=datetime.now(),
            sync_source="nvd_full",
        )
        
        self.state.last_sync_time = datetime.now()
        self.state.last_full_sync_time = datetime.now()
        self.state.sync_count += 1
        self.state.total_cves = len(all_cves)
        self._save_state()
        
        await self._save_collection(full_collection, "full_sync.json")
        
        logger.info(f"Full sync completed: {len(all_cves)} CVEs")
        return full_collection

    async def sync(self) -> CVECollection:
        """执行同步（自动判断增量或全量）"""
        if self._should_full_sync():
            return await self.perform_full_sync()
        else:
            return await self.perform_incremental_sync()

    async def _save_collection(self, collection: CVECollection, filename: str) -> bool:
        """保存 CVE 集合到文件"""
        try:
            file_path = self.data_dir / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(collection.to_json())
            logger.info(f"Saved collection to: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save collection: {e}")
            return False

    async def load_latest_collection(self) -> Optional[CVECollection]:
        """加载最新的 CVE 集合"""
        try:
            full_sync_file = self.data_dir / "full_sync.json"
            if full_sync_file.exists():
                with open(full_sync_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                return CVECollection.from_json(content)
            return None
        except Exception as e:
            logger.error(f"Failed to load latest collection: {e}")
            return None

    async def run_periodic_sync(self) -> None:
        """运行定期同步"""
        logger.info(f"Starting periodic sync, interval: {self.config.sync_interval_hours}h")
        
        while True:
            try:
                await self.sync()
                logger.info(f"Periodic sync completed, next in {self.config.sync_interval_hours}h")
            except Exception as e:
                logger.error(f"Periodic sync failed: {e}")
            
            await asyncio.sleep(self.config.sync_interval_hours * 3600)

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            "last_sync_time": (
                self.state.last_sync_time.isoformat()
                if self.state.last_sync_time
                else None
            ),
            "last_full_sync_time": (
                self.state.last_full_sync_time.isoformat()
                if self.state.last_full_sync_time
                else None
            ),
            "sync_count": self.state.sync_count,
            "total_cves": self.state.total_cves,
        }
        
        if self.exploitdb_mapper:
            stats["exploitdb"] = self.exploitdb_mapper.get_statistics()
        
        return stats
