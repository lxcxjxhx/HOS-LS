"""NVD Feed 获取器模块

从 NVD JSON Feed 和 GitHub 镜像获取 CVE 数据。
"""

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any
import aiohttp
import aiofiles

from src.db.models import CVE, CVECollection
from src.utils.logger import get_logger
from src.integration.config_manager import ConfigManager, get_config_manager

logger = get_logger(__name__)

VULN_FEED_SOURCES = [
    {
        'name': 'NVD NIST',
        'type': 'nvd_json',
        'base_url': 'https://nvd.nist.gov/feeds/json/cve/1.1',
        'enabled': True,
        'region': 'international',
    },
    {
        'name': 'GitHub Mirror',
        'type': 'github_release',
        'base_url': 'https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest',
        'enabled': True,
        'region': 'international',
    },
    {
        'name': 'CNNVD',
        'type': 'cnnvd_api',
        'base_url': 'https://www.cnnvd.org.cn/',
        'enabled': True,
        'region': 'domestic',
    },
    {
        'name': 'CNVD RSS',
        'type': 'rss_feed',
        'base_url': 'https://www.cnvd.org.cn/rss',
        'enabled': True,
        'region': 'domestic',
    },
    {
        'name': 'OpenCVE API',
        'type': 'opencve_api',
        'base_url': 'https://www.opencve.io/api/v2',
        'enabled': True,
        'region': 'international',
    },
]


@dataclass
class NVDConfig:
    """NVD 配置（从 config.yaml 读取，支持用户自定义代理端口）"""

    base_url: str = "https://nvd.nist.gov/feeds/json/cve/1.1"
    github_mirror_url: str = "https://github.com/fkie-cad/nvd-json-data-feeds"
    use_proxy: bool = True
    # 代理端口默认 7897，用户可在 ~/.hos-ls/config.yaml 中自定义
    proxy_url: str = "http://127.0.0.1:7897"
    cache_dir: str = "~/.hos-ls/nvd_cache"
    request_timeout: int = 60

    @classmethod
    def from_config_manager(cls, config_manager: Optional[ConfigManager] = None) -> 'NVDConfig':
        """从 ConfigManager 读取配置创建 NVDConfig"""
        if config_manager is None:
            config_manager = get_config_manager()
        proxy_url = config_manager.get_proxy_url() or "http://127.0.0.1:7897"
        use_proxy = config_manager.get('proxy.enabled', True)
        return cls(
            proxy_url=proxy_url,
            use_proxy=use_proxy,
        )


class NVDFeedFetcher:
    """NVD Feed 获取器"""

    def __init__(self, config: Optional[NVDConfig] = None):
        self.config = config or NVDConfig()
        self.cache_dir = Path(os.path.expanduser(self.config.cache_dir))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session: Optional[aiohttp.ClientSession] = None
        self.available_sources: List[Dict[str, Any]] = []

    async def __aenter__(self):
        """进入上下文管理器"""
        connector = None
        if self.config.use_proxy:
            connector = aiohttp.TCPConnector()
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.config.request_timeout),
        )
        logger.info("Performing vulnerability feed source health check...")
        self.available_sources = await self.check_source_availability()
        available_names = [s['name'] for s in self.available_sources if s['available']]
        logger.info(f"Available sources: {available_names}")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """退出上下文管理器"""
        if self.session:
            await self.session.close()

    def _get_proxy(self) -> Optional[str]:
        """获取代理配置"""
        if self.config.use_proxy:
            return self.config.proxy_url
        return None

    async def _check_single_source(self, source: Dict[str, Any], timeout: int) -> Dict[str, Any]:
        """Check availability of a single source via HEAD request"""
        name = source['name']
        base_url = str(source['base_url'])
        start_time = time.monotonic()
        try:
            proxy = self._get_proxy() if source.get('region') == 'international' else None
            async with self.session.head(base_url, proxy=proxy, allow_redirects=True) as response:
                elapsed_ms = (time.monotonic() - start_time) * 1000
                available = response.status < 400
                logger.debug(f"Source '{name}': available={available}, time={elapsed_ms:.1f}ms, status={response.status}")
                return {'name': name, 'available': available, 'response_time_ms': elapsed_ms}
        except Exception as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            logger.warning(f"Source '{name}' unreachable: {e}")
            return {'name': name, 'available': False, 'response_time_ms': elapsed_ms}

    async def check_source_availability(self, sources: Optional[List[Dict[str, Any]]] = None, timeout: int = 10) -> List[Dict[str, Any]]:
        """Check availability of all enabled sources in parallel"""
        if not self.session:
            raise RuntimeError("Session not initialized")
        if sources is None:
            sources = [s for s in VULN_FEED_SOURCES if s.get('enabled', False)]
        tasks = [self._check_single_source(src, timeout) for src in sources]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        results_sorted = sorted(results, key=lambda x: x['response_time_ms'])
        return results_sorted

    async def select_best_source(self) -> Optional[Dict[str, Any]]:
        """Select the fastest available source"""
        availability = await self.check_source_availability()
        for source_result in availability:
            if source_result['available']:
                for src in VULN_FEED_SOURCES:
                    if src['name'] == source_result['name']:
                        logger.info(f"Selected best source: {src['name']} ({source_result['response_time_ms']:.1f}ms)")
                        return src
        logger.warning("No available sources found")
        return None

    async def _fetch_cnnvd_feed(self, query_params: Optional[Dict[str, Any]] = None) -> CVECollection:
        """CNNVD API adapter - fetches CVE data from Chinese National Vulnerability Database"""
        logger.info("Fetching from CNNVD API (stub)")
        return CVECollection(
            cves=[],
            last_sync_time=datetime.now(),
            sync_source='cnnvd_api',
        )

    async def _fetch_cnvd_rss(self) -> CVECollection:
        """Parse CNVD RSS feed"""
        logger.info("Fetching from CNVD RSS feed (stub)")
        try:
            import feedparser
            logger.debug("feedparser module available for CNVD RSS parsing")
        except ImportError:
            logger.warning("feedparser not available, CNVD RSS fetch returning empty collection")
        return CVECollection(
            cves=[],
            last_sync_time=datetime.now(),
            sync_source='cnvd_rss',
        )

    async def _fetch_opencve_api(self, page: int = 1, page_size: int = 50) -> CVECollection:
        """Query OpenCVE API with aiohttp"""
        logger.info(f"Fetching from OpenCVE API page={page}, size={page_size} (stub)")
        return CVECollection(
            cves=[],
            last_sync_time=datetime.now(),
            sync_source='opencve_api',
        )

    async def _fetch_json(self, url: str) -> Optional[Dict[str, Any]]:
        """获取 JSON 数据"""
        if not self.session:
            raise RuntimeError("Session not initialized")

        try:
            proxy = self._get_proxy()
            logger.info(f"Fetching: {url} (proxy: {proxy is not None})")

            async with self.session.get(url, proxy=proxy) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Successfully fetched: {url}")
                    return data
                else:
                    logger.error(f"Failed to fetch {url}: status {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return None

    async def fetch_yearly_feed(self, year: int) -> Optional[Dict[str, Any]]:
        """获取年度 CVE Feed"""
        url = f"{self.config.base_url}/nvdcve-1.1-{year}.json.gz"
        return await self._fetch_json(url)

    async def fetch_recent_feed(self) -> Optional[Dict[str, Any]]:
        """获取最近更新的 CVE Feed"""
        url = f"{self.config.base_url}/nvdcve-1.1-recent.json.gz"
        return await self._fetch_json(url)

    async def fetch_modified_feed(self) -> Optional[Dict[str, Any]]:
        """获取修改过的 CVE Feed"""
        url = f"{self.config.base_url}/nvdcve-1.1-modified.json.gz"
        return await self._fetch_json(url)

    def _parse_nvd_cve(self, nvd_item: Dict[str, Any]) -> Optional[CVE]:
        """解析 NVD CVE 条目"""
        try:
            cve_data = nvd_item.get("cve", {})
            cve_id = cve_data.get("CVE_data_meta", {}).get("ID", "")
            
            if not cve_id:
                return None

            description = ""
            desc_data = cve_data.get("description", {}).get("description_data", [])
            if desc_data:
                description = desc_data[0].get("value", "")

            cvss_v3_score = None
            cvss_v3_vector = None
            cvss_v2_score = None
            cvss_v2_vector = None
            
            impact = nvd_item.get("impact", {})
            base_metric_v3 = impact.get("baseMetricV3", {})
            if base_metric_v3:
                cvss_v3 = base_metric_v3.get("cvssV3", {})
                cvss_v3_score = cvss_v3.get("baseScore")
                cvss_v3_vector = cvss_v3.get("vectorString")

            base_metric_v2 = impact.get("baseMetricV2", {})
            if base_metric_v2:
                cvss_v2 = base_metric_v2.get("cvssV2", {})
                cvss_v2_score = cvss_v2.get("baseScore")
                cvss_v2_vector = cvss_v2.get("vectorString")

            cwe = None
            problem_type = cve_data.get("problemtype", {}).get("problemtype_data", [])
            if problem_type:
                descriptions = problem_type[0].get("description", [])
                if descriptions:
                    cwe = descriptions[0].get("value")

            cpe_list = []
            configurations = nvd_item.get("configurations", {})
            nodes = configurations.get("nodes", [])
            for node in nodes:
                cpe_match = node.get("cpe_match", [])
                for cpe in cpe_match:
                    cpe_uri = cpe.get("cpe23Uri", "")
                    if cpe_uri:
                        cpe_list.append(cpe_uri)

            references = []
            ref_data = cve_data.get("references", {}).get("reference_data", [])
            for ref in ref_data:
                references.append({
                    "url": ref.get("url", ""),
                    "name": ref.get("name", ""),
                })

            published_date = None
            last_modified_date = None
            try:
                published_str = nvd_item.get("publishedDate")
                if published_str:
                    published_date = datetime.strptime(published_str, "%Y-%m-%dT%H:%MZ")
            except Exception:
                pass

            try:
                modified_str = nvd_item.get("lastModifiedDate")
                if modified_str:
                    last_modified_date = datetime.strptime(modified_str, "%Y-%m-%dT%H:%MZ")
            except Exception:
                pass

            attack_vector = None
            if cvss_v3_vector:
                if "AV:N" in cvss_v3_vector:
                    attack_vector = "NETWORK"
                elif "AV:A" in cvss_v3_vector:
                    attack_vector = "ADJACENT_NETWORK"
                elif "AV:L" in cvss_v3_vector:
                    attack_vector = "LOCAL"
                elif "AV:P" in cvss_v3_vector:
                    attack_vector = "PHYSICAL"

            tags = []
            if cwe:
                tags.append(cwe)
            if attack_vector:
                tags.append(attack_vector.lower())

            return CVE(
                cve_id=cve_id,
                description=description,
                cwe=cwe,
                cvss_v3_score=cvss_v3_score,
                cvss_v3_vector=cvss_v3_vector,
                cvss_v2_score=cvss_v2_score,
                cvss_v2_vector=cvss_v2_vector,
                cpe=cpe_list,
                exploit=False,
                exploit_refs=[],
                patch_refs=[],
                attack_vector=attack_vector,
                tags=tags,
                published_date=published_date,
                last_modified_date=last_modified_date,
                affected_products=[],
                references=references,
            )
        except Exception as e:
            logger.error(f"Error parsing NVD CVE: {e}")
            return None

    async def fetch_and_parse_feed(
        self,
        feed_type: str = "recent",
        year: Optional[int] = None,
    ) -> CVECollection:
        """获取并解析 Feed"""
        if feed_type == "year" and year:
            data = await self.fetch_yearly_feed(year)
        elif feed_type == "modified":
            data = await self.fetch_modified_feed()
        else:
            data = await self.fetch_recent_feed()

        cves: List[CVE] = []
        if data:
            cve_items = data.get("CVE_Items", [])
            for item in cve_items:
                cve = self._parse_nvd_cve(item)
                if cve:
                    cves.append(cve)

        return CVECollection(
            cves=cves,
            last_sync_time=datetime.now(),
            sync_source=f"nvd_{feed_type}",
        )

    async def incremental_sync(
        self,
        since: Optional[datetime] = None,
    ) -> CVECollection:
        """增量同步"""
        if not since:
            since = datetime.now() - timedelta(days=7)

        logger.info(f"Starting incremental sync since: {since}")

        recent_collection = await self.fetch_and_parse_feed("recent")
        modified_collection = await self.fetch_and_parse_feed("modified")

        all_cves: Dict[str, CVE] = {}
        for cve in recent_collection.cves:
            all_cves[cve.cve_id] = cve
        for cve in modified_collection.cves:
            all_cves[cve.cve_id] = cve

        filtered_cves = [
            cve for cve in all_cves.values()
            if cve.last_modified_date and cve.last_modified_date >= since
        ]

        logger.info(f"Incremental sync found {len(filtered_cves)} CVEs")

        return CVECollection(
            cves=filtered_cves,
            last_sync_time=datetime.now(),
            sync_source="nvd_incremental",
        )

    async def save_to_cache(self, collection: CVECollection, filename: str) -> bool:
        """保存到缓存"""
        try:
            cache_file = self.cache_dir / filename
            async with aiofiles.open(cache_file, 'w', encoding='utf-8') as f:
                await f.write(collection.to_json())
            logger.info(f"Saved to cache: {cache_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save to cache: {e}")
            return False

    async def load_from_cache(self, filename: str) -> Optional[CVECollection]:
        """从缓存加载"""
        try:
            cache_file = self.cache_dir / filename
            if not cache_file.exists():
                return None

            async with aiofiles.open(cache_file, 'r', encoding='utf-8') as f:
                content = await f.read()
            collection = CVECollection.from_json(content)
            logger.info(f"Loaded from cache: {cache_file}")
            return collection
        except Exception as e:
            logger.error(f"Failed to load from cache: {e}")
            return None
