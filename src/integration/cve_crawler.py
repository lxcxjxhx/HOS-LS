"""CVE网站爬虫模块

爬取CVE网站的最新漏洞信息，并将其转换为RAG库格式。
"""

import asyncio
import aiohttp
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any

from src.utils.logger import get_logger
from src.learning.self_learning import Knowledge, KnowledgeType

logger = get_logger(__name__)


@dataclass
class CVECrawler:
    """CVE网站爬虫"""

    def __init__(self, base_url: str = "https://cve.mitre.org"):
        """初始化CVE爬虫

        Args:
            base_url: CVE网站基础URL
        """
        self.base_url = base_url
        self.session: Optional[aiohttp.ClientSession] = None
        from src.storage.rag_knowledge_base import get_rag_knowledge_base
        self.rag_knowledge_base = get_rag_knowledge_base()

    async def __aenter__(self):
        """进入上下文管理器"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """退出上下文管理器"""
        if self.session:
            await self.session.close()

    async def crawl_latest_cves(self, limit: int = 50) -> List[Dict[str, Any]]:
        """爬取最新的CVE漏洞

        Args:
            limit: 爬取数量限制

        Returns:
            CVE漏洞列表
        """
        if not self.session:
            raise RuntimeError("Client session not initialized. Use context manager or initialize session first.")

        cves = []
        try:
            # 爬取CVE最新漏洞页面
            url = f"{self.base_url}/cve/search_cve_list.html"
            params = {
                "requester": "cve",
                "orderby": "Publication Date",
                "dir": "desc",
                "search_type": "ALL",
                "page": "1"
            }

            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    html = await response.text()
                    cves = self._parse_cve_list(html, limit)
                    logger.info(f"成功爬取 {len(cves)} 个CVE漏洞")
                else:
                    logger.error(f"爬取CVE列表失败，状态码: {response.status}")
        except Exception as e:
            logger.error(f"爬取CVE漏洞失败: {e}")
        
        return cves

    async def crawl_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """爬取单个CVE漏洞详情

        Args:
            cve_id: CVE ID

        Returns:
            CVE漏洞详情
        """
        if not self.session:
            raise RuntimeError("Client session not initialized. Use context manager or initialize session first.")

        try:
            url = f"{self.base_url}/cgi-bin/cvename.cgi?name={cve_id}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    details = self._parse_cve_details(html, cve_id)
                    logger.info(f"成功爬取CVE详情: {cve_id}")
                    return details
                else:
                    logger.error(f"爬取CVE详情失败，状态码: {response.status}")
        except Exception as e:
            logger.error(f"爬取CVE详情失败: {e}")
        
        return None

    async def crawl_and_store_cves(self, limit: int = 50) -> int:
        """爬取CVE漏洞并存储到RAG库

        Args:
            limit: 爬取数量限制

        Returns:
            存储的CVE数量
        """
        # 爬取最新CVE
        cves = await self.crawl_latest_cves(limit)
        stored_count = 0

        # 爬取每个CVE的详情并存储
        for cve in cves:
            details = await self.crawl_cve_details(cve["id"])
            if details:
                # 转换为知识对象并存储
                knowledge = self._convert_to_knowledge(details)
                if knowledge:
                    self.rag_knowledge_base.add_knowledge(knowledge)
                    stored_count += 1
                    logger.info(f"已存储CVE: {cve['id']}")

        logger.info(f"总计存储 {stored_count} 个CVE漏洞到RAG库")
        return stored_count

    def _parse_cve_list(self, html: str, limit: int) -> List[Dict[str, Any]]:
        """解析CVE列表

        Args:
            html: HTML内容
            limit: 限制数量

        Returns:
            CVE列表
        """
        cves = []
        
        # 正则表达式匹配CVE条目
        pattern = r'<a href="/cgi-bin/cvename\.cgi\?name=(CVE-\d+-\d+)"[^>]*>(CVE-\d+-\d+)</a>'
        matches = re.findall(pattern, html)
        
        for match in matches[:limit]:
            cve_id = match[0]
            cves.append({"id": cve_id})
        
        return cves

    def _parse_cve_details(self, html: str, cve_id: str) -> Dict[str, Any]:
        """解析CVE详情

        Args:
            html: HTML内容
            cve_id: CVE ID

        Returns:
            CVE详情
        """
        details = {
            "id": cve_id,
            "description": "",
            "published_date": None,
            "last_modified_date": None,
            "cvss_score": None,
            "affected_products": [],
            "references": []
        }

        # 解析描述
        desc_pattern = r'<div class="cvedetailssummary">(.*?)</div>'
        desc_match = re.search(desc_pattern, html, re.DOTALL)
        if desc_match:
            description = desc_match.group(1)
            # 清理HTML标签
            description = re.sub(r'<[^>]+>', '', description)
            description = description.strip()
            details["description"] = description

        # 解析日期
        date_pattern = r'Published:<\/td><td>([^<]+)<\/td>'
        date_match = re.search(date_pattern, html)
        if date_match:
            try:
                details["published_date"] = datetime.strptime(date_match.group(1), "%Y-%m-%d")
            except:
                pass

        modified_pattern = r'Last Modified:<\/td><td>([^<]+)<\/td>'
        modified_match = re.search(modified_pattern, html)
        if modified_match:
            try:
                details["last_modified_date"] = datetime.strptime(modified_match.group(1), "%Y-%m-%d")
            except:
                pass

        # 解析CVSS分数
        cvss_pattern = r'CVSS v2 Severity:<\/td><td>([^<]+)<\/td>'
        cvss_match = re.search(cvss_pattern, html)
        if cvss_match:
            details["cvss_score"] = cvss_match.group(1).strip()

        # 解析参考链接
        ref_pattern = r'<a href="([^"]+)"[^>]*>([^<]+)</a>'
        ref_matches = re.findall(ref_pattern, html)
        for url, text in ref_matches:
            if url.startswith("http"):
                details["references"].append({"url": url, "text": text})

        return details

    def _convert_to_knowledge(self, cve_details: Dict[str, Any]) -> Optional[Knowledge]:
        """将CVE详情转换为知识对象

        Args:
            cve_details: CVE详情

        Returns:
            知识对象
        """
        try:
            # 构建内容
            content_parts = [
                f"CVE ID: {cve_details['id']}",
                f"Description: {cve_details['description']}"
            ]

            if cve_details.get("published_date"):
                content_parts.append(f"Published: {cve_details['published_date'].isoformat()}")
            if cve_details.get("last_modified_date"):
                content_parts.append(f"Last Modified: {cve_details['last_modified_date'].isoformat()}")
            if cve_details.get("cvss_score"):
                content_parts.append(f"CVSS Score: {cve_details['cvss_score']}")
            if cve_details.get("references"):
                content_parts.append("References:")
                for ref in cve_details["references"]:
                    content_parts.append(f"- {ref['url']} ({ref['text']})")

            content = "\n".join(content_parts)

            # 生成标签
            tags = ["cve", "vulnerability"]
            if cve_details.get("cvss_score"):
                tags.append(f"cvss:{cve_details['cvss_score']}")

            # 创建知识对象
            knowledge = Knowledge(
                id=cve_details['id'],
                knowledge_type=KnowledgeType.vulnerability,
                content=content,
                source="CVE Database",
                confidence=0.95,
                tags=tags,
                metadata={
                    "cve_id": cve_details['id'],
                    "published_date": cve_details.get("published_date").isoformat() if cve_details.get("published_date") else None,
                    "last_modified_date": cve_details.get("last_modified_date").isoformat() if cve_details.get("last_modified_date") else None,
                    "cvss_score": cve_details.get("cvss_score"),
                    "references": cve_details.get("references")
                }
            )

            return knowledge
        except Exception as e:
            logger.error(f"转换CVE为知识对象失败: {e}")
            return None

    async def run_periodic_crawl(self, interval_hours: int = 24):
        """定期运行爬虫

        Args:
            interval_hours: 爬取间隔（小时）
        """
        logger.info(f"启动定期CVE爬虫，间隔 {interval_hours} 小时")

        while True:
            try:
                await self.crawl_and_store_cves()
                logger.info(f"CVE爬虫执行完成，下次执行将在 {interval_hours} 小时后")
            except Exception as e:
                logger.error(f"定期爬虫执行失败: {e}")

            # 等待指定时间
            await asyncio.sleep(interval_hours * 3600)


async def main():
    """主函数"""
    async with CVECrawler() as crawler:
        # 测试爬取
        count = await crawler.crawl_and_store_cves(10)
        print(f"存储了 {count} 个CVE漏洞")


if __name__ == "__main__":
    asyncio.run(main())
