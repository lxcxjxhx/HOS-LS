"""网络搜索模块

提供网络搜索功能，用于在安全扫描过程中搜索相关的安全信息。
"""

import asyncio
import aiohttp
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from src.utils.logger import get_logger
from src.core.config import Config, get_config

logger = get_logger(__name__)


@dataclass
class SearchResult:
    """搜索结果"""
    title: str
    url: str
    snippet: str
    relevance: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class WebSearcher:
    """网络搜索器
    
    提供网络搜索功能，用于在安全扫描过程中搜索相关的安全信息。
    """
    
    def __init__(self, config: Optional[Config] = None):
        """初始化网络搜索器
        
        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self.session = None
    
    async def __aenter__(self):
        """进入上下文管理器"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """退出上下文管理器"""
        await self.close()
    
    async def initialize(self):
        """初始化网络搜索器"""
        try:
            self.session = aiohttp.ClientSession()
            return True
        except Exception as e:
            logger.error(f"初始化网络搜索器失败: {e}")
            return False
    
    async def close(self):
        """关闭网络搜索器"""
        if self.session:
            await self.session.close()
    
    async def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        """执行网络搜索
        
        Args:
            query: 搜索查询
            max_results: 最大结果数
            
        Returns:
            搜索结果列表
        """
        try:
            if not self.session:
                raise RuntimeError("Client session not initialized. Use context manager or initialize session first.")
            
            # 使用 Google 搜索 API (需要 API 密钥)
            # 这里使用一个简单的模拟实现
            # 实际使用时需要替换为真实的搜索 API
            
            # 模拟搜索结果
            results = [
                SearchResult(
                    title=f"{query} - 安全漏洞信息",
                    url=f"https://example.com/search?q={query}",
                    snippet=f"关于 {query} 的详细安全漏洞信息...",
                    relevance=0.9
                ),
                SearchResult(
                    title=f"{query} - 漏洞修复建议",
                    url=f"https://example.com/fix?q={query}",
                    snippet=f"{query} 的修复建议和最佳实践...",
                    relevance=0.85
                ),
                SearchResult(
                    title=f"{query} - CVE 信息",
                    url=f"https://example.com/cve?q={query}",
                    snippet=f"{query} 相关的 CVE 漏洞信息...",
                    relevance=0.8
                ),
                SearchResult(
                    title=f"{query} - 安全最佳实践",
                    url=f"https://example.com/best-practices?q={query}",
                    snippet=f"{query} 相关的安全最佳实践...",
                    relevance=0.75
                ),
                SearchResult(
                    title=f"{query} - 技术博客",
                    url=f"https://example.com/blog?q={query}",
                    snippet=f"关于 {query} 的技术分析和解决方案...",
                    relevance=0.7
                )
            ]
            
            # 限制结果数量
            return results[:max_results]
            
        except Exception as e:
            logger.error(f"网络搜索失败: {e}")
            return []
    
    async def search_vulnerability(self, vulnerability_type: str, library: Optional[str] = None) -> List[SearchResult]:
        """搜索特定类型的漏洞信息
        
        Args:
            vulnerability_type: 漏洞类型
            library: 相关库（可选）
            
        Returns:
            搜索结果列表
        """
        query = f"{vulnerability_type} 安全漏洞"
        if library:
            query += f" {library}"
        
        return await self.search(query)
    
    async def search_library_vulnerabilities(self, library_name: str, version: Optional[str] = None) -> List[SearchResult]:
        """搜索库的漏洞信息
        
        Args:
            library_name: 库名称
            version: 库版本（可选）
            
        Returns:
            搜索结果列表
        """
        query = f"{library_name} 安全漏洞"
        if version:
            query += f" {version}"
        
        return await self.search(query)


# 全局网络搜索器实例
_web_searcher: Optional[WebSearcher] = None


def get_web_searcher() -> WebSearcher:
    """获取全局网络搜索器实例
    
    Returns:
        网络搜索器实例
    """
    global _web_searcher
    if _web_searcher is None:
        _web_searcher = WebSearcher()
        asyncio.run(_web_searcher.initialize())
    return _web_searcher


def close_web_searcher():
    """关闭全局网络搜索器实例
    
    确保在程序结束时正确关闭 aiohttp 客户端会话
    """
    global _web_searcher
    if _web_searcher:
        asyncio.run(_web_searcher.close())
        _web_searcher = None


async def search_security_info(query: str, max_results: int = 5) -> List[SearchResult]:
    """搜索安全相关信息
    
    Args:
        query: 搜索查询
        max_results: 最大结果数
        
    Returns:
        搜索结果列表
    """
    searcher = get_web_searcher()
    return await searcher.search(query, max_results)


async def search_vulnerability_info(vulnerability_type: str, library: Optional[str] = None) -> List[SearchResult]:
    """搜索漏洞相关信息
    
    Args:
        vulnerability_type: 漏洞类型
        library: 相关库（可选）
        
    Returns:
        搜索结果列表
    """
    searcher = get_web_searcher()
    return await searcher.search_vulnerability(vulnerability_type, library)


async def search_library_info(library_name: str, version: Optional[str] = None) -> List[SearchResult]:
    """搜索库相关信息
    
    Args:
        library_name: 库名称
        version: 库版本（可选）
        
    Returns:
        搜索结果列表
    """
    searcher = get_web_searcher()
    return await searcher.search_library_vulnerabilities(library_name, version)


# 注册退出处理函数，确保在程序结束时关闭会话
import atexit
atexit.register(close_web_searcher)
