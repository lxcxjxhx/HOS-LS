"""纯AI分析器模块

实现纯AI深度语义解析功能，默认使用 deepseek-reasoner。
"""

import asyncio
from pathlib import Path
from typing import List, Optional, Dict, Any

from src.core.config import Config
from src.ai.client import get_model_manager, AIProvider
from src.ai.models import AnalysisContext, SecurityAnalysisResult, VulnerabilityFinding
from src.ai.multi_agent_pipeline import MultiAgentPipeline
from src.ai.cache_manager import CacheManager


class PureAIAnalyzer:
    """纯AI分析器

    实现纯AI深度语义解析功能，使用 Multi-Agent Pipeline 进行分析。
    """

    def __init__(self, config: Config):
        """初始化纯AI分析器

        Args:
            config: 配置对象
        """
        self.config = config
        # 默认使用 deepseek-reasoner
        self.ai_provider = getattr(config, "pure_ai_provider", "deepseek")
        self.ai_model = getattr(config, "pure_ai_model", "deepseek-reasoner")
        self.model_manager = None
        self.client = None
        self.pipeline = None
        self.cache_manager = CacheManager()
        # 异步初始化
        asyncio.run(self._initialize())
    
    async def _initialize(self):
        """异步初始化"""
        try:
            self.model_manager = await get_model_manager(self.config)
            # 映射提供商名称到AIProvider枚举
            provider_map = {
                "anthropic": AIProvider.ANTHROPIC,
                "openai": AIProvider.OPENAI,
                "deepseek": AIProvider.DEEPSEEK,
                "local": AIProvider.LOCAL,
            }
            provider = provider_map.get(self.ai_provider, AIProvider.DEEPSEEK)
            self.client = self.model_manager.get_client(provider)
            if not self.client:
                # 尝试获取默认客户端
                self.client = self.model_manager.get_default_client()
            if self.client:
                self.pipeline = MultiAgentPipeline(self.client, self.config)
                print(f"[DEBUG] 纯AI分析器初始化成功，使用客户端: {self.ai_provider}")
            else:
                print(f"[DEBUG] 纯AI分析器初始化失败：无法获取AI客户端")
        except Exception as e:
            print(f"[DEBUG] 纯AI分析器初始化失败: {e}")

    async def analyze(self, file_path: str, file_content: str) -> List[VulnerabilityFinding]:
        """分析文件

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            漏洞发现列表
        """
        # 检查缓存
        cache_key = self.cache_manager.generate_cache_key(file_path, file_content)
        cached_result = self.cache_manager.get_cache(cache_key)
        if cached_result:
            return cached_result

        # 创建分析上下文
        context = AnalysisContext(
            file_path=file_path,
            code_content=file_content,
            language=self._detect_language(file_path)
        )

        # 执行多Agent分析
        result = await self.pipeline.run(context)

        # 缓存结果
        self.cache_manager.set_cache(cache_key, result.findings)

        return result.findings

    def _detect_language(self, file_path: str) -> str:
        """检测文件语言

        Args:
            file_path: 文件路径

        Returns:
            语言名称
        """
        ext = Path(file_path).suffix.lower()
        language_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "c",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".swift": "swift",
            ".kt": "kotlin",
            ".rs": "rust",
        }
        return language_map.get(ext, "unknown")

    async def analyze_file(self, file_info) -> List[VulnerabilityFinding]:
        """分析文件信息对象

        Args:
            file_info: 文件信息对象

        Returns:
            漏洞发现列表
        """
        try:
            # 检查pipeline是否初始化
            if not self.pipeline:
                print(f"[DEBUG] 纯AI分析器未初始化，跳过分析: {file_info.path}")
                return []

            # 读取文件内容
            with open(file_info.path, 'r', encoding='utf-8') as f:
                file_content = f.read()

            # 添加延迟以验证LLM调用
            import time
            time.sleep(0.2)

            # 分析文件
            return await self.analyze(file_info.path, file_content)
        except Exception as e:
            if self.config.debug:
                print(f"[DEBUG] 纯AI分析文件失败: {e}")
            return []
