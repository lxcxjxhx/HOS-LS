"""纯AI分析器模块

实现纯AI深度语义解析功能，默认使用 deepseek-reasoner。
"""

import asyncio
import json
import os
from pathlib import Path
from typing import List, Optional, Dict, Any

from src.core.config import Config
from src.ai.client import get_model_manager, AIProvider
from src.ai.models import AnalysisContext, SecurityAnalysisResult, VulnerabilityFinding
from src.ai.pure_ai.multi_agent_pipeline import MultiAgentPipeline
from src.ai.pure_ai.cache import CacheManager


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
            print(f"[DEBUG] 开始初始化纯AI分析器，使用提供商: {self.ai_provider}")
            print(f"[DEBUG] 使用模型: {self.ai_model}")
            
            # 检查API密钥
            api_key = getattr(self.config, "pure_ai_api_key", None)
            if not api_key:
                api_key = self.config.ai.api_key
            if not api_key:
                api_key = os.getenv("HOS_LS_AI_API_KEY")
            if not api_key:
                api_key = os.getenv("DEEPSEEK_API_KEY")
            
            if not api_key:
                print(f"[DEBUG] 警告: API 密钥未设置")
            else:
                print(f"[DEBUG] API 密钥已设置 (长度: {len(api_key)})")
            
            # 为纯AI模式创建临时配置
            from src.ai.client import AIModelManager
            from src.core.config import get_config
            
            # 创建临时配置，使用纯AI的提供商和模型
            temp_config = get_config()
            temp_config.ai.provider = self.ai_provider
            temp_config.ai.model = self.ai_model
            temp_config.ai.api_key = api_key
            
            # 初始化模型管理器
            self.model_manager = AIModelManager()
            await self.model_manager.initialize(temp_config)
            print(f"[DEBUG] 模型管理器初始化成功: {self.model_manager}")
            
            # 映射提供商名称到AIProvider枚举
            from src.ai.client import AIProvider
            provider_map = {
                "anthropic": AIProvider.ANTHROPIC,
                "openai": AIProvider.OPENAI,
                "deepseek": AIProvider.DEEPSEEK,
                "local": AIProvider.LOCAL,
            }
            provider = provider_map.get(self.ai_provider, AIProvider.DEEPSEEK)
            print(f"[DEBUG] 使用提供商: {provider}")
            
            # 获取客户端
            self.client = self.model_manager.get_client(provider)
            print(f"[DEBUG] 获取客户端: {self.client}")
            
            if not self.client:
                # 尝试获取默认客户端
                print(f"[DEBUG] 尝试获取默认客户端")
                self.client = self.model_manager.get_default_client()
                print(f"[DEBUG] 默认客户端: {self.client}")
            
            if self.client:
                # 验证API访问
                print(f"[DEBUG] 验证API访问...")
                try:
                    is_available, error_msg = await self.client.validate_api_access()
                    if is_available:
                        print(f"[DEBUG] API访问验证成功")
                    else:
                        print(f"[DEBUG] API访问验证失败: {error_msg}")
                except Exception as e:
                    print(f"[DEBUG] API访问验证异常: {e}")
                
                # 创建pipeline配置，包含模型信息
                pipeline_config = {
                    'max_retries': 3,
                    'model': self.ai_model
                }
                self.pipeline = MultiAgentPipeline(self.client, pipeline_config)
                print(f"[DEBUG] 纯AI分析器初始化成功，使用客户端: {self.ai_provider}, 模型: {self.ai_model}")
            else:
                print(f"[DEBUG] 纯AI分析器初始化失败：无法获取AI客户端")
        except Exception as e:
            print(f"[DEBUG] 纯AI分析器初始化失败: {e}")
            import traceback
            traceback.print_exc()

    async def analyze(self, file_path: str, file_content: str) -> List[VulnerabilityFinding]:
        """分析文件

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            漏洞发现列表
        """
        # 检查缓存
        cached_result = self.cache_manager.get(file_path)
        if cached_result:
            print(f"[PURE-AI] 使用缓存结果: {file_path}")
            return self._convert_to_findings(cached_result)

        # 执行多Agent分析
        result = await self.pipeline.run_pipeline(file_path)

        # 缓存结果
        self.cache_manager.set(file_path, result)

        return self._convert_to_findings(result)

    def _convert_to_findings(self, result: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """将分析结果转换为漏洞发现列表

        Args:
            result: 分析结果
            
        Returns:
            漏洞发现列表
        """
        findings = []
        try:
            final_decision = result.get('final_decision', {})
            final_findings = final_decision.get('final_findings', [])
            
            for finding in final_findings:
                if finding.get('status') == 'VALID':
                    vulnerability = VulnerabilityFinding(
                        rule_id=finding.get('vulnerability', 'unknown'),
                        rule_name=finding.get('vulnerability', 'unknown'),
                        severity=finding.get('severity', 'medium'),
                        confidence=float(finding.get('confidence', 50)) / 100.0,
                        location={'file': finding.get('location', 'unknown')},
                        description=finding.get('vulnerability', 'unknown'),
                        fix_suggestion=finding.get('recommendation', ''),
                        evidence=json.dumps(finding, ensure_ascii=False)
                    )
                    findings.append(vulnerability)
        except Exception as e:
            print(f"[PURE-AI] 转换结果失败: {e}")
            import traceback
            traceback.print_exc()
        
        return findings

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

            # 分析文件
            return await self.analyze(file_info.path, "")
        except Exception as e:
            print(f"[DEBUG] 纯AI分析文件失败: {e}")
            import traceback
            traceback.print_exc()
            return []
