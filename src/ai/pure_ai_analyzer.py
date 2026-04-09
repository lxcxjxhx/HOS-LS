"""纯AI分析器模块

实现纯AI深度语义解析功能，默认使用 deepseek-reasoner。
"""

import asyncio
import json
import os
from pathlib import Path
from typing import List, Optional, Dict, Any

from rich.console import Console

from src.core.config import Config
from src.ai.client import get_model_manager, AIProvider
from src.ai.models import AnalysisContext, SecurityAnalysisResult, VulnerabilityFinding
from src.ai.pure_ai.multi_agent_pipeline import MultiAgentPipeline
from src.ai.pure_ai.cache import CacheManager

console = Console()


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
        # 强制使用 deepseek-reasoner 模型进行文件分析
        self.ai_provider = getattr(config, "pure_ai_provider", "deepseek")
        self.ai_model = "deepseek-reasoner"  # 强制使用reasoner模型
        self.model_manager = None
        self.client = None
        self.pipeline = None
        self.cache_manager = CacheManager()
        # 不再在__init__中调用asyncio.run()，而是由调用方手动调用_initialize()
        # 这样可以避免在异步函数中调用asyncio.run()的问题
    
    async def _initialize(self):
        """异步初始化"""
        try:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 开始初始化纯AI分析器，使用提供商: {self.ai_provider}[/dim]")
                console.print(f"[dim][DEBUG] 使用模型: {self.ai_model}[/dim]")
            
            # 检查API密钥
            api_key = getattr(self.config, "pure_ai_api_key", None)
            if not api_key:
                api_key = self.config.ai.api_key
            if not api_key:
                api_key = os.getenv("HOS_LS_AI_API_KEY")
            if not api_key:
                api_key = os.getenv("DEEPSEEK_API_KEY")
            
            if not api_key:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 警告: API 密钥未设置[/dim]")
            else:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] API 密钥已设置 (长度: {len(api_key)})[/dim]")
            
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
            if self.config.debug:
                console.print(f"[dim][DEBUG] 模型管理器初始化成功: {self.model_manager}[/dim]")
            
            # 映射提供商名称到AIProvider枚举
            from src.ai.client import AIProvider
            provider_map = {
                "anthropic": AIProvider.ANTHROPIC,
                "openai": AIProvider.OPENAI,
                "deepseek": AIProvider.DEEPSEEK,
                "local": AIProvider.LOCAL,
            }
            provider = provider_map.get(self.ai_provider, AIProvider.DEEPSEEK)
            if self.config.debug:
                console.print(f"[dim][DEBUG] 使用提供商: {provider}[/dim]")
            
            # 获取客户端
            self.client = self.model_manager.get_client(provider)
            if self.config.debug:
                console.print(f"[dim][DEBUG] 获取客户端: {self.client}[/dim]")
            
            if not self.client:
                # 尝试获取默认客户端
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 尝试获取默认客户端[/dim]")
                self.client = self.model_manager.get_default_client()
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 默认客户端: {self.client}[/dim]")
            
            if self.client:
                # 验证API访问
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 验证API访问...[/dim]")
                try:
                    is_available, error_msg = await self.client.validate_api_access()
                    if is_available:
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] API访问验证成功[/dim]")
                    else:
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] API访问验证失败: {error_msg}[/dim]")
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] API访问验证异常: {e}[/dim]")
                
                # 创建pipeline配置，包含模型信息
                pipeline_config = {
                    'max_retries': 3,
                    'model': self.ai_model
                }
                self.pipeline = MultiAgentPipeline(self.client, pipeline_config)
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 纯AI分析器初始化成功，使用客户端: {self.ai_provider}, 模型: {self.ai_model}[/dim]")
            else:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 纯AI分析器初始化失败：无法获取AI客户端[/dim]")
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 纯AI分析器初始化失败: {e}[/dim]")
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
        print(f"[DEBUG] 开始分析: {file_path}")
        # 检查缓存
        cached_result = self.cache_manager.get(file_path)
        if cached_result:
            print(f"[PURE-AI] 使用缓存结果: {file_path}")
            findings = self._convert_to_findings(cached_result)
            print(f"[DEBUG] 从缓存获取 {len(findings)} 个问题")
            return findings

        # 执行多Agent分析
        result = await self.pipeline.run_pipeline(file_path)
        print(f"[DEBUG] 多Agent分析完成，结果类型: {type(result)}")

        # 验证结果完整性
        if not self._validate_results(result):
            print(f"[DEBUG] 结果验证失败，可能存在遗漏")

        # 缓存结果
        self.cache_manager.set(file_path, result)

        findings = self._convert_to_findings(result)
        print(f"[DEBUG] 转换为 {len(findings)} 个漏洞发现")
        return findings

    def _convert_to_findings(self, result: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """将分析结果转换为漏洞发现列表

        Args:
            result: 分析结果

        Returns:
            漏洞发现列表
        """
        findings = []
        try:
            print(f"[DEBUG] 开始转换结果，结果包含: {list(result.keys())}")
            final_decision = result.get('final_decision', {})
            print(f"[DEBUG] final_decision 类型: {type(final_decision)}")
            final_findings = final_decision.get('final_findings', [])
            print(f"[DEBUG] 找到 {len(final_findings)} 个最终发现")

            # 计算总漏洞数
            total_vulnerabilities = len(final_findings)
            
            for finding in final_findings:
                print(f"[DEBUG] 处理发现: {finding.get('vulnerability')}, 状态: {finding.get('status')}")
                # 处理所有状态的发现，包括INVALID
                status = finding.get('status', 'UNKNOWN')
                
                # 提取详细信息
                vulnerability_desc = finding.get('vulnerability', 'unknown')
                location = finding.get('location', 'unknown')
                recommendation = finding.get('recommendation', '')
                evidence = finding.get('evidence', '')

                # 生成更具体的规则名称
                rule_name = vulnerability_desc
                if status == 'INVALID' and total_vulnerabilities < 10:
                    # 当漏洞数小于10时，为INVALID状态添加特殊标识
                    rule_name = f"[需人工复核] {vulnerability_desc}"
                elif location:
                    rule_name = f"{vulnerability_desc} (位于 {location})"

                # 生成详细的描述
                description = vulnerability_desc
                if evidence:
                    description = f"{vulnerability_desc}。{evidence}"
                if recommendation:
                    description = f"{description} 建议：{recommendation}"
                
                # 根据状态设置严重程度
                severity = finding.get('severity', 'medium')
                if status == 'INVALID':
                    severity = 'info'  # INVALID状态设为info级别

                vulnerability = VulnerabilityFinding(
                    rule_id=finding.get('vulnerability', 'unknown'),
                    rule_name=rule_name,
                    severity=severity,
                    confidence=float(finding.get('confidence', 50)) / 100.0,
                    location={'file': location},
                    description=description,
                    fix_suggestion=recommendation,
                    explanation=json.dumps(finding, ensure_ascii=False)
                )
                findings.append(vulnerability)
                print(f"[DEBUG] 添加漏洞发现: {rule_name}")
        except Exception as e:
            print(f"[PURE-AI] 转换结果失败: {e}")
            import traceback
            traceback.print_exc()

        print(f"[DEBUG] 转换完成，生成 {len(findings)} 个漏洞发现")
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

    def _validate_results(self, result: Dict[str, Any]) -> bool:
        """验证分析结果的完整性

        Args:
            result: 分析结果

        Returns:
            bool: 结果是否完整
        """
        # 检查结果是否包含所有必要的字段
        required_fields = ['file_path', 'context_analysis', 'code_understanding', 
                          'risk_enumeration', 'vulnerability_verification', 
                          'attack_chain_analysis', 'adversarial_validation', 'final_decision']
        
        for field in required_fields:
            if field not in result:
                print(f"[DEBUG] 结果验证失败: 缺少字段 {field}")
                return False
        
        # 检查final_decision是否包含final_findings
        final_decision = result.get('final_decision', {})
        if 'final_findings' not in final_decision:
            print(f"[DEBUG] 结果验证失败: final_decision缺少final_findings字段")
            return False
        
        # 检查final_findings是否为空
        final_findings = final_decision.get('final_findings', [])
        if len(final_findings) == 0:
            print(f"[DEBUG] 结果验证警告: final_findings为空，可能存在遗漏")
            # 不返回False，因为可能确实没有漏洞
        
        return True

    async def analyze_file(self, file_info) -> List[VulnerabilityFinding]:
        """分析文件信息对象

        Args:
            file_info: 文件信息对象

        Returns:
            漏洞发现列表
        """
        try:
            print(f"[DEBUG] 分析文件: {file_info.path}")
            # 检查pipeline是否初始化
            if not self.pipeline:
                console.print(f"[dim][DEBUG] 纯AI分析器未初始化，跳过分析: {file_info.path}[/dim]")
                return []

            # 分析文件
            findings = await self.analyze(file_info.path, "")
            print(f"[DEBUG] 分析完成，发现 {len(findings)} 个问题")
            return findings
        except Exception as e:
            console.print(f"[dim][DEBUG] 纯AI分析文件失败: {e}[/dim]")
            import traceback
            traceback.print_exc()
            return []
