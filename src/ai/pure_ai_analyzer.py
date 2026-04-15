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
        self.ai_provider = getattr(config, "pure_ai_provider", "deepseek")
        self.ai_model = "deepseek-reasoner"
        self.model_manager = None
        self.client = None
        self.pipeline = None
        self.cache_manager = CacheManager()
        self.initialized = False
        self.debug_logs: List[str] = []
    
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
                console.print(f"[yellow]⚠ 警告: API 密钥未设置，纯AI分析器可能无法正常工作[/yellow]")
                console.print(f"[dim]请设置环境变量 HOS_LS_AI_API_KEY 或 DEEPSEEK_API_KEY[/dim]")
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
                console.print(f"[dim][DEBUG] 模型管理器初始化成功[/dim]")

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
                        console.print(f"[green]✓ API访问验证成功[/green]")
                    else:
                        console.print(f"[red]✗ API访问验证失败: {error_msg}[/red]")
                        console.print(f"[yellow]⚠ 纯AI分析器将以降级模式运行[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]⚠ API访问验证异常: {e}[/yellow]")

                # 创建pipeline配置，包含模型信息
                pipeline_config = {
                    'max_retries': 3,
                    'model': self.ai_model
                }
                self.pipeline = MultiAgentPipeline(self.client, pipeline_config)
                self.initialized = True  # 标记初始化成功
                console.print(f"[green]✓ 纯AI分析器初始化成功[/green] (提供商: {self.ai_provider}, 模型: {self.ai_model})")
            else:
                console.print(f"[red]✗ 纯AI分析器初始化失败：无法获取AI客户端[/red]")
                console.print(f"[dim]请检查API密钥配置和网络连接[/dim]")
        except Exception as e:
            console.print(f"[red]✗ 纯AI分析器初始化失败: {e}[/red]")
            import traceback
            traceback.print_exc()
            self.initialized = False

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

        # 收集 pipeline 的 debug_logs
        if isinstance(result, dict) and 'debug_logs' in result:
            self.debug_logs.extend(result['debug_logs'])

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
            self.debug_logs.append(f"[DEBUG] 开始转换结果，结果包含: {list(result.keys())}")
            final_decision = result.get('final_decision', {})
            print(f"[DEBUG] final_decision 类型: {type(final_decision)}")
            self.debug_logs.append(f"[DEBUG] final_decision 类型: {type(final_decision)}")
            final_findings = final_decision.get('final_findings', [])
            print(f"[DEBUG] 找到 {len(final_findings)} 个最终发现")
            self.debug_logs.append(f"[DEBUG] 找到 {len(final_findings)} 个最终发现")

            # Fallback: 如果 final_findings 为空，尝试从其他 Agent 获取漏洞
            if len(final_findings) == 0:
                vuln_verif = result.get('vulnerability_verification', {})
                confirmed = vuln_verif.get('confirmed_vulnerabilities', [])
                verifications = vuln_verif.get('verifications', [])
                risks = vuln_verif.get('risks', [])

                if not confirmed and verifications:
                    confirmed = [
                        v for v in verifications
                        if v.get('verdict', '').upper() == 'YES'
                    ]
                    print(f"[DEBUG] 从 verifications 提取 confirmed_vulnerabilities: {len(confirmed)}")

                adversarial_val = result.get('adversarial_validation', {})
                adversarial_analysis = adversarial_val.get('adversarial_analysis', [])
                adversarial_findings = []

                for item in adversarial_analysis:
                    verdict = item.get('verdict', '')
                    if verdict in ['ACCEPT', 'ESCALATE']:
                        vuln_info = item.get('vulnerability', {})
                        if isinstance(vuln_info, dict):
                            adversarial_findings.append({
                                'vulnerability': vuln_info.get('title', item.get('attack_chain_name', 'Unknown')),
                                'location': vuln_info.get('location', 'Unknown'),
                                'severity': vuln_info.get('severity', 'MEDIUM'),
                                'status': 'VALID' if verdict == 'ACCEPT' else 'UNCERTAIN',
                                'confidence': vuln_info.get('confidence', 'MEDIUM'),
                                'cvss_score': vuln_info.get('cvss_score', ''),
                                'recommendation': item.get('reason', '需要人工复核'),
                                'evidence': item.get('evidence', ''),
                                'requires_human_review': item.get('requires_human_review', True)
                            })
                        else:
                            adversarial_findings.append({
                                'vulnerability': item.get('attack_chain_name', 'Unknown'),
                                'location': 'Unknown',
                                'severity': 'MEDIUM',
                                'status': 'VALID' if verdict == 'ACCEPT' else 'UNCERTAIN',
                                'confidence': 'MEDIUM',
                                'cvss_score': '',
                                'recommendation': item.get('reason', '需要人工复核'),
                                'evidence': item.get('evidence', ''),
                                'requires_human_review': item.get('requires_human_review', True)
                            })

                risk_enum = result.get('risk_enumeration', {})
                risk_findings = risk_enum.get('risks', [])
                potential_vulns = risk_enum.get('potential_vulnerabilities', [])

                print(f"[DEBUG] Fallback 检查:")
                print(f"  - vulnerability_verification.confirmed_vulnerabilities: {len(confirmed)}")
                print(f"  - vulnerability_verification.risks: {len(risks)}")
                print(f"  - adversarial_validation.ACCEPT/ESCALATE: {len(adversarial_findings)}")
                print(f"  - risk_enumeration.risks: {len(risk_findings)}")
                print(f"  - risk_enumeration.potential_vulnerabilities: {len(potential_vulns)}")

                if adversarial_findings:
                    print(f"[DEBUG] 使用 fallback: 从 adversarial_validation 获取 {len(adversarial_findings)} 个漏洞")
                    final_findings = adversarial_findings
                elif confirmed:
                    print(f"[DEBUG] 使用 fallback: 从 vulnerability_verification.confirmed_vulnerabilities 获取 {len(confirmed)} 个漏洞")
                    final_findings = confirmed
                elif risks:
                    print(f"[DEBUG] 使用 fallback: 从 vulnerability_verification.risks 获取 {len(risks)} 个漏洞")
                    final_findings = risks
                elif risk_findings:
                    print(f"[DEBUG] 使用 fallback: 从 risk_enumeration.risks 获取 {len(risk_findings)} 个风险")
                    final_findings = []
                    for risk in risk_findings:
                        risk_vuln = {
                            'vulnerability': risk.get('risk_type', 'Unknown'),
                            'location': risk.get('location', 'Unknown'),
                            'severity': risk.get('severity', 'INFO'),
                            'status': 'UNCERTAIN',
                            'confidence': 'LOW',
                            'cvss_score': '',
                            'recommendation': '需要人工复核此风险',
                            'evidence': risk.get('description', ''),
                            'requires_human_review': True
                        }
                        final_findings.append(risk_vuln)

            # 计算总漏洞数
            total_vulnerabilities = len(final_findings)
            
            for finding in final_findings:
                try:
                    print(f"[DEBUG] 处理发现: {finding.get('vulnerability')}, 状态: {finding.get('status')}")
                    self.debug_logs.append(f"[DEBUG] 处理发现: {finding.get('vulnerability')}, 状态: {finding.get('status')}")
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

                    # 处理置信度，避免空字符串转换错误
                    confidence_value = finding.get('confidence', 50)
                    try:
                        confidence = float(confidence_value) / 100.0
                    except (ValueError, TypeError):
                        confidence = 0.5
                    
                    vulnerability = VulnerabilityFinding(
                        rule_id=finding.get('vulnerability', 'unknown'),
                        rule_name=rule_name,
                        severity=severity,
                        confidence=confidence,
                        location={'file': location},
                        description=description,
                        fix_suggestion=recommendation,
                        explanation=json.dumps(finding, ensure_ascii=False)
                    )
                    findings.append(vulnerability)
                    print(f"[DEBUG] 添加漏洞发现: {rule_name}")
                    self.debug_logs.append(f"[DEBUG] 添加漏洞发现: {rule_name}")
                except Exception as e:
                    print(f"[DEBUG] 处理单个发现失败: {e}")
                    self.debug_logs.append(f"[DEBUG] 处理单个发现失败: {e}")
                    continue
        except Exception as e:
            print(f"[PURE-AI] 转换结果失败: {e}")
            self.debug_logs.append(f"[DEBUG] 转换结果失败: {e}")
            import traceback
            traceback.print_exc()

        print(f"[DEBUG] 转换完成，生成 {len(findings)} 个漏洞发现")
        self.debug_logs.append(f"[DEBUG] 转换完成，生成 {len(findings)} 个漏洞发现")
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

    def _validate_results(self, result: Dict[str, Any], strict: bool = False) -> bool:
        """验证分析结果的完整性

        Args:
            result: 分析结果
            strict: 是否使用严格模式（严格模式下抛出异常）

        Returns:
            bool: 结果是否完整
        """
        required_fields = ['file_path', 'context_analysis', 'code_understanding',
                          'risk_enumeration', 'vulnerability_verification',
                          'attack_chain_analysis', 'adversarial_validation', 'final_decision']

        for field in required_fields:
            if field not in result:
                error_msg = f"结果验证失败: 缺少字段 {field}"
                print(f"[DEBUG] {error_msg}")
                if strict:
                    raise ValueError(error_msg)
                return False

        final_decision = result.get('final_decision', {})
        if 'final_findings' not in final_decision:
            error_msg = "Final Agent 输出结构错误：缺少 final_findings 字段"
            print(f"[DEBUG] {error_msg}")
            if strict:
                raise ValueError(error_msg)
            final_decision['final_findings'] = []

        final_findings = final_decision.get('final_findings', [])
        if len(final_findings) == 0:
            risk_enum = result.get('risk_enumeration', {})
            vuln_verif = result.get('vulnerability_verification', {})
            adversarial_val = result.get('adversarial_validation', {})

            has_potential_findings = (
                (risk_enum.get('potential_vulnerabilities') and len(risk_enum['potential_vulnerabilities']) > 0) or
                (vuln_verif.get('confirmed_vulnerabilities') and len(vuln_verif['confirmed_vulnerabilities']) > 0) or
                (adversarial_val.get('findings') and len(adversarial_val['findings']) > 0) or
                (risk_enum.get('risks') and len(risk_enum['risks']) > 0)
            )

            if has_potential_findings:
                print(f"[WARN] Agent 6 判定无漏洞，但其他 Agent 发现了潜在漏洞")
                print(f"[WARN]   - risk_enumeration potential_vulnerabilities: {len(risk_enum.get('potential_vulnerabilities', []))}")
                print(f"[WARN]   - vulnerability_verification confirmed_vulnerabilities: {len(vuln_verif.get('confirmed_vulnerabilities', []))}")
                print(f"[WARN]   - adversarial_validation findings: {len(adversarial_val.get('findings', []))}")
                if strict:
                    raise ValueError("Agent 6 漏报：发现了潜在漏洞但 final_findings 为空")

        return True

    async def analyze_file(self, file_info) -> List[VulnerabilityFinding]:
        """分析文件信息对象

        Args:
            file_info: 文件信息对象

        Returns:
            漏洞发现列表
        """
        try:
            if self.config.debug:
                print(f"[DEBUG] 分析文件: {file_info.path}")

            # 确保已初始化
            if not self.initialized:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 纯AI分析器未初始化，正在初始化...[/dim]")
                await self._initialize()
                if not self.initialized:
                    console.print(f"[red]✗ 纯AI分析器初始化失败，跳过分析: {file_info.path}[/red]")
                    return []

            # 检查pipeline
            if not self.pipeline:
                console.print(f"[red]✗ Pipeline未创建，跳过分析: {file_info.path}[/red]")
                return []

            # 分析文件
            findings = await self.analyze(file_info.path, "")
            if self.config.debug:
                print(f"[DEBUG] 分析完成，发现 {len(findings)} 个问题")
            return findings
        except Exception as e:
            console.print(f"[red]✗ 纯AI分析文件失败: {e}[/red]")
            if self.config.debug:
                import traceback
                traceback.print_exc()
            return []

    async def analyze_batch(self, file_infos: List[Any], max_concurrent: int = 5) -> List[List[VulnerabilityFinding]]:
        """批量分析文件
        
        Args:
            file_infos: 文件信息列表
            max_concurrent: 最大并发数，默认5
        
        Returns:
            漏洞发现列表的列表
        """
        import asyncio
        import time
        
        # 确保已初始化
        if not self.initialized:
            await self._initialize()
            if not self.initialized:
                return [[] for _ in file_infos]
        
        # 优化并发处理，增加默认并发数
        start_time = time.time()
        total_files = len(file_infos)
        
        if total_files == 0:
            return []
        
        # 动态调整并发数，根据文件数量
        if total_files < 10:
            max_concurrent = min(max_concurrent, 3)
        elif total_files < 50:
            max_concurrent = min(max_concurrent, 5)
        else:
            max_concurrent = min(max_concurrent, 8)
        
        # 创建任务
        tasks = []
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def analyze_with_limit(file_info, index):
            async with semaphore:
                if self.config.debug:
                    print(f"[DEBUG] 分析文件 {index+1}/{total_files}: {file_info.path}")
                return await self.analyze_file(file_info)
        
        for i, file_info in enumerate(file_infos):
            tasks.append(analyze_with_limit(file_info, i))
        
        # 执行任务
        results = await asyncio.gather(*tasks)
        
        if self.config.debug:
            elapsed_time = time.time() - start_time
            print(f"[DEBUG] 批量分析完成，处理 {total_files} 个文件，耗时 {elapsed_time:.2f} 秒")

        return results

    async def resume(self, checkpoint_data: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """从断点恢复扫描

        Args:
            checkpoint_data: Checkpoint数据，包含已处理文件列表和进度信息

        Returns:
            漏洞发现列表
        """
        try:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 开始从断点恢复扫描[/dim]")

            processed_files = checkpoint_data.get('processed_files', [])
            pending_files = checkpoint_data.get('pending_files', [])
            results = checkpoint_data.get('results', [])

            if self.config.debug:
                console.print(f"[dim][DEBUG] 已处理文件数: {len(processed_files)}[/dim]")
                console.print(f"[dim][DEBUG] 待处理文件数: {len(pending_files)}[/dim]")

            # 确保已初始化
            if not self.initialized:
                await self._initialize()
                if not self.initialized:
                    console.print(f"[red]✗ 纯AI分析器初始化失败，无法恢复扫描[/red]")
                    return results

            # 继续处理未完成的部分
            for file_info in pending_files:
                try:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 恢复处理文件: {file_info.path}[/dim]")

                    findings = await self.analyze_file(file_info)
                    results.append(findings)
                    processed_files.append(file_info.path)

                    # 调用检查点回调
                    if hasattr(self, 'checkpoint_callback') and self.checkpoint_callback:
                        self.checkpoint_callback({
                            'processed_file': file_info.path,
                            'findings_count': len(findings),
                            'total_processed': len(processed_files)
                        })

                    # 更新上下文记忆
                    if hasattr(self, 'context_memory') and self.context_memory:
                        await self.context_memory.update(file_info.path, findings)

                except Exception as e:
                    console.print(f"[red]✗ 恢复处理文件失败 {file_info.path}: {e}[/red]")
                    results.append([])
                    continue

            if self.config.debug:
                console.print(f"[dim][DEBUG] 断点恢复完成，共处理 {len(processed_files)} 个文件[/dim]")

            return results

        except Exception as e:
            console.print(f"[red]✗ 断点恢复失败: {e}[/red]")
            import traceback
            traceback.print_exc()
            return []

    async def incremental_scan(self, file_infos: List[Any],
                               incremental_index: Any) -> List[List[VulnerabilityFinding]]:
        """增量扫描

        Args:
            file_infos: 文件信息列表
            incremental_index: 增量索引管理器

        Returns:
            漏洞发现列表的列表
        """
        try:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 开始增量扫描，共 {len(file_infos)} 个文件[/dim]")

            # 确保已初始化
            if not self.initialized:
                await self._initialize()
                if not self.initialized:
                    return [[] for _ in file_infos]

            # 检测变更文件
            changed_files = []
            unchanged_files = []
            cached_results = []

            for file_info in file_infos:
                is_changed, change_type = incremental_index.check_file_change(file_info)
                if is_changed:
                    changed_files.append((file_info, change_type))
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 检测到变更文件: {file_info.path} (类型: {change_type})[/dim]")
                else:
                    unchanged_files.append(file_info)
                    # 复用未变更文件的缓存结果
                    cached = self.cache_manager.get(file_info.path)
                    if cached:
                        cached_results.append(self._convert_to_findings(cached))
                    else:
                        cached_results.append([])

            if self.config.debug:
                console.print(f"[dim][DEBUG] 变更文件: {len(changed_files)}, 未变更文件: {len(unchanged_files)}[/dim]")

            # 构建结果列表，保持原始顺序
            results = []
            changed_idx = 0
            cached_idx = 0

            for file_info in file_infos:
                is_changed, _ = incremental_index.check_file_change(file_info)
                if is_changed:
                    # 扫描变更文件
                    findings = await self.analyze_file(file_info)
                    results.append(findings)
                    changed_idx += 1

                    # 更新检查点回调
                    if hasattr(self, 'checkpoint_callback') and self.checkpoint_callback:
                        self.checkpoint_callback({
                            'processed_file': file_info.path,
                            'findings_count': len(findings),
                            'change_type': 'incremental'
                        })
                else:
                    # 复用缓存结果
                    results.append(cached_results[cached_idx] if cached_idx < len(cached_results) else [])
                    cached_idx += 1

            if self.config.debug:
                console.print(f"[dim][DEBUG] 增量扫描完成[/dim]")

            return results

        except Exception as e:
            console.print(f"[red]✗ 增量扫描失败: {e}[/red]")
            import traceback
            traceback.print_exc()
            return [[] for _ in file_infos]

    def set_context_memory(self, context_memory) -> None:
        """设置上下文记忆管理器

        Args:
            context_memory: ContextMemoryManager实例
        """
        self.context_memory = context_memory
        if self.config.debug:
            console.print(f"[dim][DEBUG] 上下文记忆管理器已设置[/dim]")

    def set_checkpoint_callback(self, callback) -> None:
        """设置检查点回调函数

        Args:
            callback: 回调函数，每次处理完一个文件后调用
        """
        self.checkpoint_callback = callback
        if self.config.debug:
            console.print(f"[dim][DEBUG] 检查点回调函数已设置[/dim]")
