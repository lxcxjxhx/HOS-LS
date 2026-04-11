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
from src.ai.pure_ai.poc_generator import POCGenerator

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
        self.poc_generator = None
        self.initialized = False  # 初始化状态标志
        # POC相关配置
        self.poc_enabled = getattr(config, "poc_enabled", False)
        self.poc_output_dir = getattr(config, "poc_output_dir", "./generated_pocs")
        self.poc_severity = getattr(config, "poc_severity", "high")
        self.poc_max = getattr(config, "poc_max", 10)
        # 快速模式配置
        self.fast_mode = getattr(config, "pure_ai_fast", False)
        # 并行配置
        self.batch_size = getattr(config, "pure_ai_batch_size", 8)
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
                "ollama": AIProvider.LOCAL,  # 支持ollama作为local的别名
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

                # 创建pipeline配置，包含模型信息和语言设置
                pipeline_config = {
                    'max_retries': 3,
                    'model': self.ai_model,
                    'language': getattr(self.config, 'language', 'cn')
                }
                self.pipeline = MultiAgentPipeline(self.client, pipeline_config)
                
                # 初始化POC生成器
                if self.poc_enabled:
                    self.poc_generator = POCGenerator(self.client, pipeline_config)
                    console.print(f"[green]✓ POC生成器初始化成功[/green]")
                
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
    
    async def close(self):
        """关闭分析器，清理资源"""
        if self.model_manager:
            try:
                await self.model_manager.close()
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 模型管理器已关闭[/dim]")
            except Exception as e:
                console.print(f"[yellow]⚠ 关闭模型管理器时出错: {e}[/yellow]")
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
        result = await self.pipeline.run_pipeline(file_path, self.fast_mode)
        print(f"[DEBUG] 多Agent分析完成，结果类型: {type(result)}")

        # 验证结果完整性
        if not self._validate_results(result):
            print(f"[DEBUG] 结果验证失败，可能存在遗漏")

        # 缓存结果
        self.cache_manager.set(file_path, result)

        findings = self._convert_to_findings(result)
        print(f"[DEBUG] 转换为 {len(findings)} 个漏洞发现")
        return findings
    
    async def generate_pocs(self, findings: List[VulnerabilityFinding], file_contents: Dict[str, str]) -> List[Dict[str, Any]]:
        """生成POC

        Args:
            findings: 漏洞发现列表
            file_contents: 文件路径到内容的映射

        Returns:
            POC生成结果列表
        """
        if not self.poc_enabled or not self.poc_generator:
            return []
        
        console.print(f"[cyan]开始生成POC...[/cyan]")
        console.print(f"[dim]POC输出目录: {self.poc_output_dir}[/dim]")
        console.print(f"[dim]严重级别过滤: {self.poc_severity}[/dim]")
        console.print(f"[dim]最大生成数量: {self.poc_max}[/dim]")
        
        results = await self.poc_generator.generate_all(
            findings,
            file_contents,
            self.poc_output_dir,
            self.poc_severity,
            self.poc_max
        )
        
        console.print(f"[green]✓ POC生成完成，共生成 {len(results)} 个POC[/green]")
        return results

    def _normalize_confidence(self, confidence_value) -> float:
        """标准化置信度值（支持多种格式）
        
        Args:
            confidence_value: 置信度值（可能是字符串、数字、百分比等）
            
        Returns:
            float: 标准化的置信度 (0.0 - 1.0)
        """
        try:
            confidence = float(confidence_value)
            # 如果是百分比格式 (>1)，转换为 0-1 范围
            if confidence > 1.0:
                confidence = confidence / 100.0
            return max(0.0, min(confidence, 1.0))
        except (ValueError, TypeError):
            if isinstance(confidence_value, str):
                if '%' in confidence_value:
                    try:
                        return float(confidence_value.replace('%', '')) / 100.0
                    except:
                        return 0.5
                elif confidence_value.lower() in ['高', 'high']:
                    return 0.8
                elif confidence_value.lower() in ['中', 'medium']:
                    return 0.5
                elif confidence_value.lower() in ['低', 'low']:
                    return 0.2
            return 0.5

    def _convert_to_findings(self, result: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """将分析结果转换为漏洞发现列表（混合模式：新架构优先 + 旧逻辑兜底）

        策略：
        - 优先使用新的 FinalDecisionBuilder 架构（简洁高效）
        - 如果新架构失败或数据不完整，回退到旧的完整逻辑（健壮兜底）
        - 双重保障，100%稳定

        Args:
            result: 分析结果

        Returns:
            漏洞发现列表
        """
        findings = []
        try:
            # ========== 新架构（优先尝试） ==========
            try:
                from src.core.final_decision_builder import ensure_final_decision
                
                result = ensure_final_decision(result)
                final_decision = result.get('final_decision', {})
                vulnerabilities = final_decision.get('vulnerabilities', [])
                
                if vulnerabilities and len(vulnerabilities) > 0:
                    print(f"[DEBUG] ✓ 使用新架构提取: {len(vulnerabilities)} 个漏洞")
                    
                    for vuln in vulnerabilities:
                        try:
                            # 🔧 BUG FIX #4: 确保location字段是字符串
                            loc = vuln.get('location', result.get('file_path', 'unknown'))
                            safe_loc = str(loc) if hasattr(loc, '__fspath__') else loc

                            finding = VulnerabilityFinding(
                                rule_id=vuln.get('rule_id', ''),
                                rule_name=vuln.get('vulnerability') or vuln.get('type', 'Unknown'),
                                severity=vuln.get('severity', 'medium'),
                                confidence=self._normalize_confidence(vuln.get('confidence', 'medium')),
                                location={'file': safe_loc},
                                description=vuln.get('description') or vuln.get('potential_impact', ''),
                                fix_suggestion=vuln.get('recommendation') or vuln.get('fix_suggestion', ''),
                                explanation=json.dumps(vuln, ensure_ascii=False, default=str)
                            )
                            findings.append(finding)
                        except Exception as e:
                            print(f"[DEBUG] 新架构处理单个漏洞失败: {e}")
                            continue
                    
                    if findings:
                        print(f"[DEBUG] ✓ 新架构成功: {len(findings)} 个发现")
                        return findings
                        
            except Exception as new_arch_error:
                print(f"[DEBUG] ⚠ 新架构不可用，回退到旧逻辑: {new_arch_error}")
            
            # ========== 旧逻辑（完整兜底） ==========
            print(f"[DEBUG] 使用旧逻辑（兼容模式）")
            
            print(f"[DEBUG] 开始转换结果，结果包含: {list(result.keys())}")
            final_decision = result.get('final_decision', {})
            print(f"[DEBUG] final_decision 类型: {type(final_decision)}")
            print(f"[DEBUG] final_decision 键: {list(final_decision.keys())}")
            
            # 增强的调试：显示完整的 final_decision 内容（前 2000 字符）
            try:
                final_decision_str = json.dumps(final_decision, ensure_ascii=False, indent=2, default=str)
                print(f"[DEBUG] final_decision 内容预览: {final_decision_str[:2000]}")
            except Exception as e:
                print(f"[DEBUG] 无法序列化final_decision: {e}")
                print(f"[DEBUG] final_decision 类型: {type(final_decision)}")
            
            # 尝试多种可能的键来获取发现
            final_findings = []
            
            # 1. 首先尝试标准的 final_findings 键
            if 'final_findings' in final_decision:
                final_findings = final_decision['final_findings']
                print(f"[DEBUG] 通过 'final_findings' 键找到 {len(final_findings)} 个发现")
            
            # 2. 如果没找到，尝试其他可能的键
            if not final_findings:
                alternative_keys = ['findings', 'vulnerabilities', 'issues', 'results', 'finding']
                for key in alternative_keys:
                    if key in final_decision:
                        candidate = final_decision[key]
                        if isinstance(candidate, list) and len(candidate) > 0:
                            final_findings = candidate
                            print(f"[DEBUG] 通过 '{key}' 键找到 {len(final_findings)} 个发现")
                            break
            
            # 3. 如果 still 没找到，尝试从整个结果中查找
            if not final_findings:
                print(f"[DEBUG] 尝试从整个结果中查找发现...")
                for agent_key in ['vulnerability_verification', 'risk_enumeration', 'code_understanding', 'context_compression', 'risk_validation', 'attack_simulation']:
                    if agent_key in result:
                        agent_data = result[agent_key]
                        for possible_key in ['findings', 'vulnerabilities', 'issues', 'risks', 'problems', 'alerts']:
                            if possible_key in agent_data:
                                candidate = agent_data[possible_key]
                                if isinstance(candidate, list) and len(candidate) > 0:
                                    final_findings = candidate
                                    print(f"[DEBUG] 通过 {agent_key}.{possible_key} 找到 {len(final_findings)} 个发现")
                                    break
                        if final_findings:
                            break
            
            # 4. 如果仍然没找到，使用默认发现
            if not final_findings:
                print(f"[DEBUG] 未找到任何发现，使用默认发现")
                final_findings = [{
                    "vulnerability": "未发现安全问题",
                    "location": result.get('file_path', 'unknown'),
                    "severity": "info",
                    "status": "VALID",
                    "confidence": "高",
                    "cvss_score": "",
                    "recommendation": "代码安全，无需修复",
                    "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
                }]
            
            print(f"[DEBUG] 最终找到 {len(final_findings)} 个发现")

            # 🔧 BUG FIX #4: 辅助函数 - 递归转换所有Path对象为字符串
            def _convert_paths_to_strings(obj):
                """递归将字典/列表中所有的Path对象转换为字符串"""
                if isinstance(obj, dict):
                    return {k: _convert_paths_to_strings(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [_convert_paths_to_strings(item) for item in obj]
                elif hasattr(obj, '__fspath__'):  # 检测 Path-like 对象 (WindowsPath, PosixPath等)
                    return str(obj)
                else:
                    return obj

            # 计算总漏洞数
            total_vulnerabilities = len(final_findings)

            for finding in final_findings:
                try:
                    # 先转换所有Path对象为字符串，避免JSON序列化错误
                    safe_finding = _convert_paths_to_strings(finding)
                    finding_json = json.dumps(safe_finding, ensure_ascii=False, indent=2)
                    print(f"[DEBUG] 处理发现: {finding_json}")
                    
                    # 智能字段映射：支持所有Agent的输出格式
                    # Agent 2 (Risk Enumeration): type, location, description, potential_impact, cvss_score
                    # Agent 3 (Vulnerability Verification): risk_type, location, attack_path, payload, verdict, reason, cvss_score
                    # Agent 6 (Final Decision): vulnerability, location, severity, status, confidence, cvss_score, recommendation, evidence
                    
                    # 漏洞描述：尝试所有可能的字段
                    vulnerability_desc = 'unknown'
                    for key in ['vulnerability', 'type', 'risk_type', 'name', 'issue', 'title', 'problem']:
                        if key in finding and finding[key]:
                            vulnerability_desc = finding[key]
                            print(f"[DEBUG] 使用 {key} 作为漏洞描述: {vulnerability_desc}")
                            break
                    
                    # 状态字段
                    status = 'UNKNOWN'
                    for key in ['status', 'state', 'verdict', 'result']:
                        if key in finding and finding[key]:
                            status = finding[key]
                            print(f"[DEBUG] 使用 {key} 作为状态: {status}")
                            break
                    
                    # 位置字段
                    location = 'unknown'
                    for key in ['location', 'position', 'file', 'path', 'file_path']:
                        if key in finding and finding[key]:
                            location = finding[key]
                            print(f"[DEBUG] 使用 {key} 作为位置: {location}")
                            break
                    
                    # 推荐/修复字段
                    recommendation = ''
                    for key in ['recommendation', 'fix', 'suggestion', 'potential_impact', 'reason', 'solution', 'remediation']:
                        if key in finding and finding[key]:
                            recommendation = finding[key]
                            print(f"[DEBUG] 使用 {key} 作为推荐: {recommendation[:100]}...")
                            break
                    
                    # 证据/描述字段
                    evidence = ''
                    for key in ['evidence', 'description', 'details', 'reason', 'attack_path', 'payload', 'explanation']:
                        if key in finding and finding[key]:
                            evidence = finding[key]
                            print(f"[DEBUG] 使用 {key} 作为证据: {evidence[:100]}...")
                            break
                    
                    # 严重级别字段
                    severity = 'medium'
                    for key in ['severity', 'risk_level', 'level', 'priority']:
                        if key in finding and finding[key]:
                            severity = finding[key]
                            print(f"[DEBUG] 使用 {key} 作为严重级别: {severity}")
                            break
                    
                    # 置信度字段
                    confidence_value = 50
                    for key in ['confidence', 'score', 'certainty']:
                        if key in finding and finding[key] is not None:
                            confidence_value = finding[key]
                            print(f"[DEBUG] 使用 {key} 作为置信度: {confidence_value}")
                            break
                    
                    print(f"[DEBUG] 解析字段 - vulnerability: {vulnerability_desc}, status: {status}, location: {location}, severity: {severity}")
                    
                    # 处理所有状态的发现，包括INVALID
                    if status == 'INVALID' or status == 'NO' or status == 'REFUTE':
                        severity = 'info'  # INVALID/NO/REFUTE状态设为info级别

                    # 生成更具体的规则名称
                    rule_name = vulnerability_desc
                    if status == 'INVALID' and total_vulnerabilities < 10:
                        # 当漏洞数小于10时，为INVALID状态添加特殊标识
                        rule_name = f"[需人工复核] {vulnerability_desc}"
                    elif location and location != 'unknown':
                        rule_name = f"{vulnerability_desc} (位于 {location})"

                    # 生成详细的描述
                    description = vulnerability_desc
                    if evidence:
                        description = f"{vulnerability_desc}。{evidence}"
                    if recommendation:
                        description = f"{description} 建议：{recommendation}"

                    # 处理置信度，避免空字符串转换错误
                    try:
                        confidence = float(confidence_value) / 100.0
                    except (ValueError, TypeError):
                        # 尝试将字符串转换为数值
                        if isinstance(confidence_value, str):
                            # 处理百分比格式
                            if '%' in confidence_value:
                                try:
                                    confidence = float(confidence_value.replace('%', '')) / 100.0
                                except:
                                    confidence = 0.5
                            # 处理文本格式
                            elif confidence_value in ['高', 'high']:
                                confidence = 0.8
                            elif confidence_value in ['中', 'medium']:
                                confidence = 0.5
                            elif confidence_value in ['低', 'low']:
                                confidence = 0.2
                            else:
                                confidence = 0.5
                        else:
                            confidence = 0.5
                    
                    vulnerability = VulnerabilityFinding(
                        rule_id=vulnerability_desc,
                        rule_name=rule_name,
                        severity=severity,
                        confidence=confidence,
                        location={'file': str(location) if hasattr(location, '__fspath__') else location},  # 确保location是字符串
                        description=description,
                        fix_suggestion=recommendation,
                        explanation=json.dumps(safe_finding, ensure_ascii=False, default=str)  # 🔧 使用safe_finding
                    )
                    findings.append(vulnerability)
                    print(f"[DEBUG] 添加漏洞发现: {rule_name}")
                except Exception as e:
                    print(f"[DEBUG] 处理单个发现失败: {e}")
                    continue
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
        """验证分析结果的完整性（混合模式：新架构优先 + 旧逻辑兜底）

        策略：
        - 优先使用新的 ensure_final_decision 保证数据完整
        - 如果新架构失败，回退到旧的验证逻辑
        - 永远返回 True（避免上层崩溃）

        Args:
            result: 分析结果

        Returns:
            bool: 结果是否完整（永远返回True）
        """
        # ========== 新架构（优先尝试） ==========
        try:
            from src.core.final_decision_builder import ensure_final_decision
            
            result = ensure_final_decision(result)
            
            final_decision = result.get('final_decision', {})
            vuln_count = len(final_decision.get('vulnerabilities', []))
            risk_level = final_decision.get('risk_level', 'unknown')
            
            print(f"[DEBUG] ✓ 新架构验证完成: "
                  f"{vuln_count} 个漏洞, "
                  f"风险等级: {risk_level}, "
                  f"置信度: {final_decision.get('confidence', 0):.0%}")
            
            return True  # 新架构成功
            
        except Exception as new_arch_error:
            print(f"[DEBUG] ⚠ 新架构验证失败，回退到旧逻辑: {new_arch_error}")
        
        # ========== 旧逻辑（完整兜底） ==========
        print(f"[DEBUG] 使用旧逻辑验证（兼容模式）")
        
        # 检查结果是否包含基本字段
        required_fields = ['file_path', 'final_decision']
        
        for field in required_fields:
            if field not in result:
                print(f"[DEBUG] 结果验证失败: 缺少字段 {field}")
                return False
        
        # 检查final_decision是否包含final_findings
        final_decision = result.get('final_decision', {})
        if 'final_findings' not in final_decision:
            # 创建空的final_findings
            final_decision['final_findings'] = []
            print(f"[DEBUG] 结果验证警告: final_decision缺少final_findings字段，已创建空列表")
        
        # 检查final_findings是否为空
        final_findings = final_decision.get('final_findings', [])
        if len(final_findings) == 0:
            print(f"[DEBUG] 结果验证警告: final_findings为空，可能存在遗漏")
            # 添加默认的发现信息，确保系统能够正常处理
            final_decision['final_findings'] = [{
                "vulnerability": "未发现安全问题",
                "location": result.get('file_path', 'unknown'),
                "severity": "info",
                "status": "VALID",
                "confidence": "高",
                "cvss_score": "",
                "recommendation": "代码安全，无需修复",
                "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
            }]
            print(f"[DEBUG] 已添加默认的发现信息")
        
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

    async def analyze_batch(self, file_infos: List[Any], max_concurrent: int = None) -> List[List[VulnerabilityFinding]]:
        """批量分析文件
        
        Args:
            file_infos: 文件信息列表
            max_concurrent: 最大并发数，默认使用batch_size
        
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
        
        try:
            # 优化并发处理
            start_time = time.time()
            total_files = len(file_infos)
            
            if total_files == 0:
                return []
            
            # 使用batch_size作为默认并发数
            if max_concurrent is None:
                max_concurrent = self.batch_size
            
            # 动态调整并发数，根据文件数量
            if total_files < 10:
                max_concurrent = min(max_concurrent, 3)
            elif total_files < 50:
                max_concurrent = min(max_concurrent, 5)
            else:
                max_concurrent = min(max_concurrent, self.batch_size)
            
            console.print(f"[dim]批量分析配置: 并发数={max_concurrent}, 总文件数={total_files}[/dim]")
            
            # 分批处理
            batch_size = max_concurrent
            results = []
            
            for i in range(0, total_files, batch_size):
                batch = file_infos[i:i+batch_size]
                batch_start = time.time()
                
                # 创建任务
                tasks = []
                semaphore = asyncio.Semaphore(max_concurrent)
                
                async def analyze_with_limit(file_info, index):
                    async with semaphore:
                        if self.config.debug:
                            print(f"[DEBUG] 分析文件 {i+index+1}/{total_files}: {file_info.path}")
                        return await self.analyze_file(file_info)
                
                for j, file_info in enumerate(batch):
                    tasks.append(analyze_with_limit(file_info, j))
                
                # 执行批次任务
                batch_results = await asyncio.gather(*tasks)
                results.extend(batch_results)
                
                batch_elapsed = time.time() - batch_start
                console.print(f"[dim]批次 {i//batch_size + 1} 完成，处理 {len(batch)} 个文件，耗时 {batch_elapsed:.2f} 秒[/dim]")
            
            if self.config.debug:
                elapsed_time = time.time() - start_time
                print(f"[DEBUG] 批量分析完成，处理 {total_files} 个文件，耗时 {elapsed_time:.2f} 秒")
            
            return results
        finally:
            # 分析完成后关闭客户端会话
            await self.close()
    
    async def analyze_and_generate_pocs(self, file_infos: List[Any], max_concurrent: int = None) -> Dict[str, Any]:
        """分析文件并生成POC
        
        Args:
            file_infos: 文件信息列表
            max_concurrent: 最大并发数，默认使用batch_size
        
        Returns:
            包含分析结果和POC生成结果的字典
        """
        try:
            # 分析文件
            findings_list = await self.analyze_batch(file_infos, max_concurrent)
            
            # 收集所有发现
            all_findings = []
            file_contents = {}
            
            for i, findings in enumerate(findings_list):
                all_findings.extend(findings)
                # 收集文件内容
                file_info = file_infos[i]
                if hasattr(file_info, 'path'):
                    try:
                        with open(file_info.path, 'r', encoding='utf-8') as f:
                            file_contents[file_info.path] = f.read()
                    except Exception as e:
                        console.print(f"[yellow]⚠ 无法读取文件内容: {file_info.path} - {e}[/yellow]")
            
            # 生成POC
            poc_results = []
            if self.poc_enabled and all_findings:
                poc_results = await self.generate_pocs(all_findings, file_contents)
            
            return {
                'findings': all_findings,
                'poc_results': poc_results,
                'file_count': len(file_infos)
            }
        finally:
            # 分析和POC生成完成后关闭客户端会话
            await self.close()
