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

        # 收集 pipeline 的 debug_logs (过滤掉WARN消息)
        if isinstance(result, dict) and 'debug_logs' in result:
            pipeline_logs = result['debug_logs']
            filtered_logs = [log for log in pipeline_logs if '[WARN]' not in str(log)]
            self.debug_logs.extend(filtered_logs)

        # 验证结果完整性
        if not self._validate_results(result):
            print(f"[DEBUG] 结果验证失败，可能存在遗漏")

        # 缓存结果
        self.cache_manager.set(file_path, result)

        findings = self._convert_to_findings(result)
        print(f"[DEBUG] 转换为 {len(findings)} 个漏洞发现")
        return findings

    def _extract_location_from_evidence(self, finding: Dict[str, Any], file_path_context: str) -> str:
        """从evidence中提取位置信息

        Args:
            finding: 发现数据
            file_path_context: 文件路径上下文

        Returns:
            提取的位置字符串
        """
        evidence = finding.get('evidence', [])
        if not evidence:
            return file_path_context

        if isinstance(evidence, list):
            for ev in evidence:
                if isinstance(ev, dict):
                    loc = ev.get('location', '')
                    if loc and loc not in ('N/A', 'Unknown', '', None):
                        if isinstance(loc, (int, float)):
                            return f"{Path(file_path_context).name}:{int(loc)}"
                        return f"{Path(file_path_context).name}:{loc}"
        elif isinstance(evidence, dict):
            loc = evidence.get('location', '')
            if loc and loc not in ('N/A', 'Unknown', '', None):
                return f"{Path(file_path_context).name}:{loc}"

        return file_path_context

    def _line_exists_in_file(self, file_path: str, line_num: int) -> bool:
        """验证指定行号是否在文件真实存在

        Args:
            file_path: 文件路径
            line_num: 行号

        Returns:
            行号是否有效
        """
        if not file_path or line_num <= 0:
            return False
        try:
            path = Path(file_path)
            if not path.exists():
                return False
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                return 0 < line_num <= len(lines)
        except Exception:
            return False

    def _extract_code_at_line(self, file_path: str, line_num: int, context_lines: int = 2) -> str:
        """提取指定行及其上下文的代码

        Args:
            file_path: 文件路径
            line_num: 行号
            context_lines: 上下文行数

        Returns:
            代码片段
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return ""
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                if line_num <= 0 or line_num > len(lines):
                    return ""
                start = max(0, line_num - context_lines - 1)
                end = min(len(lines), line_num + context_lines)
                return ''.join(lines[start:end])
        except Exception:
            return ""

    def _verify_code_pattern_in_file(self, file_path: str, line_num: int, pattern_keywords: List[str]) -> bool:
        """验证代码模式是否在指定行附近存在

        Args:
            file_path: 文件路径
            line_num: 行号
            pattern_keywords: 需要验证的关键词列表

        Returns:
            模式是否匹配
        """
        if not pattern_keywords:
            return True
        try:
            code_snippet = self._extract_code_at_line(file_path, line_num, context_lines=3)
            if not code_snippet:
                return False
            code_upper = code_snippet.upper()
            return any(kw.upper() in code_upper for kw in pattern_keywords)
        except Exception:
            return False

    def _validate_finding_location(self, finding: Dict[str, Any], file_path_context: str) -> Dict[str, Any]:
        """验证漏洞发现的位置和代码是否真实存在

        Args:
            finding: 漏洞发现
            file_path_context: 文件路径上下文

        Returns:
            验证结果，包含 is_valid, reason, verified_line 等信息
        """
        location = finding.get('location', '')
        if not location:
            return {'is_valid': False, 'reason': '位置信息为空'}

        # 解析位置：可能是 "文件名:行号" 或 "完整路径:行号" 格式
        file_name = ""
        line_num = 0

        if isinstance(location, str) and ':' in location:
            parts = location.rsplit(':', 1)
            if len(parts) == 2:
                file_name = parts[0]
                try:
                    line_num = int(parts[1])
                except ValueError:
                    return {'is_valid': False, 'reason': f'行号无效: {parts[1]}'}
        elif isinstance(location, dict):
            file_name = location.get('file', '')
            line_num = location.get('line', 0)

        # 确定要检查的文件路径
        check_file = file_name if file_name else file_path_context
        if check_file and not Path(check_file).is_absolute():
            # 如果是相对路径，尝试相对于原始文件目录
            if file_path_context:
                base_dir = str(Path(file_path_context).parent)
                check_file = str(Path(base_dir) / check_file)

        # 检查行号是否存在
        if line_num > 0 and check_file:
            if not self._line_exists_in_file(check_file, line_num):
                return {
                    'is_valid': False,
                    'reason': f'声称的位置 {check_file}:{line_num} 行不存在或文件无法读取',
                    'file': check_file,
                    'line': line_num
                }

            # 如果发现中有 code_snippet，验证关键词是否在代码中
            code_snippet = finding.get('code_snippet', '')
            if code_snippet:
                # 提取关键词（过滤掉常见的非代码词）
                keywords = [kw.strip() for kw in code_snippet.split() if len(kw) > 3]
                suspicious_keywords = ['EXAMPLE', 'SAMPLE', 'TEST', 'DEMO', 'FIXME', 'TODO', 'XXX']
                meaningful_keywords = [kw for kw in keywords if kw.upper() not in suspicious_keywords]
                if meaningful_keywords:
                    if not self._verify_code_pattern_in_file(check_file, line_num, meaningful_keywords[:5]):
                        return {
                            'is_valid': False,
                            'reason': f'声称的问题代码模式在指定位置附近未找到匹配',
                            'file': check_file,
                            'line': line_num
                        }

        return {
            'is_valid': True,
            'reason': '位置验证通过',
            'file': check_file,
            'line': line_num
        }

    def _generate_recommendation(self, risk_type: str, severity: str, description: str, evidence: str) -> str:
        """根据风险类型和严重程度生成具体修复建议

        Args:
            risk_type: 风险类型
            severity: 严重程度
            description: 风险描述
            evidence: 证据描述

        Returns:
            具体的修复建议
        """
        risk_upper = risk_type.upper()
        desc_upper = description.upper()
        combined = f"{risk_upper} {desc_upper}"

        high_keywords = ["SQL", "INJECT", "XSS", "CSRF", "COMMAND", "RCE", "PRIVILEGE",
                         "AUTHENTICATION", "CREDENTIAL", "SECRET", "KEY", "PASSWORD",
                         "UNSAFE", "DESERIALIZ", "SSRF", "PATH", "SENSITIVE",
                         "DATA EXPOSURE", "JWT", "TOKEN", "EXPOSURE", "REDIS",
                         "DENIAL", "DOS", "SERVICE", "ATTACK", "SCAN"]
        medium_keywords = ["WEAK", "DEFAULT", "MISSING", "HARDCODED", "CONFIGURATION",
                          "BROKEN", "INSECURE", "TRAVERSAL", "CONTEXT", "TENANT",
                          "CUSTOM SECURITY", "AUTHORIZATION", "PERMISSION", "越权"]
        low_keywords = ["INFO", "LOGGING", "DEBUG", "REMEDIATION", "BEST", "PRACTICE"]

        if any(kw in combined for kw in high_keywords):
            severity_advice = {
                "CRITICAL": "立即修复",
                "HIGH": "优先修复",
                "MEDIUM": "尽快修复",
                "LOW": "建议修复",
                "INFO": "可选择修复"
            }.get(severity.upper() if severity else "MEDIUM", "建议修复")

            if "SQL" in combined or "INJECT" in combined:
                return f"{severity_advice}：使用参数化查询或预编译语句，勿使用字符串拼接SQL"
            elif "XSS" in combined:
                return f"{severity_advice}：对用户输入进行HTML实体编码，设置严格CSP策略"
            elif "CSRF" in combined:
                return f"{severity_advice}：为所有状态修改请求添加CSRF Token验证，使用SameSite Cookie"
            elif "COMMAND" in combined or "RCE" in combined:
                return f"{severity_advice}：避免直接执行用户输入，使用安全的API或白名单验证"
            elif "AUTHENTICATION" in combined or "CREDENTIAL" in combined or "PASSWORD" in combined or "SECRET" in combined:
                return f"{severity_advice}：使用安全的方式存储凭据，实施强密码策略和密钥轮换"
            elif "PRIVILEGE" in combined or "ACCESS" in combined:
                return f"{severity_advice}：实施最小权限原则，使用基于角色的访问控制(RBAC)"
            elif "SSRF" in combined:
                return f"{severity_advice}：建立URL白名单验证，禁用对内部网络的访问"
            elif "PATH" in combined and "TRAVERSAL" in combined:
                return f"{severity_advice}：对用户输入进行路径规范化，使用白名单验证文件路径"
            elif "DESERIALIZ" in combined:
                return f"{severity_advice}：避免反序列化不受信任的数据，使用安全的序列化方案"
            elif "SENSITIVE" in combined or "DATA EXPOSURE" in combined or "EXPOSURE" in combined or "敏感" in description or "暴露" in description:
                return f"{severity_advice}：对敏感数据进行脱敏处理，最小化令牌中存储的信息，仅保留必要的用户标识"
            elif "JWT" in combined or "TOKEN" in combined or "令牌" in description:
                return f"{severity_advice}：确保令牌不包含敏感信息，使用令牌加密或签名保护完整性"
            elif "REDIS" in combined or "DENIAL" in combined or "DOS" in combined or "SERVICE" in combined or "ATTACK" in combined or "SCAN" in combined or "服务" in description or "拒绝" in description:
                return f"{severity_advice}：优化查询效率，对大键集合使用游标遍历而非一次性加载，限制资源消耗"
            elif "AUTHENTICATION" in combined or "CREDENTIAL" in combined or "PASSWORD" in combined or "SECRET" in combined:
                return f"{severity_advice}：使用安全的方式存储凭据，实施强密码策略和密钥轮换"
            elif "PRIVILEGE" in combined or "ACCESS" in combined or "AUTHORIZATION" in combined or "PERMISSION" in combined or "越权" in description or "授权" in description:
                return f"{severity_advice}：实施最小权限原则，使用基于角色的访问控制(RBAC)，验证用户操作权限"
            else:
                return f"{severity_advice}：基于代码证据评估后实施相应安全措施"

        elif any(kw in combined for kw in medium_keywords):
            severity_advice = {
                "CRITICAL": "立即修复",
                "HIGH": "优先修复",
                "MEDIUM": "尽快修复",
                "LOW": "建议修复",
                "INFO": "可选择修复"
            }.get(severity.upper() if severity else "LOW", "建议修复")

            if "WEAK" in combined or "DEFAULT" in combined:
                return f"{severity_advice}：替换弱加密算法或默认配置，使用行业标准安全方案"
            elif "MISSING" in combined or "缺失" in description:
                return f"{severity_advice}：添加缺失的安全控制或验证机制"
            elif "HARDCODED" in combined or "硬编码" in description:
                return f"{severity_advice}：将硬编码的配置移动到安全存储（如环境变量或密钥管理系统）"
            elif "CONFIGURATION" in combined or "CONFIG" in combined or "配置" in description:
                return f"{severity_advice}：修正安全配置，遵循安全最佳实践"
            elif "CONTEXT" in combined or "TENANT" in combined or "上下文" in description or "租户" in description:
                return f"{severity_advice}：确保上下文隔离正确实现，验证多线程/异步场景下的上下文传递"
            elif "CUSTOM SECURITY" in combined or "自定义" in description:
                return f"{severity_advice}：审查自定义安全逻辑，进行代码审计和渗透测试"
            elif "不足" in description or "不完整" in description or "INSECURE" in combined:
                return f"{severity_advice}：增强安全控制，确保配置完整和正确"
            else:
                return f"{severity_advice}：基于代码证据评估后实施相应安全措施"

        elif any(kw in combined for kw in low_keywords):
            return "参考最佳实践进行优化，或作为低优先级改进项"

        if description and len(description) > 10:
            return f"根据描述评估: {description[:50]}..."

        return "需要人工复核此风险"

    def _generate_detailed_description(self, vulnerability: str, finding: Dict[str, Any]) -> str:
        """根据漏洞类型生成详细的中文描述

        Args:
            vulnerability: 漏洞名称
            finding: 漏洞发现数据

        Returns:
            详细的中文描述
        """
        vuln_upper = vulnerability.upper()
        evidence_list = finding.get('evidence', [])
        evidence_text = ""
        if evidence_list and isinstance(evidence_list, list):
            evidence_text = " ".join([
                e.get('reason', e.get('description', '')) if isinstance(e, dict) else str(e)
                for e in evidence_list[:3]
            ])

        combined = f"{vuln_upper} {evidence_text.upper()}"

        if "SQL" in combined or "INJECT" in combined:
            return "SQL注入漏洞：攻击者可通过在用户输入中注入恶意SQL语句来操作数据库，可能导致敏感数据泄露、数据篡改或服务器沦陷。常见于使用字符串拼接构建SQL查询的场景。"
        elif "UNAUTHORIZED" in combined or "ACCESS" in combined or "未授权" in vulnerability or "越权" in vulnerability:
            return "未授权访问/越权漏洞：应用程序未对用户操作权限进行充分验证，导致低权限用户可执行高权限操作或访问他人资源。可能导致数据泄露、账户劫持或业务逻辑被恶意利用。"
        elif "XSS" in combined:
            return "跨站脚本(XSS)漏洞：攻击者可在页面中注入恶意JavaScript代码，窃取用户Cookie、会话令牌或劫持用户操作。常见于未对用户输入进行HTML编码就输出到页面的场景。"
        elif "CSRF" in combined:
            return "跨站请求伪造(CSRF)漏洞：攻击者诱骗已登录用户在不知情的情况下发起恶意请求，可导致账户设置被修改、密码被更改等敏感操作被执行。"
        elif "COMMAND" in combined or "RCE" in combined:
            return "命令注入/远程代码执行漏洞：应用程序将用户输入传递给系统命令执行函数，攻击者可通过构造恶意命令在服务器上执行任意代码，获取服务器完全控制权。"
        elif "CREDENTIAL" in combined or "PASSWORD" in combined or "SECRET" in combined or "KEY" in combined:
            return "凭据/密钥泄露风险：代码中包含硬编码的敏感凭据（如密码、API密钥、加密密钥），可能被源码泄露或通过代码审查被发现，造成严重安全风险。"
        elif "SENSITIVE" in combined or "DATA EXPOSURE" in combined or "暴露" in vulnerability or "泄露" in vulnerability:
            return "敏感数据泄露：应用程序在响应、日志或令牌中暴露了不应公开的敏感信息（如用户密码、身份证号、银行卡号等），违反数据保护合规要求。"
        elif "JWT" in combined or "TOKEN" in combined or "令牌" in vulnerability:
            return "令牌安全配置问题：令牌的生成、验证或存储存在安全缺陷，可能被伪造、窃取或重放，导致会话劫持或身份冒充。"
        elif "SSRF" in combined:
            return "服务端请求伪造(SSRF)漏洞：应用程序从用户指定URL获取资源时未进行充分验证，攻击者可利用此漏洞访问内网服务、读取本地文件或探测内网结构。"
        elif "PATH" in combined and ("TRAVERSAL" in combined or "Traversal" in combined):
            return "路径遍历漏洞：应用程序对用户提供的文件路径未进行充分验证，攻击者可通过构造 '../' 等特殊字符序列访问服务器上的敏感文件。"
        elif "DESERIALIZ" in combined:
            return "不安全的反序列化漏洞：应用程序反序列化来自不可信源的数据，攻击者可通过构造恶意序列化对象执行任意代码或进行拒绝服务攻击。"
        elif "WEAK" in combined or "ENCRYPT" in combined or "加密" in vulnerability:
            return "弱加密算法风险：使用了存在已知攻击方法或密钥长度不足的加密算法（如MD5、SHA1、DES等），攻击者可能破解敏感数据。"
        elif "CORS" in combined:
            return "CORS配置不当：跨域资源共享(CORS)策略配置过于宽松，允许任意来源的跨域请求，可能导致敏感API被恶意网站调用。"
        elif "UPLOAD" in combined or "上传" in vulnerability:
            return "文件上传漏洞：应用程序对用户上传文件的类型、内容和大小缺乏充分验证，攻击者可上传恶意文件（如WebShell）并执行任意代码。"
        elif "REDIS" in combined or "CACHE" in combined or "缓存" in vulnerability:
            return "缓存安全配置问题：缓存机制未进行适当的访问控制或数据隔离，不同用户/租户的数据可能发生混淆，导致信息泄露。"
        else:
            evidence = finding.get('evidence_chain_summary', '') or finding.get('reason', '')
            if evidence and len(evidence) > 20:
                return f"安全风险：{evidence[:100]}..."
            return f"发现{vulnerability}相关安全风险，建议根据详细代码上下文进行人工复核确认。"

    def _convert_to_findings(self, result: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """将分析结果转换为漏洞发现列表

        Args:
            result: 分析结果

        Returns:
            漏洞发现列表
        """
        findings = []
        file_path_context = str(result.get('file_path', 'unknown'))
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
                vulnerabilities = vuln_verif.get('vulnerabilities', [])
                risks = vuln_verif.get('risks', [])

                confirmed = [v for v in vulnerabilities if v.get('signal_state') == 'CONFIRMED']
                print(f"[DEBUG] Fallback: 从 vulnerability_verification 提取 CONFIRMED 漏洞: {len(confirmed)}")

                adversarial_val = result.get('adversarial_validation', {})
                adversarial_analysis = adversarial_val.get('adversarial_analysis', [])
                adversarial_findings = []

                for item in adversarial_analysis:
                    verdict = item.get('verdict', '')
                    if verdict in ['ACCEPT', 'ESCALATE']:
                        vuln_info = item.get('vulnerability', {})
                        raw_location = None
                        if isinstance(vuln_info, dict):
                            raw_location = vuln_info.get('location', None)
                            if not raw_location or raw_location in ('Unknown', '', None):
                                raw_location = self._extract_location_from_evidence(item, file_path_context)
                            else:
                                raw_location = f"{Path(file_path_context).name}:{raw_location}"
                            adversarial_findings.append({
                                'vulnerability': vuln_info.get('title', item.get('attack_chain_name', 'Unknown')),
                                'location': raw_location,
                                'severity': vuln_info.get('severity', 'MEDIUM'),
                                'status': 'VALID' if verdict == 'ACCEPT' else 'UNCERTAIN',
                                'confidence': vuln_info.get('confidence', 'MEDIUM'),
                                'cvss_score': vuln_info.get('cvss_score', ''),
                                'recommendation': self._generate_recommendation(
                                    vuln_info.get('title', item.get('attack_chain_name', 'Unknown')),
                                    vuln_info.get('severity', 'MEDIUM'),
                                    item.get('reason', ''),
                                    str(item.get('evidence', ''))
                                ),
                                'evidence': item.get('evidence', []),
                                'requires_human_review': item.get('requires_human_review', True)
                            })
                        else:
                            raw_location = self._extract_location_from_evidence(item, file_path_context)
                            adversarial_findings.append({
                                'vulnerability': item.get('attack_chain_name', 'Unknown'),
                                'location': raw_location,
                                'severity': 'MEDIUM',
                                'status': 'VALID' if verdict == 'ACCEPT' else 'UNCERTAIN',
                                'confidence': 'MEDIUM',
                                'cvss_score': '',
                                'recommendation': self._generate_recommendation(
                                    item.get('attack_chain_name', 'Unknown'),
                                    'MEDIUM',
                                    item.get('reason', ''),
                                    str(item.get('evidence', ''))
                                ),
                                'evidence': item.get('evidence', []),
                                'requires_human_review': item.get('requires_human_review', True)
                            })

                risk_enum = result.get('risk_enumeration', {})
                risk_findings = risk_enum.get('risks', [])

                print(f"[DEBUG] Fallback 检查:")
                print(f"  - vulnerability_verification.vulnerabilities (CONFIRMED): {len(confirmed)}")
                print(f"  - adversarial_validation.ACCEPT/ESCALATE: {len(adversarial_findings)}")
                print(f"  - risk_enumeration.risks: {len(risk_findings)}")

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
                        raw_location = risk.get('location', None)
                        if not raw_location or raw_location in ('Unknown', '', None):
                            raw_location = self._extract_location_from_evidence(risk, file_path_context)

                        location_valid = False
                        if raw_location:
                            if ':' in raw_location:
                                loc_parts = raw_location.rsplit(':', 1)
                                if len(loc_parts) == 2:
                                    path_part, line_part = loc_parts
                                    try:
                                        line_num = int(line_part)
                                        if self._line_exists_in_file(path_part, line_num):
                                            location_valid = True
                                            validated_location = raw_location
                                        else:
                                            print(f"[WARN] Fallback: 跳过无效 location {raw_location}")
                                    except ValueError:
                                        pass
                            else:
                                try:
                                    line_num = int(raw_location)
                                    if self._line_exists_in_file(file_path_context, line_num):
                                        location_valid = True
                                        validated_location = f"{file_path_context}:{line_num}"
                                except ValueError:
                                    pass

                        if location_valid:
                            risk_vuln = {
                                'vulnerability': risk.get('risk_type', 'Unknown'),
                                'location': validated_location,
                                'severity': risk.get('severity', 'INFO'),
                                'status': 'UNCERTAIN',
                                'confidence': 'LOW',
                                'cvss_score': '',
                                'recommendation': self._generate_recommendation(
                                    risk.get('risk_type', 'Unknown'),
                                    risk.get('severity', 'INFO'),
                                    risk.get('description', ''),
                                    str(risk.get('evidence', ''))
                                ),
                                'evidence': risk.get('evidence', []),
                                'requires_human_review': True
                            }
                            final_findings.append(risk_vuln)
                        else:
                            print(f"[WARN] Fallback: 跳过无法验证的 risk: {risk.get('risk_type', 'Unknown')}")

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
                    evidence = finding.get('evidence', [])

                    # 优先从 evidence 提取真实的源代码位置（AI 可能输出路由级位置）
                    if evidence and isinstance(evidence, list) and len(evidence) > 0:
                        for e in evidence:
                            if isinstance(e, dict) and e.get('location'):
                                loc = e.get('location')
                                if loc and loc != 'N/A' and ':' in str(loc) and not str(loc).startswith('/'):
                                    location = str(loc)
                                    break
                    else:
                        # 如果 evidence 中没有有效位置，使用 AI 提供的位置
                        if not location or location in ('Unknown', 'unknown', '', None):
                            location = self._extract_location_from_evidence(finding, file_path_context)

                    # 生成规则名称 - 只包含漏洞名称
                    rule_name = vulnerability_desc
                    if status == 'INVALID' and total_vulnerabilities < 10:
                        rule_name = f"[需人工复核] {vulnerability_desc}"

                    # 生成详细的描述
                    raw_description = finding.get('description') or finding.get('reason') or ''
                    if raw_description == vulnerability_desc or not raw_description:
                        description = self._generate_detailed_description(vulnerability_desc, finding)
                    else:
                        description = raw_description

                    # 清理模拟数据路径
                    if location and location.startswith('/path/to/'):
                        location = self._extract_location_from_evidence(finding, file_path_context) or location

                    # 处理 Severity 枚举对象转换为字符串
                    severity_obj = finding.get('severity')
                    if hasattr(severity_obj, 'value'):
                        severity = str(severity_obj.value)
                    elif hasattr(severity_obj, 'name'):
                        severity = str(severity_obj.name)
                    elif isinstance(severity_obj, str):
                        severity = severity_obj
                    else:
                        severity = 'medium'

                    # 如果 severity 格式是 "severity.HIGH" 则提取后面的部分
                    if severity.startswith('severity.'):
                        severity = severity.split('.')[-1]

                    if status == 'INVALID':
                        severity = 'info'  # INVALID状态设为info级别

                    # 处理置信度，避免空字符串转换错误
                    confidence_value = finding.get('confidence', 50)
                    try:
                        confidence = float(confidence_value) / 100.0
                    except (ValueError, TypeError):
                        confidence = 0.5

                    # 验证漏洞位置和代码是否真实存在（防止AI编造）
                    validation_result = self._validate_finding_location(finding, file_path_context)
                    if not validation_result['is_valid']:
                        print(f"[WARN] 漏洞验证失败: {vulnerability_desc} - {validation_result['reason']}")
                        self.debug_logs.append(f"[WARN] 漏洞验证失败: {vulnerability_desc} - {validation_result['reason']}")
                        status = 'INVALID'
                        rule_name = f"[待人工复核] {vulnerability_desc}"
                        description = f"[自动验证未通过] {validation_result['reason']}。原始描述：{description[:100]}..." if description else f"[自动验证未通过] {validation_result['reason']}"

                    # 提取行号
                    line_num = 0
                    if isinstance(location, str) and ':' in location:
                        parts = location.rsplit(':', 1)
                        if len(parts) == 2 and parts[1].isdigit():
                            line_num = int(parts[1])

                    # 提取代码片段
                    code_snippet = self._extract_code_at_line(
                        file_path_context,
                        line_num if line_num > 0 else 1,
                        context_lines=3
                    )

                    # 提取evidence数据
                    evidence = finding.get('evidence', [])
                    metadata = {
                        'evidence': evidence,
                        'requires_human_review': finding.get('requires_human_review', False)
                    }

                    vulnerability = VulnerabilityFinding(
                        rule_id=finding.get('vulnerability', 'unknown'),
                        rule_name=rule_name,
                        severity=severity,
                        confidence=confidence,
                        location={'file': location.rsplit(':', 1)[0] if isinstance(location, str) and ':' in location else location, 'line': line_num},
                        description=description,
                        fix_suggestion=recommendation,
                        explanation=json.dumps(finding, ensure_ascii=False),
                        code_snippet=code_snippet,
                        metadata=metadata
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
