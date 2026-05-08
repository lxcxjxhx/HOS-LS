"""纯AI分析器模块

实现纯AI深度语义解析功能，默认使用 deepseek-v4-pro。
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
from src.ai.pure_ai.schema_validator import LineNumberValidator
from src.nvd.nvd_query_adapter import NVDQueryAdapter

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
        self.ai_provider = config.ai.get_provider("pure_ai")
        self.ai_model = config.ai.get_model("pure_ai")
        self.model_manager = None
        self.client = None
        self.pipeline = None
        self.cache_manager = CacheManager()
        self.initialized = False
        self.debug_logs: List[str] = []
        self.nvd_adapter = NVDQueryAdapter()
    
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
                console.print(f"[yellow]WARNING: API 密钥未设置，纯AI分析器可能无法正常工作[/yellow]")
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
                        console.print(f"[green][OK] API访问验证成功[/green]")
                    else:
                        console.print(f"[red][X] API访问验证失败: {error_msg}[/red]")
                        console.print(f"[yellow][!] 纯AI分析器将以降级模式运行[/yellow]")
                except Exception as e:
                    console.print(f"[yellow][!] API访问验证异常: {e}[/yellow]")

                # 创建pipeline配置，包含模型信息
                pipeline_config = {
                    'max_retries': 3,
                    'model': self.ai_model
                }
                self.pipeline = MultiAgentPipeline(self.client, pipeline_config)
                self.initialized = True  # 标记初始化成功
                console.print(f"[green][OK] 纯AI分析器初始化成功[/green] (提供商: {self.ai_provider}, 模型: {self.ai_model})")
            else:
                console.print(f"[red][X] 纯AI分析器初始化失败：无法获取AI客户端[/red]")
                console.print(f"[dim]请检查API密钥配置和网络连接[/dim]")
        except Exception as e:
            console.print(f"[red][X] 纯AI分析器初始化失败: {e}[/red]")
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

        # 执行多Agent分析（使用优化版流水线，Agent 3-5 并行执行）
        result = await self.pipeline.run_pipeline_optimized(file_path, enable_parallel=True)
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

    def _calculate_evidence_confidence(self, evidence: Any) -> float:
        """计算证据列表的平均置信度

        Args:
            evidence: 证据列表

        Returns:
            平均置信度（0.0-1.0），如果无法计算则返回0.0
        """
        if not evidence:
            return 0.0

        if isinstance(evidence, list):
            confidences = []
            for e in evidence:
                if isinstance(e, dict) and 'confidence' in e:
                    conf = e['confidence']
                    if isinstance(conf, (int, float)):
                        confidences.append(float(conf))
                    elif isinstance(conf, str):
                        try:
                            if '%' in conf:
                                confidences.append(float(conf.replace('%', '')) / 100.0)
                            else:
                                confidences.append(float(conf))
                        except:
                            pass
            if confidences:
                return sum(confidences) / len(confidences)

        elif isinstance(evidence, dict) and 'confidence' in evidence:
            conf = evidence['confidence']
            if isinstance(conf, (int, float)):
                return float(conf)
            elif isinstance(conf, str):
                try:
                    if '%' in conf:
                        return float(conf.replace('%', '')) / 100.0
                    return float(conf)
                except:
                    pass

        return 0.0

    def normalize_severity(self, severity: str) -> str:
        """确保严重等级合法

        Args:
            severity: 原始严重等级

        Returns:
            合法的严重等级（CRITICAL/HIGH/MEDIUM/LOW/INFO）
        """
        if not severity:
            return 'MEDIUM'

        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        normalized = severity.upper().strip()

        if normalized in valid_severities:
            return normalized

        if 'critical' in normalized or '严重' in severity:
            return 'CRITICAL'
        elif 'high' in normalized or '高' in severity:
            return 'HIGH'
        elif 'medium' in normalized or '中' in severity:
            return 'MEDIUM'
        elif 'low' in normalized or '低' in severity:
            return 'LOW'
        elif 'info' in normalized or '信息' in severity:
            return 'INFO'

        print(f"[DEBUG] [normalize_severity] 未知严重等级 '{severity}'，使用默认 '中'")
        return 'MEDIUM'

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
                        if ':' in str(loc) and str(loc).count(':') >= 2:
                            return str(loc)
                        if ':' in str(loc):
                            parts = str(loc).rsplit(':', 1)
                            if len(parts) == 2 and parts[0].endswith(('.java', '.py', '.js', '.ts', '.go', '.rb')):
                                return str(loc)
                        return f"{Path(file_path_context).name}:{loc}"
        elif isinstance(evidence, dict):
            loc = evidence.get('location', '')
            if loc and loc not in ('N/A', 'Unknown', '', None):
                if ':' in str(loc) and str(loc).count(':') >= 2:
                    return str(loc)
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
            line_num: 行号（1-based）
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
                start = max(0, line_num - context_lines)
                end = min(len(lines), line_num + context_lines + 1)
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
                potential_drive = parts[0]
                potential_line = parts[1]
                if len(potential_drive) == 1 and potential_drive.isalpha():
                    file_name = potential_drive + ':' + potential_line.rsplit(':', 1)[0] if ':' in potential_line else location
                    try:
                        line_num = int(potential_line.rsplit(':', 1)[-1])
                    except ValueError:
                        line_num = 0
                else:
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

            if "HARDCODED" in combined or "硬编码" in combined:
                if "CREDENTIAL" in combined or "PASSWORD" in combined or "SECRET" in combined or "KEY" in combined:
                    return f"{severity_advice}：将硬编码的凭据移动到安全存储（如环境变量或密钥管理系统），实施凭据轮换策略"
                elif "PATH" in combined or "路径" in combined:
                    return f"{severity_advice}：将硬编码的路径改为从配置文件或环境变量读取，提高可移植性"
                else:
                    return f"{severity_advice}：将硬编码的配置移动到安全存储（如环境变量或配置文件）"
            elif "SQL" in combined or "INJECT" in combined:
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

    def _normalize_vulnerability_name(self, vulnerability: str) -> str:
        """将英文漏洞名称翻译为中文

        Args:
            vulnerability: 原始漏洞名称（可能是英文或中文）

        Returns:
            中文漏洞名称
        """
        if not vulnerability:
            return "未知漏洞"

        vuln_upper = vulnerability.upper()
        vuln_lower = vulnerability.lower()

        mapping = {
            "SQL INJECTION": "SQL注入",
            "SQL_INJECTION": "SQL注入",
            "SQLINJECTION": "SQL注入",
            "SQL": "SQL注入",

            "XSS": "跨站脚本攻击",
            "CROSS-SITE SCRIPTING": "跨站脚本攻击",
            "CROSS SITE SCRIPTING": "跨站脚本攻击",

            "CSRF": "跨站请求伪造",
            "CROSS-SITE REQUEST FORGERY": "跨站请求伪造",
            "CROSS SITE REQUEST FORGERY": "跨站请求伪造",

            "SSRF": "服务器端请求伪造",
            "SERVER-SIDE REQUEST FORGERY": "服务器端请求伪造",

            "PATH TRAVERSAL": "路径遍历",
            "PATH_TRAVERSAL": "路径遍历",
            "DIRECTORY TRAVERSAL": "目录遍历",

            "COMMAND INJECTION": "命令注入",
            "COMMAND_INJECTION": "命令注入",
            "RCE": "远程代码执行",
            "REMOTE CODE EXECUTION": "远程代码执行",

            "XXE": "XML外部实体注入",

            "LFI": "本地文件包含",
            "LOCAL FILE INCLUSION": "本地文件包含",

            "RFI": "远程文件包含",
            "REMOTE FILE INCLUSION": "远程文件包含",

            "IDOR": "越权访问",
            "INSECURE DIRECT OBJECT REFERENCE": "越权访问",

            "SSTI": "服务器端模板注入",
            "SERVER SIDE TEMPLATE INJECTION": "服务器端模板注入",

            "SENSITIVE DATA EXPOSURE": "敏感数据泄露",
            "DATA EXPOSURE": "敏感数据泄露",
            "INFORMATION DISCLOSURE": "信息泄露",

            "WEAK CRYPTOGRAPHY": "弱加密算法",
            "WEAK ENCRYPTION": "弱加密算法",
            "INSECURE ENCRYPTION": "不安全加密",

            "HARDCODED CREDENTIAL": "硬编码凭据",
            "HARDCODED PASSWORD": "硬编码密码",
            "HARDCODED SECRET": "硬编码密钥",
            "HARDCODED API KEY": "硬编码API密钥",

            "JWT VULNERABILITY": "JWT安全漏洞",
            "JWT": "令牌安全漏洞",
            "TOKEN": "令牌安全漏洞",
            "BEARER TOKEN": "令牌安全漏洞",

            "CORS MISCONFIGURATION": "CORS配置不当",
            "CORS": "跨域资源共享配置不当",

            "DESERIALIZATION": "反序列化漏洞",
            "INSECURE DESERIALIZATION": "不安全反序列化",

            "OPEN REDIRECT": "开放重定向",
            "UNVALIDATED REDIRECT": "未验证重定向",

            "BUFFER OVERFLOW": "缓冲区溢出",

            "PRINTF FORMAT STRING": "格式化字符串漏洞",

            "PATH DEPENDENCY": "路径依赖风险",
            "HARDCODED PATH": "硬编码路径",

            "CREDENTIAL": "凭据安全风险",
            "PASSWORD": "密码安全风险",
            "SECRET": "密钥安全风险",
            "APIKEY": "API密钥安全风险",

            "FRAME OPTIONS": "X-Frame-Options配置问题",
            "X-FRAME-OPTIONS": "X-Frame-Options配置问题",

            "CSRF PROTECTION": "CSRF保护缺失",
            "CSRF PROTECTION DISABLED": "CSRF保护被禁用",

            "AUTHORIZATION": "授权问题",
            "UNAUTHORIZED": "未授权访问",
            "AUTHORIZATION BYPASS": "授权绕过",

            "AUTHENTICATION": "认证问题",
            "WEAK AUTHENTICATION": "弱认证",

            "SESSION": "会话管理问题",
            "SESSION FIXATION": "会话固定",

            "REMOTE TOKEN SERVICE": "远程令牌服务风险",
            "REMOTETOKENSERVICES": "远程令牌服务风险",

            "SWAGGER": "Swagger文档暴露",
            "API DOCUMENTATION": "API文档暴露",

            "DEBUG MODE": "调试模式启用",
            "DEBUG": "调试信息泄露",

            "ERROR HANDLING": "错误处理问题",
            "STACK TRACE": "堆栈跟踪泄露",

            "XML INJECTION": "XML注入",
            "JSON INJECTION": "JSON注入",

            "CLICKJACKING": "点击劫持",

            "MIME SNIFFING": "MIME类型嗅探",

            "DOM XSS": "DOM型跨站脚本",

            "STORAGE": "存储安全风险",
            "LOCAL STORAGE": "本地存储风险",
            "SESSION STORAGE": "会话存储风险",

            "BEST PRACTICE": "最佳实践违规",
            "CODE SMELL": "代码规范问题",

            "CONFIGURATION": "配置问题",
            "MISCONFIGURATION": "配置错误",
            "INSECURE CONFIGURATION": "不安全配置",

            "SUSPICIOUS PATTERN": "可疑模式",
            "SUSPICIOUS_PATTERN": "可疑模式",
            "SUSPICIOUS": "可疑模式",
            "PATTERN": "模式",

            "WEAK SECURITY SIGNAL": "弱安全信号",
            "WEAK_SECURITY_SIGNAL": "弱安全信号",
            "WEAK_SIGNAL": "弱安全信号",

            "SECURITY MISCONFIGURATION": "安全配置错误",
            "INSECURE SETTING": "不安全设置",
            "INSECURE CONFIG": "不安全配置",
            "SECURITY CONFIG": "安全配置",

            "HARDCODED": "硬编码",
            "HARDCODED VALUE": "硬编码值",
            "HARDCODED CONFIG": "硬编码配置",
        }

        if vuln_upper in mapping:
            return mapping[vuln_upper]

        keyword_mappings = [
            (["SQL", "INJECT"], "SQL注入"),
            (["INJECTION"], "注入漏洞"),
            (["XSS", "CROSS SITE", "CROSS-SITE"], "跨站脚本攻击"),
            (["CSRF", "CROSS SITE REQUEST", "CROSS-SITE REQUEST"], "跨站请求伪造"),
            (["SSRF", "SERVER SIDE REQUEST"], "服务器端请求伪造"),
            (["PATH", "TRAVERSAL"], "路径遍历"),
            (["COMMAND", "INJECT", "EXEC"], "命令注入/远程代码执行"),
            (["RCE", "REMOTE CODE"], "远程代码执行"),
            (["XXE", "XML EXTERNAL"], "XML外部实体注入"),
            (["LFI", "LOCAL FILE"], "本地文件包含"),
            (["RFI", "REMOTE FILE"], "远程文件包含"),
            (["IDOR", "DIRECT OBJECT"], "越权访问"),
            (["SSTI", "TEMPLATE INJECTION"], "服务器端模板注入"),
            (["SENSITIVE", "DATA", "EXPOSURE"], "敏感数据泄露"),
            (["WEAK", "CRYPTO", "ENCRYPT"], "弱加密算法"),
            (["HARDCODED", "CREDENTIAL", "PASSWORD", "SECRET", "API"], "硬编码凭据"),
            (["JWT", "TOKEN", "BEARER"], "令牌安全漏洞"),
            (["CORS", "CROSS ORIGIN"], "跨域资源配置不当"),
            (["DESERIALIZ"], "反序列化漏洞"),
            (["OPEN REDIRECT", "UNVALIDATED REDIRECT"], "开放重定向"),
            (["BUFFER OVERFLOW"], "缓冲区溢出"),
            (["FORMAT STRING"], "格式化字符串漏洞"),
            (["PATH DEPENDENCY", "HARDCODED PATH"], "硬编码路径风险"),
            (["FRAME OPTIONS", "X-FRAME"], "X-Frame-Options配置问题"),
            (["CSRF PROTECTION DISABLED", "CSRF DISABLED"], "CSRF保护被禁用"),
            (["UNAUTHORIZED", "AUTHZ BYPASS"], "未授权访问"),
            (["AUTHENTICATION"], "认证问题"),
            (["SESSION FIXATION"], "会话固定攻击"),
            (["REMOTE TOKEN", "REMOTETOKEN"], "远程令牌服务风险"),
            (["SWAGGER", "API DOC"], "API文档暴露"),
            (["DEBUG MODE", "DEBUG"], "调试模式启用"),
            (["ERROR HANDLING", "STACK TRACE"], "错误处理问题"),
            (["XML INJECTION"], "XML注入"),
            (["JSON INJECTION"], "JSON注入"),
            (["CLICKJACKING"], "点击劫持"),
            (["MIME SNIFF"], "MIME类型嗅探"),
            (["DOM XSS"], "DOM型跨站脚本"),
            (["LOCAL STORAGE", "SESSION STORAGE"], "本地存储风险"),
            (["BEST PRACTICE", "CODE SMELL"], "代码规范问题"),
            (["CONFIGURATION", "MISCONFIGURATION"], "配置问题"),
            (["REFINED", "REJECTED", "UNCERTAIN"], "待确认风险"),
            (["RISK", "SIGNAL"], "风险信号"),
            (["SUSPICIOUS", "PATTERN"], "可疑模式"),
            (["WEAK", "SECURITY", "SIGNAL"], "弱安全信号"),
            (["SECURITY", "MISCONFIGURATION"], "安全配置错误"),
            (["HARDCODED", "VALUE"], "硬编码值"),
            (["HARDCODED", "CONFIG"], "硬编码配置"),
            (["INSECURE", "SETTING"], "不安全设置"),
            (["INSECURE", "CONFIG"], "不安全配置"),
        ]

        for keywords, chinese in keyword_mappings:
            if all(kw in vuln_upper or kw.lower() in vuln_lower for kw in keywords if len(kw) > 3):
                return chinese

        # 处理蛇形命名（snake_case）：拆分为单词并逐个翻译
        if '_' in vulnerability and not self._contains_chinese(vulnerability):
            snake_case_translation = self._translate_snake_case_name(vulnerability)
            if snake_case_translation and snake_case_translation != vulnerability:
                return snake_case_translation

        if any(term in vuln_upper for term in ["VULNERABILITY", "VULN", "ISSUE", "PROBLEM", "RISK", "WEAK", "INSECURE", "MISSING", "WITHOUT"]):
            if vulnerability.endswith("相关安全风险"):
                return vulnerability
            if any(term in vuln_upper for term in ["UNVERIFIED", "UNKNOWN", "GENERIC", "PLACEHOLDER"]):
                return vulnerability
            return f"{vulnerability}相关安全风险"

        return vulnerability

    def _contains_chinese(self, text: str) -> bool:
        """检查文本是否包含中文字符"""
        for char in text:
            if '\u4e00' <= char <= '\u9fff':
                return True
        return False

    def _translate_snake_case_name(self, snake_name: str) -> str:
        """将蛇形命名（snake_case）翻译为中文

        Args:
            snake_name: 蛇形命名（如 csrf_disabled）

        Returns:
            中文翻译（如 CSRF保护被禁用）
        """
        words = snake_name.split('_')
        if len(words) < 2:
            return snake_name

        # 蛇形命名关键词映射
        word_mapping = {
            "csrf": "CSRF",
            "xss": "XSS",
            "sql": "SQL",
            "rce": "远程代码执行",
            "ssrf": "SSRF",
            "xxe": "XXE",
            "cors": "CORS",
            "jwt": "JWT",
            "token": "令牌",
            "disabled": "被禁用",
            "disable": "禁用",
            "enabled": "被启用",
            "enable": "启用",
            "bypass": "绕过",
            "leakage": "泄露",
            "leak": "泄露",
            "exposure": "暴露",
            "hardcoded": "硬编码",
            "hard": "硬编码",
            "encoded": "编码",
            "missing": "缺失",
            "weak": "弱",
            "insecure": "不安全",
            "unauthorized": "未授权",
            "permit": "允许",
            "all": "所有",
            "url": "URL",
            "path": "路径",
            "exception": "异常",
            "unhandled": "未处理",
            "transport": "传输",
            "clickjack": "点击劫持",
            "frame": "框架",
            "options": "选项",
            "config": "配置",
            "configuration": "配置",
            "auth": "认证",
            "password": "密码",
            "credential": "凭据",
            "secret": "密钥",
            "api": "API",
            "key": "密钥",
            "data": "数据",
            "sensitive": "敏感",
            "information": "信息",
            "disclosure": "泄露",
            "injection": "注入",
            "upload": "上传",
            "file": "文件",
            "command": "命令",
            "redirect": "重定向",
            "open": "开放",
            "deserialization": "反序列化",
            "serialization": "序列化",
            "debug": "调试",
            "mode": "模式",
            "error": "错误",
            "handling": "处理",
            "stack": "堆栈",
            "trace": "跟踪",
            "session": "会话",
            "storage": "存储",
            "local": "本地",
            "best": "最佳",
            "practice": "实践",
            "code": "代码",
            "smell": "规范问题",
            "pattern": "模式",
            "suspicious": "可疑",
            "security": "安全",
            "misconfiguration": "配置错误",
            "setting": "设置",
            "swagger": "Swagger文档",
            "value": "值",
            "object": "对象",
            "user": "用户",
            "complete": "完整",
            "full": "完整",
            "refresh": "刷新",
            "scope": "作用域",
            "protection": "保护",
            "cache": "缓存",
            "log": "日志",
            "print": "打印",
            "output": "输出",
            "input": "输入",
            "validation": "验证",
            "sanitize": "清洗",
            "encoding": "编码",
            "escaping": "转义",
        }

        # 特殊组合映射
        special_combinations = {
            "csrf_disabled": "CSRF保护被禁用",
            "csrf_protection_disabled": "CSRF保护被禁用",
            "permit_all_url_bypass": "允许所有URL绕过安全检查",
            "token_transport_leakage": "令牌传输过程中泄露",
            "unhandled_exception": "未处理的异常",
            "x_frame_options_missing": "X-Frame-Options响应头缺失",
            "clickjacking_risk": "点击劫持风险",
            "hardcoded_credential": "硬编码凭据",
            "hardcoded_password": "硬编码密码",
            "hardcoded_secret": "硬编码密钥",
            "hardcoded_api_key": "硬编码API密钥",
            "sensitive_data_exposure": "敏感数据泄露",
            "information_disclosure": "信息泄露",
            "weak_encryption": "弱加密算法",
            "insecure_configuration": "不安全配置",
            "debug_mode_enabled": "调试模式被启用",
            "error_handling_issue": "错误处理问题",
            "stack_trace_disclosure": "堆栈跟踪泄露",
            "cors_misconfiguration": "CORS配置错误",
            "missing_authentication": "缺少认证",
            "missing_authorization": "缺少授权",
            "session_fixation": "会话固定攻击",
            "open_redirect": "开放重定向",
            "sql_injection": "SQL注入",
            "command_injection": "命令注入",
            "path_traversal": "路径遍历",
            "file_upload_vulnerability": "文件上传漏洞",
            "deserialization_vulnerability": "反序列化漏洞",
            "xxe_vulnerability": "XXE漏洞",
            "ssrf_vulnerability": "SSRF漏洞",
            "xss_reflected": "反射型XSS",
            "xss_stored": "存储型XSS",
            "xss_dom": "DOM型XSS",
            "swagger_exposure": "Swagger文档暴露",
            "api_doc_exposure": "API文档暴露",
            "refresh_scope_risk": "RefreshScope风险",
            "configuration_binding_risk": "配置绑定风险",
        }

        # 先检查特殊组合映射
        full_snake = snake_name.lower()
        if full_snake in special_combinations:
            return special_combinations[full_snake]

        # 逐个单词翻译并组合
        translated_parts = []
        for word in words:
            word_lower = word.lower()
            if word_lower in word_mapping:
                translated_parts.append(word_mapping[word_lower])
            else:
                # 保留原始单词
                translated_parts.append(word)

        # 如果有任何部分未翻译，返回原始名称
        if any(p.isalpha() for p in translated_parts if isinstance(p, str)):
            # 仍有英文单词未翻译
            return snake_name

        return "".join(translated_parts)

    async def _translate_vulnerability_name_ai_async(self, vulnerability: str) -> str:
        """使用真正的AI进行漏洞名称翻译（异步版本）

        通过AI模型将英文漏洞名称翻译为中文，结合NVD CVE数据库上下文。

        Args:
            vulnerability: 原始漏洞名称（英文）

        Returns:
            中文漏洞名称
        """
        if not vulnerability:
            return "未知漏洞"

        nvd_context = ""
        if self.nvd_adapter and self.nvd_adapter.is_available():
            try:
                keywords = [vulnerability]
                cwe_results = self.nvd_adapter.match_cwe(keywords, limit=1)
                if cwe_results and len(cwe_results) > 0:
                    cwe_info = cwe_results[0]
                    nvd_context = cwe_info.get('cwe_description', '')
            except Exception:
                pass

        prompt = f"""你是一个安全漏洞专家。请将以下漏洞名称翻译为中文。

漏洞名称: {vulnerability}
{f'相关NVD描述: {nvd_context}' if nvd_context else ''}

要求:
1. 只输出中文翻译，不要解释，不要添加任何额外内容
2. 使用安全领域的标准术语
3. 如果无法翻译或无法确定，返回原名称
4. 翻译要准确、简洁、专业

中文翻译:"""

        try:
            if not self.client:
                return self._normalize_vulnerability_name(vulnerability)

            from src.ai.models import AIRequest
            ai_request = AIRequest(
                prompt=prompt,
                model=self.ai_model,
                temperature=0.1,
                max_tokens=100
            )
            response = await self.client.generate(ai_request)
            translation = response.content.strip()
            if translation and translation != vulnerability:
                return translation
            return self._normalize_vulnerability_name(vulnerability)
        except Exception as e:
            print(f"[DEBUG] AI翻译失败，使用fallback: {e}")
            return self._normalize_vulnerability_name(vulnerability)

    def _translate_vulnerability_name_ai(self, vulnerability: str) -> str:
        """使用真正的AI进行漏洞名称翻译（同步包装器）

        Args:
            vulnerability: 原始漏洞名称（英文）

        Returns:
            中文漏洞名称
        """
        if not vulnerability:
            return "未知漏洞"

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                try:
                    future = asyncio.ensure_future(self._translate_vulnerability_name_ai_async(vulnerability))
                    return loop.run_until_complete(asyncio.shield(future))
                except RuntimeError:
                    pass
            else:
                try:
                    return loop.run_until_complete(self._translate_vulnerability_name_ai_async(vulnerability))
                except RuntimeError:
                    pass
        except Exception:
            pass

        return self._normalize_vulnerability_name(vulnerability)

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

        if "SQL" in vuln_upper or "INJECT" in vuln_upper:
            return "SQL注入漏洞：攻击者可通过在用户输入中注入恶意SQL语句来操作数据库，可能导致敏感数据泄露、数据篡改或服务器沦陷。常见于使用字符串拼接构建SQL查询的场景。"
        elif "UNAUTHORIZED" in vuln_upper or "ACCESS" in vuln_upper or "未授权" in vulnerability or "越权" in vulnerability:
            return "未授权访问/越权漏洞：应用程序未对用户操作权限进行充分验证，导致低权限用户可执行高权限操作或访问他人资源。可能导致数据泄露、账户劫持或业务逻辑被恶意利用。"
        elif "XSS" in vuln_upper or "跨站脚本" in vulnerability:
            return "跨站脚本(XSS)漏洞：攻击者可在页面中注入恶意JavaScript代码，窃取用户Cookie、会话令牌或劫持用户操作。常见于未对用户输入进行HTML编码就输出到页面的场景。"
        elif "CSRF" in vuln_upper or "跨站请求伪造" in vulnerability:
            return "跨站请求伪造(CSRF)漏洞：攻击者诱骗已登录用户在不知情的情况下发起恶意请求，可导致账户设置被修改、密码被更改等敏感操作被执行。"
        elif "PATH" in vuln_upper and ("TRAVERSAL" in vuln_upper or "遍历" in vulnerability or "路径" in vulnerability):
            return "路径遍历漏洞：应用程序对用户提供的文件路径未进行充分验证，攻击者可通过构造 '../' 等特殊字符序列访问服务器上的敏感文件。"
        elif "COMMAND" in vuln_upper or "RCE" in vuln_upper or "命令注入" in vulnerability:
            return "命令注入/远程代码执行漏洞：应用程序将用户输入传递给系统命令执行函数，攻击者可通过构造恶意命令在服务器上执行任意代码，获取服务器完全控制权。"
        elif "CREDENTIAL" in vuln_upper or "PASSWORD" in vuln_upper or "SECRET" in vuln_upper or "KEY" in vuln_upper or "凭据" in vulnerability or "密码" in vulnerability:
            return "硬编码凭据风险：代码中包含硬编码的敏感凭据（如密码、API密钥、加密密钥），可能被源码泄露或通过代码审查被发现，造成严重安全风险。建议使用环境变量或密钥管理系统存储敏感信息。"
        elif "SENSITIVE" in vuln_upper or "DATA EXPOSURE" in vuln_upper or "暴露" in vulnerability or "泄露" in vulnerability:
            return "敏感数据泄露：应用程序在响应、日志或令牌中暴露了不应公开的敏感信息（如用户密码、身份证号、银行卡号等），违反数据保护合规要求。"
        elif "JWT" in vuln_upper or "TOKEN" in vuln_upper or "令牌" in vulnerability:
            return "令牌安全配置问题：令牌的生成、验证或存储存在安全缺陷，可能被伪造、窃取或重放，导致会话劫持或身份冒充。"
        elif "SSRF" in vuln_upper or "服务端请求伪造" in vulnerability:
            return "服务端请求伪造(SSRF)漏洞：应用程序从用户指定URL获取资源时未进行充分验证，攻击者可利用此漏洞访问内网服务、读取本地文件或探测内网结构。"
        elif "DESERIALIZ" in vuln_upper or "反序列化" in vulnerability:
            return "不安全的反序列化漏洞：应用程序反序列化来自不可信源的数据，攻击者可通过构造恶意序列化对象执行任意代码或进行拒绝服务攻击。"
        elif "WEAK" in vuln_upper or "ENCRYPT" in vuln_upper or "加密" in vulnerability or "CRYPTO" in vuln_upper:
            return "弱加密算法风险：使用了存在已知攻击方法或密钥长度不足的加密算法（如MD5、SHA1、DES等），攻击者可能破解敏感数据。"
        elif "CORS" in vuln_upper or "跨域" in vulnerability:
            return "CORS配置不当：跨域资源共享(CORS)策略配置过于宽松，允许任意来源的跨域请求，可能导致敏感API被恶意网站调用。"
        elif "UPLOAD" in vuln_upper or "上传" in vulnerability:
            return "文件上传漏洞：应用程序对用户上传文件的类型、内容和大小缺乏充分验证，攻击者可上传恶意文件（如WebShell）并执行任意代码。"
        elif "REDIS" in vuln_upper or "CACHE" in vuln_upper or "缓存" in vulnerability:
            return "缓存安全配置问题：缓存机制未进行适当的访问控制或数据隔离，不同用户/租户的数据可能发生混淆，导致信息泄露。"
        elif "HARDCODED" in vuln_upper or "硬编码" in vulnerability or "RESOURCE" in vuln_upper or "路径" in vulnerability or "配置" in vulnerability:
            if "PATH" in vuln_upper or "路径" in vulnerability:
                return "硬编码路径风险：代码中包含硬编码的文件路径或资源路径，可能导致在不同环境或部署配置下出现路径错误，降低系统的可移植性和配置灵活性。"
            elif "CREDENTIAL" in vuln_upper or "PASSWORD" in vuln_upper or "SECRET" in vuln_upper or "KEY" in vuln_upper:
                return "硬编码凭据风险：代码中包含硬编码的敏感凭据（如密码、API密钥、加密密钥），可能被源码泄露或通过代码审查被发现，造成严重安全风险。建议使用环境变量或密钥管理系统存储敏感信息。"
            else:
                return "硬编码配置风险：代码中包含硬编码的配置值，降低了系统的可配置性和可维护性。建议将配置外部化到配置文件或环境变量中。"
        else:
            evidence = finding.get('evidence_chain_summary', '') or finding.get('reason', '') or finding.get('description', '')
            if evidence and len(evidence) > 20:
                return f"安全风险：{evidence[:150]}..."
            if 'evidence' in finding and isinstance(finding['evidence'], list) and len(finding['evidence']) > 0:
                ev = finding['evidence'][0]
                if isinstance(ev, dict):
                    reason = ev.get('reason', ev.get('description', ''))
                    if reason and len(reason) > 15:
                        return f"发现可疑代码模式：{reason[:100]}..."
            return f"发现{vulnerability}相关安全风险，建议根据详细代码上下文进行人工复核确认。"

    HIGH_RISK_TYPES = [
        'sql', 'sql注入', 'sql injection', 'sqli',
        'xss', 'cross-site', '跨站脚本',
        'csrf', 'cross-site request',
        '认证', 'authentication', 'auth bypass', '认证绕过',
        '授权', 'authorization', '越权', '权限',
        'session', '会话',
        '敏感信息', 'sensitive', 'password', 'secret', 'token',
        '注入', 'injection',
        '文件上传', 'file upload',
        '路径遍历', 'path traversal', 'directory traversal',
        '命令执行', 'command execution', 'rce',
        '远程代码执行', 'remote code execution',
        'xxe', 'xml external entity',
        '反序列化', 'deserialization', 'serialization',
        'cors', '跨域',
        'ssl', 'tls', '证书',
        '中间人', 'mitm',
    ]

    def _is_high_risk_type(self, title: str) -> bool:
        """检查是否为高危风险类型

        Args:
            title: 风险标题

        Returns:
            是否为高危风险
        """
        if not title:
            return False
        title_lower = title.lower()
        for pattern in self.HIGH_RISK_TYPES:
            if pattern in title_lower:
                return True
        return False

    def _check_rejection_completeness(self, risk_findings: List[Dict], all_rejected: bool = False) -> List[Dict]:
        """检查拒绝完整性，识别可能的审核失误

        当所有风险都被拒绝时，检查是否存在高危类型被错误拒绝的情况。
        对于高危类型，即使被 REJECTED 也标记为需要人工复核。

        Args:
            risk_findings: 风险发现列表
            all_rejected: 是否所有风险都被拒绝

        Returns:
            修改后的风险发现列表
        """
        if not all_rejected:
            return risk_findings

        modified_count = 0
        for risk in risk_findings:
            title = risk.get('title', risk.get('risk_type', ''))
            verification_decision = risk.get('verification_decision', '')
            signal_state = risk.get('signal_state', '')

            if verification_decision == 'REJECTED' and signal_state == 'REJECTED':
                if self._is_high_risk_type(title):
                    print(f"[WARN] [完整性检查] 高危风险类型被拒绝，进入人工复核: {title}")
                    risk['requires_human_review'] = True
                    risk['high_risk_override'] = True
                    risk['status'] = 'REFINED'
                    risk['signal_state'] = 'REFINED'
                    modified_count += 1

        if modified_count > 0:
            print(f"[WARN] [完整性检查] 识别出 {modified_count} 个高危类型被错误拒绝，已标记为待人工复核")

        return risk_findings

    def _merge_verification_results(self, risk: Dict[str, Any]) -> Dict[str, Any]:
        """合并验证结果到风险决策

        如果验证决策为CONFIRMED但裁决为其他状态，覆盖裁决

        Args:
            risk: 风险字典

        Returns:
            修改后的风险字典
        """
        verification_decision = risk.get('verification_decision', '')
        signal_state = risk.get('signal_state', 'NEW')
        reason = risk.get('reason', '')

        if verification_decision == 'CONFIRMED' and signal_state != 'CONFIRMED':
            print(f"[DEBUG] 验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}, 采用验证决策")
            self.debug_logs.append(f"[DEBUG] 验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}")
            risk['signal_state'] = 'CONFIRMED'
            risk['status'] = 'CONFIRMED'
            risk['verification_override'] = True
            risk['override_reason'] = f"验证决策: {verification_decision}, 原因: {reason}"
            self.debug_logs.append(f"[DEBUG] 覆盖原因: {reason}")

        elif verification_decision == 'REFINED' and signal_state not in ['CONFIRMED', 'REFINED']:
            print(f"[DEBUG] 验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}, 采用验证决策")
            self.debug_logs.append(f"[DEBUG] 验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}")
            risk['signal_state'] = 'REFINED'
            risk['status'] = 'REFINED'
            risk['verification_override'] = True
            risk['override_reason'] = f"验证决策: {verification_decision}, 原因: {reason}"

        elif verification_decision == 'REJECTED' and signal_state != 'REJECTED':
            print(f"[DEBUG] 验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}, 采用验证决策")
            self.debug_logs.append(f"[DEBUG] 验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}")
            risk['signal_state'] = 'REJECTED'
            risk['status'] = 'REJECTED'
            risk['verification_override'] = True
            risk['override_reason'] = f"验证决策: {verification_decision}, 原因: {reason}"

        return risk

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
            # 统一置信度阈值：MIN_CONFIDENCE = 0.3
            # - 低于 0.3 的风险直接跳过
            # - 0.3-0.7 的风险标记为 REFINED
            # - 高于 0.7 的风险标记为 CONFIRMED
            MIN_CONFIDENCE = 0.3  # 统一阈值

            if len(final_findings) == 0:
                vuln_verif = result.get('vulnerability_verification', {})
                vulnerabilities = vuln_verif.get('vulnerabilities', [])
                risks = vuln_verif.get('risks', [])

                def get_verification_state(v):
                    return v.get('signal_state') or v.get('verification_decision') or 'UNKNOWN'

                confirmed = [v for v in vulnerabilities if get_verification_state(v) == 'CONFIRMED']
                refined_with_high_confidence = []

                for v in vulnerabilities:
                    if get_verification_state(v) == 'REFINED':
                        evidence = v.get('evidence', [])
                        avg_conf = self._calculate_evidence_confidence(evidence)
                        if avg_conf and avg_conf >= MIN_CONFIDENCE:
                            refined_with_high_confidence.append((v, avg_conf))

                print(f"[DEBUG] Fallback: 从 vulnerability_verification 提取已确认漏洞: {len(confirmed)}")
                print(f"[DEBUG] Fallback: 从 vulnerability_verification 提取高置信度已细化漏洞: {len(refined_with_high_confidence)}")

                adversarial_val = result.get('adversarial_validation', {})
                adversarial_analysis = adversarial_val.get('adversarial_analysis', [])
                adversarial_findings = []

                for item in adversarial_analysis:
                    verdict = item.get('verdict', '')
                    if verdict in ['ACCEPT', 'ESCALATE']:
                        item_confidence = item.get('confidence', 0)
                        if isinstance(item_confidence, str):
                            try:
                                item_confidence = float(item_confidence.replace('%', '')) / 100.0 if '%' in item_confidence else 0.5
                            except:
                                item_confidence = 0.5

                        if verdict == 'ESCALATE' and item_confidence < MIN_CONFIDENCE:
                            print(f"[DEBUG] 跳过低置信度待定: {item.get('attack_chain_name', '未知')} (置信度={item_confidence:.2f})")
                            continue

                        vuln_info = item.get('vulnerability', {})
                        raw_location = None
                        if isinstance(vuln_info, dict):
                            raw_location = vuln_info.get('location', None)
                            if not raw_location or raw_location in ('Unknown', '', None):
                                raw_location = self._extract_location_from_evidence(item, file_path_context)
                            else:
                                raw_location = f"{Path(file_path_context).name}:{raw_location}"
                            adversarial_findings.append({
                                'vulnerability': self._translate_vulnerability_name_ai(vuln_info.get('title', item.get('attack_chain_name', 'Unknown'))),
                                'location': raw_location,
                                'severity': self.normalize_severity(vuln_info.get('severity', 'MEDIUM')),
                                'status': 'VALID' if verdict == 'ACCEPT' else 'UNCERTAIN',
                                'confidence': item_confidence,
                                'cvss_score': vuln_info.get('cvss_score', ''),
                                'recommendation': self._generate_recommendation(
                                    vuln_info.get('title', item.get('attack_chain_name', 'Unknown')),
                                    self.normalize_severity(vuln_info.get('severity', 'MEDIUM')),
                                    item.get('reason', ''),
                                    str(item.get('evidence', ''))
                                ),
                                'evidence': item.get('evidence', []),
                                'requires_human_review': item.get('requires_human_review', True)
                            })
                        else:
                            raw_location = self._extract_location_from_evidence(item, file_path_context)
                            adversarial_findings.append({
                                'vulnerability': self._translate_vulnerability_name_ai(item.get('attack_chain_name', 'Unknown')),
                                'location': raw_location,
                                'severity': self.normalize_severity(item.get('severity', 'MEDIUM')),
                                'status': 'VALID' if verdict == 'ACCEPT' else 'UNCERTAIN',
                                'confidence': item_confidence,
                                'cvss_score': '',
                                'recommendation': self._generate_recommendation(
                                    item.get('attack_chain_name', 'Unknown'),
                                    self.normalize_severity(item.get('severity', 'MEDIUM')),
                                    item.get('reason', ''),
                                    str(item.get('evidence', ''))
                                ),
                                'evidence': item.get('evidence', []),
                                'requires_human_review': item.get('requires_human_review', True)
                            })

                risk_enum = result.get('risk_enumeration', {})
                risk_findings = risk_enum.get('risks', [])

                vuln_verif = result.get('vulnerability_verification', {})
                signal_id_to_verification = {
                    v.get('signal_id'): v
                    for v in vuln_verif.get('vulnerabilities', [])
                    if v.get('signal_id')
                }

                evidence_chain = result.get('evidence_chain', {})
                tracker_signal_states = evidence_chain.get('signal_states', {})

                if not risk_findings and tracker_signal_states:
                    confirmed_signals = {
                        sig_id: sig_data for sig_id, sig_data in tracker_signal_states.items()
                        if sig_data.get('state') in ['CONFIRMED', 'REFINED']
                    }
                    if confirmed_signals:
                        print(f"[DEBUG] risk_enumeration.risks 为空，从 signal_tracker 提取 {len(confirmed_signals)} 个已确认信号")
                        for sig_id, sig_data in confirmed_signals.items():
                            verification = signal_id_to_verification.get(sig_id, {})
                            evidence_list = verification.get('evidence', [])
                            if not evidence_list:
                                evidence_list = sig_data.get('evidence', [])
                            stored_title = sig_data.get('title', '') or sig_data.get('type', '')
                            stored_desc = sig_data.get('description', '')

                            has_meaningful_info = bool(stored_title and stored_title not in ('', 'UNKNOWN', 'unknown'))
                            has_meaningful_desc = bool(stored_desc and stored_desc.strip())
                            has_evidence = bool(evidence_list and len(evidence_list) > 0)

                            if not has_meaningful_info and not has_meaningful_desc and not has_evidence:
                                print(f"[DEBUG] Fallback: 跳过信息不完整的信号 {sig_id}")
                                continue

                            if not stored_title and stored_desc:
                                stored_title = stored_desc[:50] + "..." if len(stored_desc) > 50 else stored_desc

                            risk_findings.append({
                                'signal_id': sig_id,
                                'title': stored_title,
                                'risk_type': stored_title,
                                'severity': sig_data.get('severity', 'MEDIUM'),
                                'description': stored_desc or f"信号追踪确认漏洞: {sig_id}",
                                'evidence': evidence_list,
                                'verification_decision': verification.get('verification_decision', 'CONFIRMED'),
                                'verification_reason': verification.get('reason', ''),
                                'status': 'CONFIRMED'
                            })

                risk_based_findings = []

                for risk in risk_findings:
                    signal_id = risk.get('signal_id', '')

                    # NEW-BUG-007 修复: 检查标题是否泛化，如果是则从 signal_tracker 获取正确信息
                    risk_title = risk.get('title', '') or risk.get('vulnerability', '') or risk.get('risk_type', '')
                    泛化标记 = ['risk相关安全风险', 'UNKNOWN', 'unknown', '', 'UNVERIFIED_RISK', 'UNVERIFIED', 'GENERIC', 'PLACEHOLDER']
                    is泛化 = not risk_title or risk_title in 泛化标记 or 'UNVERIFIED' in risk_title.upper()

                    if is泛化 and signal_id and signal_id in tracker_signal_states:
                        sig_data = tracker_signal_states[signal_id]
                        tracker_title = sig_data.get('title', '') or sig_data.get('type', '')
                        if tracker_title and tracker_title not in ('', 'UNKNOWN', 'unknown'):
                            print(f"[DEBUG] 替换泛化标题: '{risk_title}' -> '{tracker_title}'")
                            risk['title'] = tracker_title
                            risk['vulnerability'] = tracker_title
                            risk['risk_type'] = tracker_title
                            risk['description'] = sig_data.get('description', '') or risk.get('description', '')

                    tracker_state = None
                    if signal_id and signal_id in tracker_signal_states:
                        tracker_state = tracker_signal_states[signal_id].get('state', None)

                    if signal_id and signal_id in signal_id_to_verification:
                        verification = signal_id_to_verification[signal_id]
                        risk['verification_decision'] = verification.get('verification_decision', '')
                        risk['verification_reason'] = verification.get('verification_reason', '')

                    risk = self._merge_verification_results(risk)

                    verification_decision = risk.get('verification_decision', '')

                    if tracker_state:
                        if verification_decision == 'CONFIRMED' and tracker_state in ['REJECTED', 'NEW']:
                            print(f"[DEBUG] Agent-3 确认覆盖 tracker 状态: {tracker_state} -> CONFIRMED")
                            risk['signal_state'] = 'CONFIRMED'
                            risk_state = 'CONFIRMED'
                        else:
                            risk['signal_state'] = tracker_state
                            risk_state = tracker_state
                    else:
                        risk_state = risk.get('signal_state', 'NEW')

                    risk_confidence = self._calculate_evidence_confidence(risk.get('evidence', []))
                    MIN_CONFIDENCE = 0.3

                    risk_title = risk.get('title', risk.get('risk_type', ''))
                    is_high_risk = self._is_high_risk_type(risk_title)

                    if risk_state == 'REJECTED' and verification_decision != 'CONFIRMED':
                        rejection_confidence = risk.get('rejection_confidence', 0.5)
                        if is_high_risk and rejection_confidence < 0.7:
                            print(f"[WARN] [审核检查] 高危风险被拒绝(低置信度): {risk_title}, 置信度: {rejection_confidence:.2f}, 标记为待人工复核")
                            risk['requires_human_review'] = True
                            risk['high_risk_override'] = True
                            risk_state = 'REFINED'
                            risk['signal_state'] = 'REFINED'
                        elif is_high_risk and rejection_confidence >= 0.7:
                            print(f"[DEBUG] 高危风险被明确拒绝(高置信度: {rejection_confidence:.2f}): {risk_title}, 跳过")
                            continue
                        else:
                            print(f"[DEBUG] 跳过已拒绝信号: {risk.get('title', risk.get('risk_type', '未知风险'))}, 验证决策: {verification_decision or 'N/A'}")
                            continue

                    if risk_state in ['CONFIRMED', 'REFINED'] or (risk_confidence and risk_confidence >= MIN_CONFIDENCE):
                        if risk_confidence and risk_confidence < MIN_CONFIDENCE:
                            print(f"[DEBUG] 跳过极低置信度风险: {risk.get('title', risk.get('risk_type', '未知风险'))}, 置信度: {risk_confidence:.4f}")
                            continue
                        risk_title_raw = risk.get('title', risk.get('risk_type', 'UNKNOWN_RISK'))
                        risk_title = self._translate_vulnerability_name_ai(risk_title_raw)
                        risk_severity = self.normalize_severity(risk.get('severity', 'MEDIUM'))
                        risk_location = risk.get('location', '')
                        if not risk_location or risk_location in ('Unknown', '', None):
                            risk_location = self._extract_location_from_evidence(risk, file_path_context)
                        risk_status = risk.get('status', 'UNCERTAIN')
                        if risk.get('verification_override'):
                            risk_status = 'CONFIRMED'
                        if risk_state in ['CONFIRMED', 'REFINED'] and risk_status not in ['CONFIRMED', 'REFINED']:
                            risk_status = risk_state
                        risk_based_findings.append({
                            'vulnerability': risk_title,
                            'location': risk_location,
                            'severity': risk_severity,
                            'status': risk_status,
                            'confidence': risk_confidence if risk_confidence else 0.5,
                            'cvss_score': '',
                            'recommendation': self._generate_recommendation(risk_title, risk_severity, risk.get('description', ''), str(risk.get('evidence', []))),
                            'evidence': risk.get('evidence', []),
                            'requires_human_review': True,
                            'signal_state': risk_state,
                            'verification_decision': verification_decision
                        })

                all_rejected = (len(risk_findings) > 0 and len(risk_based_findings) == 0)
                if all_rejected:
                    print(f"[WARN] [完整性检查] 所有 {len(risk_findings)} 个风险都被拒绝，执行高危类型检查...")
                    risk_findings = self._check_rejection_completeness(risk_findings, all_rejected=True)

                    for risk in risk_findings:
                        title = risk.get('title', risk.get('risk_type', ''))
                        is_high_risk = self._is_high_risk_type(title)
                        if is_high_risk and risk.get('high_risk_override'):
                            risk_confidence = self._calculate_evidence_confidence(risk.get('evidence', []))
                            risk_location = risk.get('location', '')
                            if not risk_location or risk_location in ('Unknown', '', None):
                                risk_location = self._extract_location_from_evidence(risk, file_path_context)
                            risk_based_findings.append({
                                'vulnerability': title,
                                'location': risk_location,
                                'severity': self.normalize_severity(risk.get('severity', 'MEDIUM')),
                                'status': 'REFINED',
                                'confidence': risk_confidence if risk_confidence else 0.5,
                                'cvss_score': '',
                                'recommendation': self._generate_recommendation(title, self.normalize_severity(risk.get('severity', 'MEDIUM')), risk.get('description', ''), str(risk.get('evidence', []))),
                                'evidence': risk.get('evidence', []),
                                'requires_human_review': True,
                                'signal_state': 'REFINED',
                                'verification_decision': 'REFINED'
                            })

                print(f"[DEBUG] Fallback 检查:")
                print(f"  - vulnerability_verification.vulnerabilities (CONFIRMED): {len(confirmed)}")
                print(f"  - vulnerability_verification (REFINED 高置信度): {len(refined_with_high_confidence)}")
                print(f"  - adversarial_validation.ACCEPT/ESCALATE: {len(adversarial_findings)}")
                print(f"  - risk_enumeration.risks: {len(risk_findings)} (可用: {len(risk_based_findings)})")

                if adversarial_findings:
                    print(f"[DEBUG] 使用 fallback: 从 adversarial_validation 获取 {len(adversarial_findings)} 个漏洞")
                    final_findings = adversarial_findings
                elif confirmed:
                    print(f"[DEBUG] 使用 fallback: 从 vulnerability_verification.confirmed_vulnerabilities 获取 {len(confirmed)} 个漏洞")
                    final_findings = []
                    for v in confirmed:
                        v_type = v.get('vulnerability') or v.get('type') or v.get('title') or v.get('risk_type') or 'SUSPICIOUS_PATTERN'
                        v_copy = dict(v)
                        v_copy['vulnerability'] = v_type
                        final_findings.append(v_copy)
                elif refined_with_high_confidence:
                    print(f"[DEBUG] 使用 fallback: 从高置信度已细化获取 {len(refined_with_high_confidence)} 个漏洞")
                    final_findings = []
                    for v, conf in refined_with_high_confidence:
                        v_type = v.get('title') or v.get('risk_type') or 'SUSPICIOUS_PATTERN'
                        v_copy = dict(v)
                        v_copy['vulnerability'] = v_type
                        v_copy['status'] = 'UNCERTAIN'
                        v_copy['confidence'] = conf
                        final_findings.append(v_copy)
                elif risk_based_findings:
                    print(f"[DEBUG] 使用 fallback: 从 risk_enumeration 获取 {len(risk_based_findings)} 个漏洞")
                    verified_findings = []
                    unverified_findings = []
                    rejected_findings = []
                    for v in risk_based_findings:
                        if 'metadata' not in v:
                            v['metadata'] = {}
                        signal_state = v.get('signal_state', 'NEW')
                        status = v.get('status', 'UNKNOWN')
                        confidence = v.get('confidence', 0)
                        verification_decision = v.get('verification_decision', '')
                        evidence = v.get('evidence', [])
                        has_code_snippet = any(
                            isinstance(e, dict) and e.get('type') == 'code_line' and e.get('code_snippet')
                            for e in evidence
                        ) if evidence else False

                        if signal_state == 'REJECTED' and verification_decision != 'CONFIRMED':
                            v['metadata']['line_match_status'] = 'REJECTED'
                            rejected_findings.append(v)
                            print(f"[DEBUG] 丢弃已拒绝信号: {v.get('vulnerability', '未知')}, verification_decision={verification_decision}")
                            continue

                        if signal_state == 'NEW' and not has_code_snippet and verification_decision != 'CONFIRMED':
                            v['metadata']['line_match_status'] = 'REJECTED_NO_VERIFICATION'
                            unverified_findings.append(v)
                            print(f"[DEBUG] 丢弃未验证信号（无代码片段）: {v.get('vulnerability', '未知')}, verification_decision={verification_decision}")
                            continue

                        if signal_state == 'NEW' and confidence < MIN_CONFIDENCE:
                            v['metadata']['line_match_status'] = 'REJECTED_LOW_CONFIDENCE'
                            unverified_findings.append(v)
                            print(f"[DEBUG] 丢弃低置信度未验证信号: {v.get('vulnerability', '未知')}, confidence={confidence:.4f}")
                            continue

                        if status == 'CONFIRMED':
                            v['metadata']['line_match_status'] = 'VERIFIED'
                            verified_findings.append(v)
                        elif status == 'REFINED':
                            v['metadata']['line_match_status'] = 'VERIFIED'
                            verified_findings.append(v)
                        else:
                            v['metadata']['line_match_status'] = 'UNVERIFIED'
                            unverified_findings.append(v)
                    if rejected_findings:
                        print(f"[DEBUG] 检查 {len(rejected_findings)} 个已拒绝漏洞是否有高置信度...")
                        high_conf_rejected = [v for v in rejected_findings if v.get('confidence', 0) >= MIN_CONFIDENCE]
                        if high_conf_rejected:
                            print(f"[DEBUG] 从 {len(rejected_findings)} 个已拒绝漏洞中筛选出 {len(high_conf_rejected)} 个高置信度漏洞进行人工复核")
                            for v in high_conf_rejected:
                                v['status'] = 'UNCERTAIN'
                                v['requires_human_review'] = True
                            unverified_findings.extend(high_conf_rejected)
                    if verified_findings:
                        print(f"[DEBUG] 从 risk_enumeration 筛选出 {len(verified_findings)} 个已验证漏洞")
                        if unverified_findings:
                            print(f"[DEBUG] 额外添加 {len(unverified_findings)} 个高置信度未验证/已拒绝漏洞进行人工复核")
                        final_findings = verified_findings + unverified_findings
                    elif unverified_findings:
                        print(f"[DEBUG] 警告: risk_enumeration 中无 Agent-3 验证的漏洞，使用 {len(unverified_findings)} 个高置信度漏洞")
                        final_findings = unverified_findings
                    else:
                        print(f"[DEBUG] Fallback: 未找到任何漏洞")
                        final_findings = []
                else:
                    print(f"[DEBUG] Fallback: 未找到任何漏洞")

            # 计算总漏洞数
            total_vulnerabilities = len(final_findings)

            for finding in final_findings:
                try:
                    status = finding.get('status', 'UNKNOWN')
                    vuln_name = finding.get('vulnerability', '') or ''

                    if status == 'REJECTED':
                        print(f"[DEBUG] 跳过 final_decision 中的已拒绝发现: {vuln_name}")
                        self.debug_logs.append(f"[DEBUG] 跳过 final_decision 中的已拒绝发现: {vuln_name}")
                        continue

                    status_display = status
                    if status == 'CONFIRMED':
                        status_display = '已确认'
                    elif status == 'REJECTED':
                        status_display = '已拒绝'
                    elif status == 'REFINED':
                        status_display = '已细化'
                    elif status == 'NEW':
                        status_display = '新增'
                    elif status == 'UNCERTAIN':
                        status_display = '待定'
                    print(f"[DEBUG] 处理发现: {finding.get('vulnerability')}, 状态: {status_display}")
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

                    # 生成规则名称 - 只包含漏洞名称（中文化）
                    rule_name = self._translate_vulnerability_name_ai(vulnerability_desc)
                    if status == 'INVALID' and total_vulnerabilities < 10:
                        rule_name = f"[需人工复核] {rule_name}"

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

                    # 保存原始严重级别
                    original_severity = severity

                    # 处理置信度，避免空字符串转换错误
                    confidence_value = finding.get('confidence', 50)
                    try:
                        if isinstance(confidence_value, str):
                            if '%' in confidence_value:
                                confidence_value = confidence_value.replace('%', '')
                                confidence = float(confidence_value) / 100.0
                            elif float(confidence_value) > 1:
                                confidence = float(confidence_value) / 100.0
                            else:
                                confidence = float(confidence_value)
                        else:
                            confidence = float(confidence_value) / 100.0 if float(confidence_value) > 1 else float(confidence_value)
                    except (ValueError, TypeError):
                        confidence = 0.5

                    if confidence < 0.3:
                        print(f"[DEBUG] 跳过极低置信度漏洞: {vulnerability_desc}, 置信度: {confidence:.4f}")
                        self.debug_logs.append(f"[DEBUG] 跳过极低置信度漏洞: {vulnerability_desc}, 置信度: {confidence:.4f}")
                        continue

                    # 验证漏洞位置和代码是否真实存在（防止AI编造）
                    validation_result = self._validate_finding_location(finding, file_path_context)
                    if not validation_result['is_valid']:
                        print(f"[WARN] 漏洞验证失败，跳过: {vulnerability_desc} - {validation_result['reason']}")
                        self.debug_logs.append(f"[WARN] 漏洞验证失败，跳过: {vulnerability_desc} - {validation_result['reason']}")
                        continue

                    # 提取行号
                    line_num = 0
                    if isinstance(location, str) and ':' in location:
                        parts = location.rsplit(':', 1)
                        if len(parts) == 2 and parts[1].isdigit():
                            line_num = int(parts[1])

                    # 使用 LineNumberValidator 修正不准确的行号
                    line_validation_passed = True
                    try:
                        if line_num > 0 and file_path_context:
                            validator = LineNumberValidator()  # 使用配置中的tolerance值
                            with open(file_path_context, 'r', encoding='utf-8', errors='ignore') as f:
                                file_content = f.read()
                            actual_line, match_status, candidates = validator.find_actual_line(finding, file_content)
                            finding['line_match_status'] = match_status

                            if match_status == "NOT_FOUND":
                                print(f"[WARN] 行号验证失败，跳过: {rule_name} - AI报告行{line_num}无法验证")
                                self.debug_logs.append(f"[WARN] 行号验证失败，跳过: {rule_name} - AI报告行{line_num}无法验证")
                                line_validation_passed = False
                            elif actual_line > 0 and actual_line != line_num:
                                print(f"[DEBUG] Line number adjusted: {line_num} -> {actual_line} (status: {match_status})")
                                self.debug_logs.append(f"[DEBUG] Line number adjusted: {line_num} -> {actual_line}")
                                line_num = actual_line
                    except Exception as e:
                        print(f"[DEBUG] Line number validation skipped: {e}")
                        self.debug_logs.append(f"[DEBUG] Line number validation skipped: {e}")

                    if not line_validation_passed:
                        continue

                    # 提取代码片段
                    code_snippet = self._extract_code_at_line(
                        file_path_context,
                        line_num if line_num > 0 else 1,
                        context_lines=3
                    )

                    # 计算 end_line：根据代码片段实际行数计算
                    snippet_lines = code_snippet.count('\n') + 1 if code_snippet else 1
                    end_line = line_num + snippet_lines - 1

                    # 提取来源信息
                    vuln_source = finding.get('source', 'ai_analysis')
                    original_rule_id = finding.get('rule_id', finding.get('vulnerability', 'unknown'))

                    # 提取evidence数据
                    evidence = finding.get('evidence', [])
                    metadata = {
                        'evidence': evidence,
                        'requires_human_review': finding.get('requires_human_review', False),
                        'line_match_status': finding.get('line_match_status', 'UNVERIFIED'),
                        'signal_state': finding.get('signal_state', 'NEW'),
                        'status': finding.get('status', 'UNKNOWN'),
                        'source': vuln_source,
                        'rule_id': original_rule_id
                    }

                    vulnerability = VulnerabilityFinding(
                        rule_id=original_rule_id,
                        rule_name=rule_name,
                        severity=severity,
                        confidence=confidence,
                        location={
                            'file': location.rsplit(':', 1)[0] if isinstance(location, str) and ':' in location else location,
                            'line': line_num,
                            'end_line': end_line
                        },
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

        Raises:
            APIError: 当API错误需要截断时
        """
        from src.ai.providers.deepseek import APIError as DeepSeekAPIError

        try:
            if self.config.debug:
                print(f"[DEBUG] 分析文件: {file_info.path}")

            # 确保已初始化
            if not self.initialized:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 纯AI分析器未初始化，正在初始化...[/dim]")
                await self._initialize()
                if not self.initialized:
                    console.print(f"[red][X] 纯AI分析器初始化失败，跳过分析: {file_info.path}[/red]")
                    return []

            # 检查pipeline
            if not self.pipeline:
                console.print(f"[red][X] Pipeline未创建，跳过分析: {file_info.path}[/red]")
                return []

            # 分析文件
            findings = await self.analyze(file_info.path, "")
            if self.config.debug:
                print(f"[DEBUG] 分析完成，发现 {len(findings)} 个问题")
            return findings
        except DeepSeekAPIError as e:
            console.print(f"[red][X] API错误，分析中断: {e.message}[/red]")
            raise
        except Exception as e:
            console.print(f"[red][X] 纯AI分析文件失败: {e}[/red]")
            if self.config.debug:
                import traceback
                traceback.print_exc()
            return []

    async def analyze_batch(self, file_infos: List[Any], max_concurrent: int = 5) -> List[List[VulnerabilityFinding]]:
        """批量分析文件 - 智能分层扫描

        仿人类专家思维：
        1. 先用 CodeVulnScanner 快速预检所有文件
        2. AI 只分析 CodeVulnScanner 发现可疑的文件

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

        start_time = time.time()
        total_files = len(file_infos)

        if total_files == 0:
            return []

        # Step 1: 快速预检 - CodeVulnScanner 扫描所有文件
        from src.analyzers.code_vuln_scanner import CodeVulnScanner
        from src.core.file_filter import SecurityFileFilter, RiskLevel

        code_scanner = CodeVulnScanner()
        file_filter = SecurityFileFilter()

        suspicious_files = []  # 需要 AI 分析的可疑文件
        safe_files = []  # 安全文件，跳过 AI 分析

        print(f"[DEBUG] 智能分层扫描：先快速预检 {total_files} 个文件...")

        DEPENDENCY_FILES = {
            'pom.xml', 'build.gradle', 'build.gradle.kts',
            'package.json', 'requirements.txt', 'Pipfile', 'Pipfile.lock',
            'Gemfile', 'Gemfile.lock', 'go.mod', 'go.sum',
            'Cargo.toml', 'composer.json', 'package-lock.json'
        }

        from pathlib import Path

        dependency_files = {}
        all_file_paths = [str(fi.path) for fi in file_infos]

        for file_info in file_infos:
            file_name = Path(file_info.path).name.lower()
            if file_name in DEPENDENCY_FILES:
                try:
                    with open(file_info.path, 'r', encoding='utf-8') as f:
                        dependency_files[file_name] = f.read()
                except Exception:
                    pass

        project_libraries = []
        library_matcher = None
        nvd_vulnerabilities = []

        if dependency_files:
            try:
                from src.scanner.library_matcher import get_library_matcher
                library_matcher = get_library_matcher()

                if library_matcher._nvd_available:
                    for file_name, content in dependency_files.items():
                        language = 'java'
                        if file_name == 'package.json' or file_name == 'package-lock.json':
                            language = 'javascript'
                        elif file_name in ('requirements.txt', 'Pipfile', 'Pipfile.lock'):
                            language = 'python'

                        libs = library_matcher.detect_libraries(content, language)
                        project_libraries.extend(libs)

                    if project_libraries:
                        print(f"[DEBUG] Build project dependency table: found {len(project_libraries)} libraries")

                    if library_matcher._nvd_available:
                        nvd_vulnerabilities = library_matcher.match_vulnerabilities(project_libraries)
                        if nvd_vulnerabilities:
                            print(f"[DEBUG] Found {len(nvd_vulnerabilities)} known CVE vulnerabilities in project dependencies")

                            for vuln in nvd_vulnerabilities[:5]:
                                cvss = vuln.metadata.get('cvss_score', 0)
                                print(f"[DEBUG]   - {vuln.library_name}: {vuln.cve_id} (CVSS: {cvss})")
                            if len(nvd_vulnerabilities) > 5:
                                print(f"[DEBUG]   ... and {len(nvd_vulnerabilities) - 5} more CVEs")
            except Exception as e:
                if self.config.debug:
                    print(f"[DEBUG] Library version detection failed: {e}")

        vulnerable_library_names = set()
        if nvd_vulnerabilities:
            vulnerable_library_names = {v.library_name for v in nvd_vulnerabilities}

        for i, file_info in enumerate(file_infos):
            file_path = str(file_info.path)

            if code_scanner.is_code_file(file_path) or code_scanner.is_mybatis_mapper(file_path):
                classified = file_filter.classify_file(file_path)
                uses_vulnerable_lib = False

                if vulnerable_library_names and library_matcher:
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        language = file_info.language.value if file_info.language else 'java'
                        imported_libs = library_matcher.detect_libraries(content, language)
                        imported_names = {lib.name for lib in imported_libs}
                        if imported_names & vulnerable_library_names:
                            uses_vulnerable_lib = True
                    except Exception:
                        pass

                if classified.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM) or uses_vulnerable_lib:
                    quick_results = code_scanner.scan_file(file_path)
                    if quick_results or uses_vulnerable_lib:
                        suspicious_files.append((i, file_info, quick_results))
                    else:
                        suspicious_files.append((i, file_info, []))
                elif self.config.pure_ai:
                    suspicious_files.append((i, file_info, []))
                else:
                    safe_files.append((i, file_path))
            else:
                if self.config.pure_ai:
                    suspicious_files.append((i, file_info, []))
                else:
                    safe_files.append((i, file_path))

        print(f"[DEBUG] 预检完成：{len(suspicious_files)} 个可疑文件需要 AI 深度分析，{len(safe_files)} 个安全文件跳过 AI")

        if not suspicious_files:
            # 所有文件都安全，直接返回空结果
            return [[] for _ in file_infos]

        # Step 2: AI 只分析可疑文件
        ai_results = {}
        dynamic_concurrent = min(max_concurrent, len(suspicious_files))

        print(f"[DEBUG] 开始 AI 深度分析 {len(suspicious_files)} 个可疑文件 (并发数: {dynamic_concurrent})...")

        semaphore = asyncio.Semaphore(dynamic_concurrent)

        async def analyze_with_limit(idx, file_info):
            async with semaphore:
                if self.config.debug:
                    print(f"[DEBUG] AI 分析文件 {idx+1}/{len(suspicious_files)}: {file_info.path}")
                return idx, await self.analyze_file(file_info)

        tasks = [analyze_with_limit(idx, fi) for idx, fi, _ in suspicious_files]
        ai_analyzed = await asyncio.gather(*tasks)

        for idx, result in ai_analyzed:
            ai_results[idx] = result

        # Step 3: 组装结果
        results = [[] for _ in file_infos]

        file_to_vuln_libs = {}
        if vulnerable_library_names and library_matcher:
            for idx, file_info, _ in suspicious_files:
                try:
                    with open(file_info.path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    language = file_info.language.value if file_info.language else 'java'
                    imported_libs = library_matcher.detect_libraries(content, language)
                    imported_names = {lib.name for lib in imported_libs}
                    matched_libs = imported_names & vulnerable_library_names
                    if matched_libs:
                        file_to_vuln_libs[idx] = matched_libs
                except Exception:
                    pass

        for idx, _, quick_results in suspicious_files:
            all_findings = []
            if idx in ai_results:
                all_findings.extend(ai_results[idx])
            if not all_findings and quick_results:
                for qr in quick_results:
                    from dataclasses import asdict
                    qr_dict = asdict(qr)
                    qr_dict['rule_id'] = qr_dict.get('vuln_type', 'unknown')
                    qr_dict['rule_name'] = qr_dict.get('vuln_type', 'unknown')
                    severity_map = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}
                    level = qr_dict.get('level', 'MEDIUM')
                    if hasattr(level, 'value'):
                        level = level.value
                    qr_dict['severity'] = severity_map.get(str(level).upper(), 'medium')
                    qr_dict['fix_suggestion'] = qr_dict.get('remediation', '')
                    qr_dict['location'] = {
                        'file': qr_dict.get('file_path', ''),
                        'line': qr_dict.get('line_number', 0),
                        'column': 0,
                        'end_line': qr_dict.get('line_number', 0),
                        'end_column': 0
                    }
                    for key in ['vuln_type', 'level', 'remediation', 'file_path', 'line_number']:
                        qr_dict.pop(key, None)
                    all_findings.append(type('Finding', (), qr_dict)())

            if idx in file_to_vuln_libs and nvd_vulnerabilities:
                for vuln in nvd_vulnerabilities:
                    if vuln.library_name in file_to_vuln_libs[idx]:
                        cvss_score = vuln.metadata.get('cvss_score', 0)
                        severity_map = {
                            'CRITICAL': 'critical', 'HIGH': 'high',
                            'MEDIUM': 'medium', 'LOW': 'low'
                        }
                        severity = severity_map.get(vuln.severity.upper(), 'medium')

                        finding = type('Finding', (), {
                            'rule_id': f"NVD-{vuln.cve_id}",
                            'rule_name': f"{vuln.library_name} 存在已知漏洞",
                            'description': f"{vuln.library_name} 版本 {vuln.affected_versions[0] if vuln.affected_versions else '未知'} 存在CVE漏洞",
                            'severity': severity,
                            'confidence': min(1.0, cvss_score / 10.0 + 0.3),
                            'message': f"{vuln.library_name} 存在 {vuln.cve_id}，受影响版本: {', '.join(vuln.affected_versions[:3]) if vuln.affected_versions else '未知'}",
                            'code_snippet': f"检测到库: {vuln.library_name}",
                            'fix_suggestion': f"升级到安全版本: {vuln.fix_version}" if vuln.fix_version else "请查看官方安全公告并升级",
                            'metadata': {
                                'source': 'nvd_library_matcher',
                                'cve_id': vuln.cve_id,
                                'library_name': vuln.library_name,
                                'verified': True,
                                'cvss_score': cvss_score
                            }
                        })()
                        all_findings.append(finding)

            results[idx] = all_findings

        # Step 4: 第三重验证 - NVD CVE相似度复查
        all_ai_findings = []
        for idx, findings in enumerate(results):
            for f in findings:
                if hasattr(f, 'metadata') and f.metadata.get('source') != 'nvd_library_matcher':
                    all_ai_findings.append((idx, f))

        cve_confirmed_count = 0
        hallucination_warnings = []
        filled_gaps_count = 0

        if all_ai_findings and project_libraries and nvd_vulnerabilities:
            print(f"[DEBUG] [Triple Verification] Starting NVD CVE similarity verification...")

            verified_library_names = {v.library_name for v in nvd_vulnerabilities}

            for idx, finding in all_ai_findings:
                if not hasattr(finding, 'metadata'):
                    continue

                metadata = finding.metadata
                library_name = metadata.get('library_name', '')

                if library_name and library_name in verified_library_names:
                    for vuln in nvd_vulnerabilities:
                        if vuln.library_name == library_name:
                            metadata['cve_confirmed'] = True
                            metadata['cve_id'] = vuln.cve_id
                            metadata['cvss_score'] = vuln.metadata.get('cvss_score', 0)
                            metadata['triple_verified'] = True
                            cve_confirmed_count += 1
                            break
                else:
                    if library_name and not any(v.library_name == library_name for v in nvd_vulnerabilities):
                        metadata['cve_confirmed'] = False
                        metadata['hallucination_risk'] = 'MEDIUM'
                        metadata['triple_verified'] = False
                        hallucination_warnings.append({
                            'file_idx': idx,
                            'library_name': library_name,
                            'rule_name': getattr(finding, 'rule_name', 'Unknown')
                        })

            for vuln in nvd_vulnerabilities:
                already_found = any(
                    hasattr(f, 'metadata') and f.metadata.get('cve_id') == vuln.cve_id
                    for findings in results
                    for f in findings
                )
                if not already_found:
                    for idx, file_info, _ in suspicious_files:
                        try:
                            with open(file_info.path, 'r', encoding='utf-8') as f:
                                content = f.read()
                            language = file_info.language.value if file_info.language else 'java'
                            imported_libs = library_matcher.detect_libraries(content, language)
                            imported_names = {lib.name for lib in imported_libs}
                            if vuln.library_name in imported_names:
                                cvss_score = vuln.metadata.get('cvss_score', 0)
                                severity_map = {
                                    'CRITICAL': 'critical', 'HIGH': 'high',
                                    'MEDIUM': 'medium', 'LOW': 'low'
                                }
                                severity = severity_map.get(vuln.severity.upper(), 'medium')

                                gap_finding = type('Finding', (), {
                                    'rule_id': f"NVD-{vuln.cve_id}",
                                    'rule_name': f"{vuln.library_name} 存在已知漏洞 (Triple-Verified)",
                                    'description': f"{vuln.library_name} 版本 {vuln.affected_versions[0] if vuln.affected_versions else '未知'} 存在CVE漏洞",
                                    'severity': severity,
                                    'confidence': min(1.0, cvss_score / 10.0 + 0.3),
                                    'message': f"{vuln.library_name} 存在 {vuln.cve_id}，受影响版本: {', '.join(vuln.affected_versions[:3]) if vuln.affected_versions else '未知'}",
                                    'code_snippet': f"检测到库: {vuln.library_name}",
                                    'fix_suggestion': f"升级到安全版本: {vuln.fix_version}" if vuln.fix_version else "请查看官方安全公告并升级",
                                    'metadata': {
                                        'source': 'nvd_library_matcher',
                                        'cve_id': vuln.cve_id,
                                        'library_name': vuln.library_name,
                                        'verified': True,
                                        'cvss_score': cvss_score,
                                        'triple_verified': True,
                                        'gap_filled': True
                                    }
                                })()
                                results[idx].append(gap_finding)
                                filled_gaps_count += 1
                                break
                        except Exception:
                            pass

            print(f"[DEBUG] [Triple Verification] CVE confirmed: {cve_confirmed_count}")
            if hallucination_warnings:
                print(f"[DEBUG] [Triple Verification] Hallucination warnings: {len(hallucination_warnings)}")
                for hw in hallucination_warnings[:3]:
                    print(f"[DEBUG]   - {hw['rule_name']} ({hw['library_name']})")
            print(f"[DEBUG] [Triple Verification] Gap-filling (NVD): {filled_gaps_count}")

        print(f"[DEBUG] [Triple Verification] Starting file path and code snippet verification...")

        try:
            from src.analyzers.finding_verifier import FindingVerifier, verify_ai_findings

            all_findings = [f for findings in results for f in findings]
            if all_findings:
                if file_infos:
                    file_paths = [Path(fi.path) for fi in file_infos]
                    common_parts = file_paths[0].parts
                    for fp in file_paths[1:]:
                        parts = fp.parts
                        common_parts = tuple(p for p in common_parts if p in parts)
                    project_root = str(Path(*common_parts)) if common_parts else str(file_paths[0].parent)
                else:
                    project_root = ""

                verification_results = verify_ai_findings(all_findings, project_root, nvd_vulnerabilities)

                verified_count = sum(1 for v in verification_results if v['verification_level'] != 'potential_hallucination')
                hallucination_count = sum(1 for v in verification_results if v['is_hallucination'])

                triple_verified = sum(1 for v in verification_results if v['verification_level'] == 'triple_verified')
                double_verified = sum(1 for v in verification_results if v['verification_level'] == 'double_verified')
                single_verified = sum(1 for v in verification_results if v['verification_level'] == 'single_verified')

                print(f"[DEBUG] [Triple Verification] Path/Code verification results:")
                print(f"[DEBUG]   - Total findings: {len(all_findings)}")
                print(f"[DEBUG]   - Triple verified: {triple_verified}")
                print(f"[DEBUG]   - Double verified: {double_verified}")
                print(f"[DEBUG]   - Single verified: {single_verified}")
                print(f"[DEBUG]   - Needs review: {len(all_findings) - verified_count - hallucination_count}")
                print(f"[DEBUG]   - Potential hallucinations: {hallucination_count}")

                if hallucination_count > 0:
                    print(f"[DEBUG] [Triple Verification] Potential hallucinations detected:")
                    hallucinated_indices = set()
                    for i, v in enumerate(verification_results):
                        if v['is_hallucination']:
                            finding = all_findings[i]
                            hallucinated_indices.add(i)
                            print(f"[DEBUG]   - [{finding.rule_name}] confidence: {v['confidence']:.2f}, reason: file path or code not verified")

                    filtered_results = []
                    flat_index = 0
                    for file_findings in results:
                        filtered_file_findings = []
                        for finding in file_findings:
                            if flat_index not in hallucinated_indices:
                                filtered_file_findings.append(finding)
                            flat_index += 1
                        filtered_results.append(filtered_file_findings)
                    results = filtered_results
                    print(f"[DEBUG] [Triple Verification] Filtered out {hallucination_count} hallucinated findings, remaining: {sum(len(f) for f in results)}")

        except Exception as e:
            print(f"[DEBUG] [Triple Verification] File path verification failed: {e}")

        elapsed_time = time.time() - start_time
        print(f"[DEBUG] Smart layered scan completed: {total_files} files, {elapsed_time:.2f}s")
        print(f"[DEBUG]   - AI analyzed: {len(suspicious_files)} files")
        print(f"[DEBUG]   - Skipped AI: {len(safe_files)} files")

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
                    console.print(f"[red][X] 纯AI分析器初始化失败，无法恢复扫描[/red]")
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
                    console.print(f"[red][X] 恢复处理文件失败 {file_info.path}: {e}[/red]")
                    results.append([])
                    continue

            if self.config.debug:
                console.print(f"[dim][DEBUG] 断点恢复完成，共处理 {len(processed_files)} 个文件[/dim]")

            return results

        except Exception as e:
            console.print(f"[red][X] 断点恢复失败: {e}[/red]")
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
            console.print(f"[red][X] 增量扫描失败: {e}[/red]")
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
