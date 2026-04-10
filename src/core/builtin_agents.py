"""内置 Agent 实现

包含所有核心 Agent 的实现，这些 Agent 包装了现有的功能模块，
使其符合统一的 BaseAgent 接口规范。
"""

import asyncio
from typing import Any, Dict, List, Optional

from src.core.base_agent import (
    BaseAgent,
    PureAIAgentMixin,
    ExecutionContext,
    AgentResult,
    AgentStatus,
    AgentCapabilities
)
from src.core.config import Config


class ScannerAgent(BaseAgent, PureAIAgentMixin):
    """代码扫描 Agent

    包装现有的 SecurityScanner，提供代码扫描功能。
    这是 Pipeline 的第一个步骤，为后续 Agent 提供基础数据。
    """

    def _define_capabilities(self) -> AgentCapabilities:
        return AgentCapabilities(
            name="scan",
            description="代码扫描 - 检测安全漏洞和代码问题",
            input_types=["code", "directory"],
            output_types=["scan_result", "findings"],
            supported_modes=["standard", "pure-ai"],
            estimated_time=30.0
        )

    async def execute(self, context: ExecutionContext) -> AgentResult:
        """执行代码扫描"""
        try:
            from src.core.scanner import create_scanner

            config = context.config or Config()
            scanner = create_scanner(config)

            if hasattr(scanner, 'scan_sync'):
                result = await asyncio.to_thread(
                    scanner.scan_sync,
                    context.target
                )
            else:
                result = await asyncio.to_thread(
                    scanner.scan,
                    context.target
                )

            findings = []
            if hasattr(result, 'findings') and result.findings:
                for finding in result.findings[:20]:  # 限制数量
                    findings.append({
                        'rule_id': getattr(finding, 'rule_id', ''),
                        'rule_name': getattr(finding, 'rule_name', ''),
                        'severity': getattr(finding, 'severity', {}).value if hasattr(getattr(finding, 'severity', None), 'value') else str(getattr(finding, 'severity', 'unknown')),
                        'message': getattr(finding, 'message', ''),
                        'file': getattr(finding, 'location', {}).get('file', '') if hasattr(getattr(finding, 'location', None), 'get') else '',
                        'line': getattr(finding, 'location', {}).get('line', 0) if hasattr(getattr(finding, 'location', None), 'get') else 0
                    })

            summary = {}
            if hasattr(result, 'to_dict'):
                summary = result.to_dict().get('summary', {})

            return AgentResult(
                agent_name="scan",
                status=AgentStatus.COMPLETED,
                data={
                    'result': result,
                    'summary': summary,
                    'findings_count': len(findings)
                },
                message=f"扫描完成，发现 {len(findings)} 个问题",
                confidence=0.9 if findings else 1.0,
                findings=findings,
                metadata={
                    'target': context.target,
                    'has_findings': len(findings) > 0
                }
            )

        except Exception as e:
            return AgentResult(
                agent_name="scan",
                status=AgentStatus.FAILED,
                error=f"扫描失败: {str(e)}",
                confidence=0.0
            )


class ReasoningAgent(BaseAgent, PureAIAgentMixin):
    """漏洞推理 Agent

    包装现有的语义分析功能，对扫描结果进行深度推理分析。
    依赖 ScannerAgent 的输出。
    """

    def _define_capabilities(self) -> AgentCapabilities:
        return AgentCapabilities(
            name="reason",
            description="漏洞推理分析 - 深度分析漏洞原因和影响",
            input_types=["scan_result"],
            output_types=["analysis", "reasoning"],
            supported_modes=["standard", "pure-ai", "langgraph"],
            estimated_time=45.0
        )

    def validate_input(self, context: ExecutionContext) -> bool:
        scan_result = context.get_previous_result("scan")
        return scan_result is not None and scan_result.is_success

    async def execute(self, context: ExecutionContext) -> AgentResult:
        """执行漏洞推理分析"""
        try:
            scan_result = context.get_previous_result("scan")
            if not scan_result or not scan_result.is_success:
                return AgentResult(
                    agent_name="reason",
                    status=AgentStatus.FAILED,
                    error="缺少有效的扫描结果",
                    confidence=0.0
                )

            config = context.config or Config()

            if config.pure_ai or getattr(config, 'pure_ai', False):
                return await self._execute_pure_ai_mode(context, scan_result)
            else:
                return await self._execute_standard_mode(context, scan_result)

        except Exception as e:
            return AgentResult(
                agent_name="reason",
                status=AgentStatus.FAILED,
                error=f"推理分析失败: {str(e)}",
                confidence=0.0
            )

    async def _execute_standard_mode(
        self,
        context: ExecutionContext,
        scan_result: AgentResult
    ) -> AgentResult:
        """标准模式：使用现有 SemanticAgent"""
        from src.ai.reasoning.semantic_agent import SemanticAgent

        semantic_agent = SemanticAgent()

        code = context.code or ""
        evidence = scan_result.data.get('findings', []) if scan_result.data else []

        analysis = await asyncio.to_thread(
            semantic_agent.analyze,
            code=code,
            evidence=evidence,
            taint_paths=[],
            cve_patterns=[]
        )

        return AgentResult(
            agent_name="reason",
            status=AgentStatus.COMPLETED,
            data={'analysis': analysis},
            message="推理分析完成",
            confidence=getattr(analysis, 'confidence', 0.7) if analysis else 0.5,
            metadata={'mode': 'standard'}
        )

    async def _execute_pure_ai_mode(
        self,
        context: ExecutionContext,
        scan_result: AgentResult
    ) -> AgentResult:
        """纯 AI 模式：使用 AI 进行深度分析"""
        try:
            from src.ai.client import get_model_manager

            config = context.config or Config()
            model_manager = await get_model_manager(config)
            client = model_manager.get_default_client()

            if not client:
                raise RuntimeError("AI 客户端不可用")

            findings_text = "\n".join([
                f"- [{f.get('severity', '?')}] {f.get('rule_name', '')}: {f.get('message', '')}"
                for f in (scan_result.findings or [])[:10]
            ])

            prompt = f"""作为安全专家，请深度分析以下代码扫描结果：

目标: {context.target}
发现的问题:
{findings_text}

请提供：
1. 漏洞根因分析
2. 攻击场景描述
3. 影响范围评估
4. 修复建议优先级"""

            response = await client.generate(prompt)

            return AgentResult(
                agent_name="reason",
                status=AgentStatus.COMPLETED,
                data={'analysis': {'text': response}},
                message="AI 推理分析完成",
                confidence=0.85,
                metadata={'mode': 'pure-ai'}
            )

        except Exception as e:
            return AgentResult(
                agent_name="reason",
                status=AgentStatus.FAILED,
                error=f"纯AI模式失败: {str(e)}，回退到标准模式",
                confidence=0.0
            )


class POCGeneratorAgent(BaseAgent, PureAIAgentMixin):
    """POC 生成 Agent

    为发现的漏洞生成概念验证利用代码。
    依赖 ReasoningAgent 的分析结果。
    """

    def _define_capabilities(self) -> AgentCapabilities:
        return AgentCapabilities(
            name="poc",
            description="POC 生成 - 生成漏洞利用代码",
            input_types=["analysis", "findings"],
            output_types=["exploit_code", "poc"],
            supported_modes=["standard", "pure-ai"],
            estimated_time=60.0
        )

    def validate_input(self, context: ExecutionContext) -> bool:
        reason_result = context.get_previous_result("reason")
        return reason_result is not None and reason_result.is_success

    async def execute(self, context: ExecutionContext) -> AgentResult:
        """执行 POC 生成"""
        try:
            reason_result = context.get_previous_result("reason")
            scan_result = context.get_previous_result("scan")

            if not reason_result or not reason_result.is_success:
                return AgentResult(
                    agent_name="poc",
                    status=AgentStatus.FAILED,
                    error="缺少有效的分析结果",
                    confidence=0.0
                )

            config = context.config or Config()

            if config.pure_ai or getattr(config, 'pure_ai', False):
                return await self._generate_with_ai(context, scan_result, reason_result)
            else:
                return await self._generate_standard(context, scan_result)

        except Exception as e:
            return AgentResult(
                agent_name="poc",
                status=AgentStatus.FAILED,
                error=f"POC生成失败: {str(e)}",
                confidence=0.0
            )

    async def _generate_standard(
        self,
        context: ExecutionContext,
        scan_result: Optional[AgentResult]
    ) -> AgentResult:
        """标准模式：使用 ExploitGenerator"""
        from src.exploit.generator import ExploitGenerator

        config = context.config or Config()
        generator = ExploitGenerator(config)

        exploits = []
        findings = scan_result.findings if scan_result else []

        for finding in findings[:3]:
            try:
                exploit = await asyncio.to_thread(generator.generate, finding)
                if exploit:
                    exploits.append({
                        'vulnerability': getattr(finding, 'message', str(finding)),
                        'exploit_code': str(exploit)[:500]  # 截断长代码
                    })
            except Exception:
                continue

        return AgentResult(
            agent_name="poc",
            status=AgentStatus.COMPLETED,
            data={'exploits': exploits},
            message=f"生成了 {len(exploits)} 个POC",
            confidence=0.7 if exploits else 0.3,
            findings=exploits,
            metadata={'mode': 'standard'}
        )

    async def _generate_with_ai(
        self,
        context: ExecutionContext,
        scan_result: Optional[AgentResult],
        reason_result: AgentResult
    ) -> AgentResult:
        """纯 AI 模式：使用 AI 生成 POC"""
        try:
            from src.ai.client import get_model_manager

            config = context.config or Config()
            model_manager = await get_model_manager(config)
            client = model_manager.get_default_client()

            if not client:
                raise RuntimeError("AI 客户端不可用")

            findings_summary = "\n".join([
                f"- {f.get('message', '')}" for f in (scan_result.findings or [])[:5]
            ])

            prompt = f"""基于以下漏洞信息，生成安全的POC验证代码（仅用于安全测试）：

发现的问题:
{findings_summary}

分析结果:
{str(reason_result.data.get('analysis', {}))[:500] if reason_result.data else ''}

要求：
1. 仅生成概念性验证代码（不造成实际危害）
2. 包含详细注释说明
3. 标注风险等级和影响"""

            poc_code = await client.generate(prompt)

            return AgentResult(
                agent_name="poc",
                status=AgentStatus.COMPLETED,
                data={'exploits': [{'exploit_code': poc_code}]},
                message="AI POC 生成完成",
                confidence=0.8,
                metadata={'mode': 'pure-ai'}
            )

        except Exception as e:
            return AgentResult(
                agent_name="poc",
                status=AgentStatus.FAILED,
                error=f"AI POC生成失败: {str(e)}",
                confidence=0.0
            )


class ReportGeneratorAgent(BaseAgent):
    """报告生成 Agent

    生成最终的安全扫描报告。
    可以在 Pipeline 的任何阶段之后运行。
    """

    def _define_capabilities(self) -> AgentCapabilities:
        return AgentCapabilities(
            name="report",
            description="报告生成 - 生成安全扫描报告",
            input_types=["scan_result", "analysis", "poc"],
            output_types=["report_html", "report_json"],
            supported_modes=["standard", "pure-ai"],
            estimated_time=10.0
        )

    async def execute(self, context: ExecutionContext) -> AgentResult:
        """生成报告"""
        try:
            all_results = context.get_all_results()

            report_data = {
                'pipeline_used': list(all_results.keys()),
                'timestamp': __import__('datetime').datetime.now().isoformat(),
                'target': context.target,
                'agents_results': {
                    name: result.to_dict()
                    for name, result in all_results.items()
                }
            }

            all_findings = []
            for result in all_results.values():
                if result.findings:
                    all_findings.extend(result.findings)

            report_data['total_findings'] = len(all_findings)
            report_data['summary'] = self._generate_summary(all_results, all_findings)

            return AgentResult(
                agent_name="report",
                status=AgentStatus.COMPLETED,
                data={'report': report_data},
                message=f"报告生成完成，共 {len(all_findings)} 个问题",
                confidence=1.0,
                findings=all_findings,
                metadata={'format': 'internal'}
            )

        except Exception as e:
            return AgentResult(
                agent_name="report",
                status=AgentStatus.FAILED,
                error=f"报告生成失败: {str(e)}",
                confidence=0.0
            )

    def _generate_summary(self, results: Dict, findings: List) -> Dict:
        """生成摘要信息"""
        severity_counts = {}
        for finding in findings:
            sev = finding.get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            'total_agents_executed': len(results),
            'total_findings': len(findings),
            'by_severity': severity_counts,
            'success_rate': sum(1 for r in results.values() if r.is_success) / max(len(results), 1)
        }


class AttackChainAgent(BaseAgent, PureAIAgentMixin):
    """攻击链分析 Agent

    分析漏洞之间的关联关系，构建完整的攻击路径。
    """

    def _define_capabilities(self) -> AgentCapabilities:
        return AgentCapabilities(
            name="attack-chain",
            description="攻击链分析 - 构建完整攻击路径",
            input_types=["analysis", "findings"],
            output_types=["attack_graph", "attack_path"],
            supported_modes=["standard", "pure-ai", "langgraph"],
            estimated_time=40.0
        )

    def validate_input(self, context: ExecutionContext) -> bool:
        reason_result = context.get_previous_result("reason")
        return reason_result is not None and reason_result.is_success

    async def execute(self, context: ExecutionContext) -> AgentResult:
        """执行攻击链分析"""
        try:
            from src.ai.reasoning.attack_agent import AttackAgent

            attack_agent = AttackAgent()

            taint_paths = []
            evidence = []

            scan_result = context.get_previous_result("scan")
            if scan_result and scan_result.data:
                evidence = scan_result.data.get('findings', [])

            attack_chains = await asyncio.to_thread(
                attack_agent.generate_attack_chains,
                taint_paths=taint_paths,
                evidence=evidence
            )

            chains_data = []
            if attack_chains:
                for chain in attack_chains[:5]:
                    chains_data.append({
                        'vulnerability_type': getattr(chain, 'vulnerability_type', 'Unknown'),
                        'impact': getattr(chain, 'impact', 'Medium'),
                        'confidence': getattr(chain, 'confidence', 0.5),
                        'path': getattr(chain, 'path', [])
                    })

            return AgentResult(
                agent_name="attack-chain",
                status=AgentStatus.COMPLETED,
                data={'attack_chains': chains_data},
                message=f"识别出 {len(chains_data)} 条潜在攻击链",
                confidence=0.75 if chains_data else 0.4,
                findings=chains_data,
                metadata={'chains_count': len(chains_data)}
            )

        except Exception as e:
            return AgentResult(
                agent_name="attack-chain",
                status=AgentStatus.FAILED,
                error=f"攻击链分析失败: {str(e)}",
                confidence=0.0
            )
