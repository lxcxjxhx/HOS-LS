import asyncio
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from src.ai.pure_ai.context_builder import ContextBuilder
from src.ai.pure_ai.prompt_templates import PromptTemplates
from src.ai.pure_ai.schema_validator import SchemaValidator
from src.ai.models import AIRequest
from src.ai.token_tracker import get_token_tracker
from src.ai.pure_ai.schema import SignalState

console = Console()

class SemanticConsistencyError(Exception):
    """语义一致性异常"""
    pass

class EvidenceChain:
    """证据链追踪器"""

    def __init__(self):
        self.signals: Dict[str, Dict[str, Any]] = {}
        self.evidence_chain: Dict[str, List[Dict[str, Any]]] = {}

    def add_signal(self, signal_id: str, signal_type: str, agent: str, state: str, evidence: List[Dict[str, Any]]):
        """添加信号

        Args:
            signal_id: 信号ID
            signal_type: 信号类型
            agent: 来源Agent
            state: 信号状态
            evidence: 证据列表
        """
        if signal_id not in self.signals:
            self.signals[signal_id] = {
                'signal_id': signal_id,
                'signal_type': signal_type,
                'original_agent': agent,
                'current_state': state,
                'state_history': [(agent, state)]
            }
            self.evidence_chain[signal_id] = []

        self.signals[signal_id]['current_state'] = state
        self.signals[signal_id]['state_history'].append((agent, state))
        self.evidence_chain[signal_id].extend(evidence)

    def update_signal_state(self, signal_id: str, agent: str, new_state: str, evidence: List[Dict[str, Any]], confidence_change: float = None, reason: str = None):
        """更新信号状态

        Args:
            signal_id: 信号ID
            agent: 更新Agent
            new_state: 新状态
            evidence: 新证据
            confidence_change: 置信度变化（可选）
            reason: 状态转换原因（可选）
        """
        if signal_id in self.signals:
            old_state = self.signals[signal_id]['current_state']
            self.signals[signal_id]['current_state'] = new_state
            self.signals[signal_id]['state_history'].append((agent, new_state))
            self.evidence_chain[signal_id].extend(evidence)

            log_parts = [f"[DEBUG] Signal {signal_id} state: {old_state} -> {new_state} by {agent}"]
            if confidence_change is not None:
                log_parts.append(f"(confidence: {confidence_change:+.2f})")
            if reason:
                log_parts.append(f"reason: {reason}")
            print(" ".join(log_parts))

    def get_signal(self, signal_id: str) -> Optional[Dict[str, Any]]:
        """获取信号"""
        return self.signals.get(signal_id)

    def get_evidence_chain(self, signal_id: str) -> List[Dict[str, Any]]:
        """获取信号证据链"""
        return self.evidence_chain.get(signal_id, [])

    def get_all_signals(self) -> Dict[str, Dict[str, Any]]:
        """获取所有信号"""
        return self.signals

    def validate_state_transition(self, signal_id: str, from_state: str, to_state: str) -> bool:
        """验证状态转换是否合法

        Args:
            signal_id: 信号ID
            from_state: 原始状态
            to_state: 目标状态

        Returns:
            是否合法
        """
        valid_transitions = {
            SignalState.NEW.value: [SignalState.CONFIRMED.value, SignalState.REJECTED.value, SignalState.REFINED.value, SignalState.UNCERTAIN.value],
            SignalState.CONFIRMED.value: [SignalState.REJECTED.value, SignalState.UNCERTAIN.value],
            SignalState.REFINED.value: [SignalState.CONFIRMED.value, SignalState.REJECTED.value, SignalState.UNCERTAIN.value],
            SignalState.UNCERTAIN.value: [SignalState.CONFIRMED.value, SignalState.REJECTED.value],
            SignalState.REJECTED.value: [],
        }

        allowed = valid_transitions.get(from_state, [])
        return to_state in allowed

class MultiAgentPipeline:
    """多Agent流水线系统

    协调6个专业Agent完成代码安全分析
    """

    def __init__(self, client, config: Optional[Any] = None):
        """初始化多Agent流水线

        Args:
            client: AI客户端
            config: 配置参数
        """
        self.client = client
        self.config = config
        self.context_builder = ContextBuilder(config)
        self.prompt_templates = PromptTemplates()
        self.token_tracker = get_token_tracker()
        self.checkpoint_callback = None
        self._processed_files = []
        self._current_step = None
        self._agent_timings = {}
        self.evidence_chain_tracker = EvidenceChain()
        self.schema_validator = SchemaValidator()
        self.debug_logs: List[str] = []
        if hasattr(config, 'get'):
            self.max_retries = config.get('max_retries', 3)
            self.model = config.get('model', 'deepseek-reasoner')
        else:
            self.max_retries = getattr(config, 'max_retries', 3)
            self.model = getattr(config, 'ai', {}).get('model', 'deepseek-reasoner') if hasattr(config, 'ai') else 'deepseek-reasoner'

    def set_checkpoint_callback(self, callback) -> None:
        """设置检查点回调函数

        Args:
            callback: 回调函数，签名: callback(checkpoint_data)
        """
        self.checkpoint_callback = callback

    def get_state(self) -> Dict[str, Any]:
        """获取流水线状态用于序列化

        Returns:
            包含当前状态的字典
        """
        return {
            'agent_timings': self._agent_timings if hasattr(self, '_agent_timings') else {},
            'current_step': self._current_step if hasattr(self, '_current_step') else None,
            'processed_files': self._processed_files if hasattr(self, '_processed_files') else [],
            'timestamp': time.time()
        }

    def set_state(self, state: Dict[str, Any]) -> None:
        """从序列化状态恢复

        Args:
            state: 包含之前状态的字典
        """
        if 'agent_timings' in state:
            self._agent_timings = state['agent_timings']
        if 'current_step' in state:
            self._current_step = state['current_step']
        if 'processed_files' in state:
            self._processed_files = state['processed_files']

    def _trigger_checkpoint_callback(self, step: str, data: Dict[str, Any]) -> None:
        """触发检查点回调

        Args:
            step: 当前步骤名称
            data: 步骤数据
        """
        if self.checkpoint_callback:
            try:
                self.checkpoint_callback({
                    'step': step,
                    'data': data,
                    'state': self.get_state(),
                    'timestamp': time.time()
                })
            except Exception as e:
                console.print(f"[yellow]检查点回调失败: {e}[/yellow]")

    async def run_pipeline(self, file_path: str) -> Dict[str, Any]:
        """运行完整的多Agent流水线

        Args:
            file_path: 文件路径

        Returns:
            分析结果
        """
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

        try:
            print(f"[DEBUG] 开始运行多Agent流水线: {file_path}")
            total_start_time = time.time()
            self._agent_timings = {}
            self._current_step = 'started'
            self._current_file_path = file_path
            self.evidence_chain_tracker = EvidenceChain()
            total_token_usage = {
                'prompt_tokens': 0,
                'completion_tokens': 0,
                'total_tokens': 0
            }

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
                refresh_per_second=1
            ) as progress:
                main_task = progress.add_task(f"[cyan]分析: {Path(file_path).name}[/cyan]", total=7)

                start_time = time.time()
                context = self.context_builder.build_context(file_path)
                elapsed = time.time() - start_time
                self._agent_timings['context_build'] = elapsed
                self._current_step = 'context_build'
                self._trigger_checkpoint_callback('context_build', {'elapsed': elapsed})
                progress.advance(main_task)

                start_time = time.time()
                context_analysis, token_usage = await self._run_agent_0(file_path, context)
                elapsed = time.time() - start_time
                self._agent_timings['agent_0'] = elapsed
                self._current_step = 'agent_0'
                self._trigger_checkpoint_callback('agent_0', {'elapsed': elapsed, 'token_usage': token_usage})
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)

                start_time = time.time()
                code_understanding, token_usage = await self._run_agent_1(file_path, context, context_analysis)
                elapsed = time.time() - start_time
                self._agent_timings['agent_1'] = elapsed
                self._current_step = 'agent_1'
                self._trigger_checkpoint_callback('agent_1', {'elapsed': elapsed, 'token_usage': token_usage})
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)

                start_time = time.time()
                risk_enumeration, token_usage = await self._run_agent_2(file_path, code_understanding)
                elapsed = time.time() - start_time
                self._agent_timings['agent_2'] = elapsed
                self._current_step = 'agent_2'
                self._trigger_checkpoint_callback('agent_2', {'elapsed': elapsed, 'token_usage': token_usage})
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                self._track_risk_signals(risk_enumeration)
                progress.advance(main_task)

                start_time = time.time()
                vulnerability_verification, token_usage = await self._run_agent_3(file_path, risk_enumeration, context['file_content'])
                elapsed = time.time() - start_time
                self._agent_timings['agent_3'] = elapsed
                self._current_step = 'agent_3'
                self._trigger_checkpoint_callback('agent_3', {'elapsed': elapsed, 'token_usage': token_usage})
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                self._track_verification_signals(vulnerability_verification)
                self._check_semantic_consistency('agent_2_to_3', risk_enumeration, vulnerability_verification)
                progress.advance(main_task)

                start_time = time.time()
                attack_chain_analysis, token_usage = await self._run_agent_4(file_path, vulnerability_verification)
                elapsed = time.time() - start_time
                self._agent_timings['agent_4'] = elapsed
                self._current_step = 'agent_4'
                self._trigger_checkpoint_callback('agent_4', {'elapsed': elapsed, 'token_usage': token_usage})
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                self._track_attack_chain_signals(attack_chain_analysis)
                progress.advance(main_task)

                start_time = time.time()
                adversarial_validation, token_usage = await self._run_agent_5(file_path, attack_chain_analysis, context['file_content'])
                elapsed = time.time() - start_time
                self._agent_timings['agent_5'] = elapsed
                self._current_step = 'agent_5'
                self._trigger_checkpoint_callback('agent_5', {'elapsed': elapsed, 'token_usage': token_usage})
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                self._track_adversarial_signals(adversarial_validation)
                self._check_semantic_consistency('agent_4_to_5', attack_chain_analysis, adversarial_validation)
                progress.advance(main_task)

                start_time = time.time()
                final_decision, token_usage = await self._run_agent_6(file_path, adversarial_validation, vulnerability_verification)
                elapsed = time.time() - start_time
                self._agent_timings['agent_6'] = elapsed
                self._current_step = 'agent_6'
                self._trigger_checkpoint_callback('agent_6', {'elapsed': elapsed, 'token_usage': token_usage})
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)

            total_elapsed = time.time() - total_start_time
            self._current_step = 'completed'
            self._trigger_checkpoint_callback('pipeline_completed', {
                'total_elapsed': total_elapsed,
                'total_token_usage': total_token_usage,
                'agent_timings': self._agent_timings,
                'signal_summary': self._get_signal_summary()
            })
            if file_path not in self._processed_files:
                self._processed_files.append(file_path)
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [bold green]✓ {Path(file_path).name} 分析完成[/bold green] [dim]({total_elapsed:.2f}s)[/dim]")

            if total_token_usage['total_tokens'] > 0:
                avg_tokens_per_agent = total_token_usage['total_tokens'] / 6 if 6 > 0 else 0
                console.print(f"[dim]  📊 Token: {total_token_usage['total_tokens']:,} (提示词: {total_token_usage['prompt_tokens']:,}, 补全: {total_token_usage['completion_tokens']:,})[/dim]")

            return {
                'file_path': file_path,
                'context_analysis': context_analysis,
                'code_understanding': code_understanding,
                'risk_enumeration': risk_enumeration,
                'vulnerability_verification': vulnerability_verification,
                'attack_chain_analysis': attack_chain_analysis,
                'adversarial_validation': adversarial_validation,
                'final_decision': final_decision,
                'evidence_chain': self._get_signal_summary(),
                'debug_logs': self.debug_logs
            }
        except Exception as e:
            self._current_step = 'error'
            self._trigger_checkpoint_callback('pipeline_error', {'error': str(e)})
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [bold red]✗ {Path(file_path).name} 分析失败: {e}[/bold red]")
            import traceback
            traceback.print_exc()
            return {
                'file_path': file_path,
                'error': str(e)
            }

    def _track_risk_signals(self, risk_enumeration: Dict[str, Any]) -> None:
        """追踪风险信号"""
        risks = risk_enumeration.get('risks', [])
        for risk in risks:
            signal_id = risk.get('signal_id', '')
            if signal_id:
                evidence = risk.get('evidence', [])
                self.evidence_chain_tracker.add_signal(
                    signal_id=signal_id,
                    signal_type='risk',
                    agent='Agent-2',
                    state=risk.get('signal_state', SignalState.NEW.value),
                    evidence=evidence
                )
                print(f"[DEBUG] Added risk signal: {signal_id}")

    def _track_verification_signals(self, vulnerability_verification: Dict[str, Any]) -> None:
        """追踪验证信号"""
        vulnerabilities = vulnerability_verification.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            signal_id = vuln.get('signal_id', '')
            if signal_id:
                evidence = vuln.get('evidence', [])
                new_state = vuln.get('signal_state', SignalState.NEW.value)
                verification_decision = vuln.get('verification_decision', '')
                verification_reason = vuln.get('verification_reason', '')
                old_signal = self.evidence_chain_tracker.get_signal(signal_id)
                if old_signal:
                    old_confidence = self._get_avg_confidence(old_signal.get('evidence_chain', []))
                    new_confidence = self._get_avg_confidence(evidence)
                    confidence_change = new_confidence - old_confidence if old_confidence and new_confidence else None

                    self.evidence_chain_tracker.update_signal_state(
                        signal_id=signal_id,
                        agent='Agent-3',
                        new_state=new_state,
                        evidence=evidence,
                        confidence_change=confidence_change,
                        reason=f"verification_decision={verification_decision}, reason={verification_reason}"
                    )
                    print(f"[DEBUG] Updated verification signal: {signal_id} -> {new_state}")

    def _track_attack_chain_signals(self, attack_chain_analysis: Dict[str, Any]) -> None:
        """追踪攻击链信号"""
        chains = attack_chain_analysis.get('attack_chains', [])
        for chain in chains:
            signal_id = chain.get('signal_id', '')
            if signal_id:
                evidence = chain.get('evidence', [])
                self.evidence_chain_tracker.add_signal(
                    signal_id=signal_id,
                    signal_type='attack_chain',
                    agent='Agent-4',
                    state=chain.get('signal_state', SignalState.NEW.value),
                    evidence=evidence
                )
                print(f"[DEBUG] Added attack chain signal: {signal_id}")

    def _track_adversarial_signals(self, adversarial_validation: Dict[str, Any]) -> None:
        """追踪对抗验证信号"""
        analysis = adversarial_validation.get('adversarial_analysis', [])
        for item in analysis:
            challenged_id = item.get('challenged_signal_id', '')
            if challenged_id:
                evidence = item.get('evidence', [])
                verdict = item.get('verdict', 'UNCERTAIN')
                reason = item.get('reason', '')
                state_mapping = {
                    'ACCEPT': SignalState.CONFIRMED.value,
                    'REFUTE': SignalState.REJECTED.value,
                    'ESCALATE': SignalState.UNCERTAIN.value,
                    'UNCERTAIN': SignalState.UNCERTAIN.value
                }
                new_state = state_mapping.get(verdict, SignalState.UNCERTAIN.value)
                old_signal = self.evidence_chain_tracker.get_signal(challenged_id)
                old_confidence = self._get_avg_confidence(old_signal.get('evidence_chain', [])) if old_signal else None
                new_confidence = self._get_avg_confidence(evidence)
                confidence_change = new_confidence - old_confidence if old_confidence and new_confidence else None

                self.evidence_chain_tracker.update_signal_state(
                    signal_id=challenged_id,
                    agent='Agent-5',
                    new_state=new_state,
                    evidence=evidence,
                    confidence_change=confidence_change,
                    reason=f"verdict={verdict}, reason={reason}"
                )
                print(f"[DEBUG] Updated adversarial signal: {challenged_id} -> {new_state}")

    def _check_semantic_consistency(self, check_name: str, upstream: Dict[str, Any], downstream: Dict[str, Any]) -> None:
        """检查语义一致性

        Args:
            check_name: 检查名称
            upstream: 上游输出
            downstream: 下游输出
        """
        print(f"[DEBUG] Running semantic consistency check: {check_name}")

        if check_name == 'agent_2_to_3':
            upstream_signals = set(r.get('signal_id', '') for r in upstream.get('risks', []))
            downstream_signals = set(v.get('signal_id', '') for v in downstream.get('vulnerabilities', []))

            missing_signals = upstream_signals - downstream_signals
            if missing_signals:
                print(f"[WARN] Semantic gap detected: signals in Agent-2 but not in Agent-3: {missing_signals}")
                print(f"[DEBUG] Agent-2 produced {len(upstream_signals)} signals, Agent-3 consumed {len(downstream_signals)} signals")
                self._fill_missing_signals_via_refinement(missing_signals, downstream, 'risk')
                downstream_signals = set(v.get('signal_id', '') for v in downstream.get('vulnerabilities', []))
                remaining_gaps = upstream_signals - downstream_signals
                if remaining_gaps:
                    print(f"[WARN] After refinement, still missing signals: {remaining_gaps}")

        elif check_name == 'agent_4_to_5':
            upstream_signals = set(c.get('signal_id', '') for c in upstream.get('attack_chains', []))
            downstream_signals = set(a.get('challenged_signal_id', '') for a in downstream.get('adversarial_analysis', []))

            missing_signals = upstream_signals - downstream_signals
            if missing_signals:
                print(f"[WARN] Semantic gap detected: signals in Agent-4 but not in Agent-5: {missing_signals}")
                print(f"[DEBUG] Agent-4 produced {len(upstream_signals)} signals, Agent-5 consumed {len(downstream_signals)} signals")
                self._fill_missing_signals_via_refinement(missing_signals, downstream, 'attack_chain')

    def _fill_missing_signals_via_refinement(self, missing_signals: set, downstream: Dict[str, Any], signal_type: str) -> None:
        """通过添加REFINED状态的信号来填补语义鸿沟

        Args:
            missing_signals: 缺失的信号ID集合
            downstream: 下游输出（将被修改）
            signal_type: 信号类型 ('risk' 或 'attack_chain')
        """
        if signal_type == 'risk':
            vulnerabilities = downstream.get('vulnerabilities', [])
            for signal_id in missing_signals:
                if signal_id not in [v.get('signal_id', '') for v in vulnerabilities]:
                    vulnerabilities.append({
                        'title': 'WEAK_SECURITY_SIGNAL',
                        'severity': 'MEDIUM',
                        'location': 'Unknown (refined from upstream)',
                        'evidence': [{
                            'type': 'code_line',
                            'location': 'N/A',
                            'reason': f'Signal {signal_id} was not processed by downstream agent',
                            'confidence': 0.3
                        }],
                        'cwe_id': '',
                        'cvss_score': '',
                        'signal_id': signal_id,
                        'signal_state': 'REFINED',
                        'verification_decision': 'REFINED',
                        'verification_reason': 'Signal inherited from upstream due to semantic gap'
                    })
                    print(f"[DEBUG] Filled missing signal {signal_id} with REFINED status")
            downstream['vulnerabilities'] = vulnerabilities

    def _get_signal_summary(self) -> Dict[str, Any]:
        """获取信号摘要"""
        signals = self.evidence_chain_tracker.get_all_signals()
        summary = {
            'total_signals': len(signals),
            'by_state': {},
            'by_type': {}
        }
        for signal_id, signal_data in signals.items():
            state = signal_data.get('current_state', 'UNKNOWN')
            signal_type = signal_data.get('signal_type', 'unknown')
            summary['by_state'][state] = summary['by_state'].get(state, 0) + 1
            summary['by_type'][signal_type] = summary['by_type'].get(signal_type, 0) + 1

        print(f"[DEBUG] Signal summary: {summary}")
        return summary

    def _get_avg_confidence(self, evidence_list: List[Dict[str, Any]]) -> Optional[float]:
        """计算证据列表的平均置信度

        Args:
            evidence_list: 证据列表

        Returns:
            平均置信度或None
        """
        if not evidence_list:
            return None
        confidences = [e.get('confidence', 0) for e in evidence_list if isinstance(e, dict) and 'confidence' in e]
        if not confidences:
            return None
        return sum(confidences) / len(confidences)
    
    async def _run_agent_0(self, file_path: str, context: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 0：上下文构建

        Args:
            file_path: 文件路径
            context: 上下文信息

        Returns:
            (上下文分析结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 0 (上下文构建) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 0 (上下文构建) on: {file_path}")
        prompt = self.prompt_templates.AGENT_0_CONTEXT_BUILDER.format(
            file_path=file_path,
            file_content=context['file_content'],
            related_files=self.prompt_templates.format_related_files(context['related_files']),
            imports=self.prompt_templates.format_imports(context['imports']),
            function_calls=self.prompt_templates.format_function_calls(context['function_calls'])
        )
        
        response, token_usage = await self._generate_with_retry(prompt, "Agent 0", temperature=0.2)
        result = self._parse_json_response(response, schema_name="context_analysis")
        print(f"[DEBUG] Agent 0 完成，token使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 0 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_1(self, file_path: str, context: Dict[str, Any], context_analysis: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 1：代码理解

        Args:
            file_path: 文件路径
            context: 上下文信息
            context_analysis: 上下文分析结果

        Returns:
            (代码理解结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 1 (代码理解) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 1 (代码理解) on: {file_path}")
        context_info = json.dumps(context_analysis, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_1_CODE_UNDERSTANDING.format(
            file_path=file_path,
            file_content=context['file_content'],
            context_info=context_info
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 1", temperature=0.2)
        result = self._parse_json_response(response, schema_name="code_understanding")
        print(f"[DEBUG] Agent 1 完成，token使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 1 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_2(self, file_path: str, code_understanding: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 2：风险枚举

        Args:
            file_path: 文件路径
            code_understanding: 代码理解结果

        Returns:
            (风险枚举结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 2 (风险枚举) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 2 (风险枚举) on: {file_path}")
        structured_data = json.dumps(code_understanding, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_2_RISK_ENUMERATION.format(
            file_path=file_path,
            structured_data=structured_data
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 2", temperature=0.3)
        result = self._parse_json_response(response, schema_name="risk_enumeration")
        print(f"[DEBUG] Agent 2 完成，token使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 2 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_3(self, file_path: str, risk_enumeration: Dict[str, Any], file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 3：漏洞验证

        Args:
            file_path: 文件路径
            risk_enumeration: 风险枚举结果
            file_content: 文件内容

        Returns:
            (漏洞验证结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 3 (漏洞验证) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 3 (漏洞验证) on: {file_path}")
        risk_list = json.dumps(risk_enumeration.get('risks', []), ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_3_VULNERABILITY_VERIFICATION.format(
            file_path=file_path,
            risk_list=risk_list,
            file_content=file_content
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 3", temperature=0.1)
        result = self._parse_json_response(response, schema_name="vulnerability")
        print(f"[DEBUG] Agent 3 完成，token使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 3 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage

    async def _run_agent_4(self, file_path: str, vulnerability_verification: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 4：攻击链分析

        Args:
            file_path: 文件路径
            vulnerability_verification: 漏洞验证结果

        Returns:
            (攻击链分析结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 4 (攻击链分析) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 4 (攻击链分析) on: {file_path}")
        verification_results = json.dumps(vulnerability_verification, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_4_ATTACK_CHAIN_ANALYSIS.format(
            file_path=file_path,
            verification_results=verification_results
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 4", temperature=0.2)
        result = self._parse_json_response(response, schema_name="attack_chain")
        print(f"[DEBUG] Agent 4 完成，token使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 4 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_5(self, file_path: str, attack_chain_analysis: Dict[str, Any], file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 5：对抗验证

        Args:
            file_path: 文件路径
            attack_chain_analysis: 攻击链分析结果
            file_content: 文件内容

        Returns:
            (对抗验证结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 5 (对抗验证) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 5 (对抗验证) on: {file_path}")
        attack_chain_json = json.dumps(attack_chain_analysis, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_5_ADVERSARIAL_VALIDATION.format(
            file_path=file_path,
            attack_chain_analysis=attack_chain_json,
            file_content=file_content
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 5", temperature=0.1)
        result = self._parse_json_response(response, schema_name="adversarial")
        print(f"[DEBUG] Agent 5 完成，token使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 5 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_6(self, file_path: str, adversarial_validation: Dict[str, Any], vulnerability_verification: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 6：最终裁决

        Args:
            file_path: 文件路径
            adversarial_validation: 对抗验证结果
            vulnerability_verification: 漏洞验证结果

        Returns:
            (最终裁决结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 6 (最终裁决) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 6 (最终裁决) on: {file_path}")
        adversarial_results = json.dumps(adversarial_validation, ensure_ascii=False)
        verification_results = json.dumps(vulnerability_verification, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_6_FINAL_DECISION.format(
            file_path=file_path,
            adversarial_results=adversarial_results,
            verification_results=verification_results
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 6", temperature=0.2)
        result = self._parse_json_response(response, schema_name="final_decision")
        print(f"[DEBUG] Agent 6 完成，token使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 6 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _generate_with_retry(self, prompt: str, agent_name: str = "unknown", temperature: float = 0.0) -> Tuple[str, Dict[str, int]]:
        """带重试的生成
        
        Args:
            prompt: 提示词
            agent_name: Agent名称
            temperature: 温度值
            
        Returns:
            (生成的响应, token使用信息)
        """
        for i in range(self.max_retries):
            try:
                # JSON Guard: 在prompt顶部添加JSON输出强制约束
                json_guard_prompt = "只输出JSON，否则视为失败\n\n" + prompt
                
                # 创建AIRequest对象
                request = AIRequest(
                    prompt=json_guard_prompt,
                    model=self.model,
                    temperature=temperature
                )
                
                # 调用客户端生成
                response = await self.client.generate(request)
                
                # 提取token使用信息
                token_usage = {
                    'prompt_tokens': 0,
                    'completion_tokens': 0,
                    'total_tokens': 0
                }
                response_content = ""
                if hasattr(response, 'usage') and response.usage:
                    token_usage['prompt_tokens'] = response.usage.get('prompt_tokens', 0)
                    token_usage['completion_tokens'] = response.usage.get('completion_tokens', 0)
                    token_usage['total_tokens'] = response.usage.get('total_tokens', 0)

                if hasattr(response, 'content'):
                    response_content = response.content
                else:
                    response_content = str(response)

                # 跟踪token使用（包含prompt和response内容）
                self.token_tracker.track_usage(
                    provider=self.client.__class__.__name__,
                    model=self.model,
                    prompt_tokens=token_usage['prompt_tokens'],
                    completion_tokens=token_usage['completion_tokens'],
                    total_tokens=token_usage['total_tokens'],
                    duration=0.0,
                    success=True,
                    prompt=json_guard_prompt,
                    response=response_content,
                    agent_name=agent_name,
                    file_path=getattr(self, '_current_file_path', 'unknown')
                )

                # 返回响应内容和token使用信息
                return response_content, token_usage
                    
            except Exception as e:
                console.print(f"[bold cyan][PURE-AI][/bold cyan] [yellow]生成失败 (Agent: {agent_name}, 尝试 {i+1}/{self.max_retries}): {e}[/yellow]")
                import traceback
                traceback.print_exc()
                if i == self.max_retries - 1:
                    raise
                await asyncio.sleep(1)
    
    def _parse_json_response(self, response: str, schema_name: str = None) -> Dict[str, Any]:
        """解析JSON响应

        Args:
            response: 响应字符串
            schema_name: Schema名称，用于验证

        Returns:
            解析后的JSON对象
        """
        try:
            cleaned_response = response.strip()

            try:
                data = json.loads(cleaned_response)
                if schema_name:
                    validator = SchemaValidator()
                    validated_data = validator.validate_with_fallback(data, schema_name)
                    return validated_data
                return data
            except json.JSONDecodeError:
                pass

            json_match = re.search(r'```json\s*([\s\S]*?)```', cleaned_response)
            if json_match:
                json_str = json_match.group(1).strip()
                try:
                    data = json.loads(json_str)
                    if schema_name:
                        validator = SchemaValidator()
                        validated_data = validator.validate_with_fallback(data, schema_name)
                        return validated_data
                    return data
                except json.JSONDecodeError:
                    pass

            json_match = re.search(r'```\s*([\s\S]*?)```', cleaned_response)
            if json_match:
                json_str = json_match.group(1).strip()
                try:
                    data = json.loads(json_str)
                    if schema_name:
                        validator = SchemaValidator()
                        validated_data = validator.validate_with_fallback(data, schema_name)
                        return validated_data
                    return data
                except json.JSONDecodeError:
                    pass

            json_match = re.search(r'\{[\s\S]*\}', cleaned_response)
            if json_match:
                json_str = json_match.group(0)
                try:
                    data = json.loads(json_str)
                    if schema_name:
                        validator = SchemaValidator()
                        validated_data = validator.validate_with_fallback(data, schema_name)
                        return validated_data
                    return data
                except json.JSONDecodeError:
                    pass

            first_brace = cleaned_response.find('{')
            last_brace = cleaned_response.rfind('}')
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                json_str = cleaned_response[first_brace:last_brace+1]
                json_str = re.sub(r'(?<!\\)\'', '"', json_str)
                json_str = re.sub(r'(\w+)\s*:', '"\1":', json_str)
                try:
                    data = json.loads(json_str)
                    if schema_name:
                        validator = SchemaValidator()
                        validated_data = validator.validate_with_fallback(data, schema_name)
                        return validated_data
                    return data
                except json.JSONDecodeError:
                    pass

            if schema_name:
                validator = SchemaValidator()
                validated_data = validator.validate_with_fallback({'raw': response}, schema_name)
                return validated_data

            return {'raw_response': response}
        except Exception as e:
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [yellow]JSON解析失败: {e}[/yellow]")
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [dim]原始响应: {response[:500]}...[/dim]")
            return {'raw_response': response, 'error': str(e)}
