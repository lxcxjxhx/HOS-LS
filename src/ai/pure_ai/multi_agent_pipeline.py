import asyncio
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from src.ai.pure_ai.context_builder import ContextBuilder
from src.ai.pure_ai.line_number_mapper import LineNumberMapper
from src.ai.prompt_engine import get_prompt_engine, PromptEngine
from src.ai.pure_ai.schema_validator import SchemaValidator
from src.ai.models import AIRequest
from src.ai.token_tracker import get_token_tracker
from src.ai.pure_ai.schema import SignalState

console = Console()

class SemanticConsistencyError(Exception):
    """语义一致性异常"""
    pass


class KnownFileRegistry:
    """已知文件注册表 - 防止幻觉引用

    维护一个已知文件的注册表，确保所有引用的 location
    都在已知的文件范围内，防止 AI 生成不存在的文件引用。
    """

    def __init__(self):
        self._files: Dict[str, str] = {}
        self._line_counts: Dict[str, int] = {}

    def register(self, file_path: str, content: str) -> None:
        """注册文件到注册表

        Args:
            file_path: 文件路径
            content: 文件内容
        """
        self._files[file_path] = content
        self._line_counts[file_path] = content.count('\n') + 1 if content else 1

    def clear(self) -> None:
        """清空注册表"""
        self._files.clear()
        self._line_counts.clear()

    def validate_location(self, location: str) -> Tuple[bool, str]:
        """验证 location 是否有效

        Args:
            location: 位置字符串（格式：文件路径:行号）

        Returns:
            (是否有效, 错误信息)
        """
        if not location:
            return False, "Empty location"

        parts = location.rsplit(':', 1)
        if len(parts) != 2:
            return False, f"Invalid location format: {location}"

        path, line_str = parts

        if path not in self._files:
            available = ', '.join(list(self._files.keys())[:3])
            return False, f"Unknown file: {path}. Available: {available}"

        try:
            line_num = int(line_str)
        except ValueError:
            return False, f"Invalid line number: {line_str}"

        max_line = self._line_counts[path]
        if line_num < 1 or line_num > max_line:
            return False, f"Line {line_num} out of range (1-{max_line})"

        return True, ""

    def get_file_content(self, file_path: str) -> Optional[str]:
        """获取文件内容"""
        return self._files.get(file_path)

    def get_known_file_paths(self) -> List[str]:
        """获取所有已知文件路径"""
        return list(self._files.keys())

    def get_file_summary(self) -> str:
        """获取文件摘要列表"""
        return '\n'.join([f"- {path} ({self._line_counts[path]} lines)" for path in self._files.keys()])

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
        self.prompt_engine = get_prompt_engine()
        self.token_tracker = get_token_tracker()
        self.checkpoint_callback = None
        self._processed_files = []
        self._current_step = None
        self._agent_timings = {}
        self.evidence_chain_tracker = EvidenceChain()
        self.schema_validator = SchemaValidator()
        self._file_registry = KnownFileRegistry()
        self.line_number_mapper = LineNumberMapper()
        self.debug_logs: List[str] = []
        if hasattr(config, 'get'):
            self.max_retries = config.get('max_retries', 3)
            self.model = config.get('model', 'deepseek-v4-pro')
            self.temperature = config.get('temperature', 0.1)
        else:
            self.max_retries = getattr(config, 'max_retries', 3)
            self.model = getattr(config, 'ai', {}).get('model', 'deepseek-v4-pro') if hasattr(config, 'ai') else 'deepseek-v4-pro'
            self.temperature = getattr(config, 'ai', {}).get('temperature', 0.1) if hasattr(config, 'ai') else 0.1

        console.print(f"[dim][DEBUG] Pipeline 使用模型: {self.model}, Temperature: {self.temperature}[/dim]")

    def _detect_language(self, file_path: str, file_content: str) -> str:
        """检测代码语言/框架

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            检测到的语言/框架描述
        """
        file_path = str(file_path)
        if file_path.endswith('.java'):
            return 'Java'
        elif file_path.endswith('.py'):
            return 'Python'
        elif file_path.endswith('.js'):
            return 'JavaScript'
        elif file_path.endswith('.go'):
            return 'Go'
        elif file_path.endswith('.php'):
            return 'PHP'
        elif file_path.endswith('.cs'):
            return 'C#'
        elif file_path.endswith('.rb'):
            return 'Ruby'
        elif file_path.endswith('.ts'):
            return 'TypeScript'

        # 配置文件格式
        elif file_path.endswith(('.yml', '.yaml')):
            return 'YAML'
        elif file_path.endswith('.properties'):
            return 'Properties'
        elif file_path.endswith('.xml'):
            return 'XML'
        elif file_path.endswith('.json'):
            return 'JSON'
        elif file_path.endswith('.toml'):
            return 'TOML'
        elif file_path.endswith(('.ini', '.conf', '.cfg')):
            return 'Config'

        # Web文件格式
        elif file_path.endswith(('.html', '.htm')):
            return 'HTML'
        elif file_path.endswith('.vue'):
            return 'Vue'
        elif file_path.endswith('.jsx'):
            return 'JSX'
        elif file_path.endswith('.tsx'):
            return 'TSX'
        elif file_path.endswith(('.css', '.scss', '.sass', '.less')):
            return 'CSS'

        # 脚本文件格式
        elif file_path.endswith('.sql'):
            return 'SQL'
        elif file_path.endswith(('.sh', '.bash')):
            return 'Shell'
        elif file_path.endswith('.ps1'):
            return 'PowerShell'
        elif file_path.endswith(('.bat', '.cmd')):
            return 'Batch'

        # 其他文件格式
        elif file_path.endswith('.md'):
            return 'Markdown'
        elif file_path.endswith('.txt'):
            return 'Text'
        elif file_path.endswith('.gradle'):
            return 'Gradle'
        elif file_path.endswith('.kts'):
            return 'Kotlin'
        elif file_path.endswith('Dockerfile'):
            return 'Dockerfile'
        elif file_path.endswith('.dockerfile'):
            return 'Dockerfile'
        elif file_path.endswith('.csv'):
            return 'CSV'
        elif file_path.endswith('.proto'):
            return 'Protobuf'

        # 检查文件内容中的框架特征
        if 'import org.springframework' in file_content or 'package com.' in file_content:
            return 'Java'
        if 'from django' in file_content or 'import django' in file_content:
            return 'Python'
        if 'from flask' in file_content or 'import flask' in file_content:
            return 'Python'
        if 'const express' in file_content or 'require(express)' in file_content:
            return 'JavaScript'
        if 'import React' in file_content or 'from react' in file_content:
            return 'JavaScript'

        return 'Unknown'

    def _register_known_files(self, context: Dict[str, Any]) -> None:
        """注册已知文件到注册表

        Args:
            context: 上下文信息
        """
        self._file_registry.clear()
        self._file_registry.register(
            context['current_file'],
            context['file_content']
        )
        for rf in context.get('related_files', []):
            self._file_registry.register(rf['path'], rf['content'])
        print(f"[DEBUG] Registered {len(self._file_registry.get_known_file_paths())} known files")

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
                self._register_known_files(context)
                self.line_number_mapper.record_file_snapshot(file_path, context['file_content'])
                elapsed = time.time() - start_time
                self._agent_timings['context_build'] = elapsed
                self._current_step = 'context_build'
                self._trigger_checkpoint_callback('context_build', {'elapsed': elapsed})
                progress.advance(main_task)

                # 检测代码语言
                detected_language = self._detect_language(file_path, context['file_content'])
                print(f"[DEBUG] 检测到语言: {detected_language}")

                start_time = time.time()
                context_analysis, token_usage = await self._run_agent_0(file_path, context, detected_language)
                elapsed = time.time() - start_time
                self._agent_timings['agent_0'] = elapsed
                self._current_step = 'agent_0'
                self._trigger_checkpoint_callback('agent_0', {'elapsed': elapsed, 'token_usage': token_usage})
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)

                start_time = time.time()
                code_understanding, token_usage = await self._run_agent_1(file_path, context, context_analysis, detected_language)
                elapsed = time.time() - start_time
                self._agent_timings['agent_1'] = elapsed
                self._current_step = 'agent_1'
                self._trigger_checkpoint_callback('agent_1', {'elapsed': elapsed, 'token_usage': token_usage})
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)

                start_time = time.time()
                risk_enumeration, token_usage = await self._run_agent_2(file_path, code_understanding, detected_language)
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
                vulnerability_verification, token_usage = await self._run_agent_3(file_path, risk_enumeration, context['file_content'], detected_language)
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
                attack_chain_analysis, token_usage = await self._run_agent_4(file_path, vulnerability_verification, detected_language)
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
                adversarial_validation, token_usage = await self._run_agent_5(file_path, attack_chain_analysis, context['file_content'], detected_language)
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
                final_decision, token_usage = await self._run_agent_6(file_path, context, adversarial_validation, vulnerability_verification, detected_language)
                validated_final_decision = self._validate_final_findings(final_decision, context)
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
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [bold green]OK {Path(file_path).name} 分析完成[/bold green] [dim]({total_elapsed:.2f}s)[/dim]")

            if total_token_usage['total_tokens'] > 0:
                avg_tokens_per_agent = total_token_usage['total_tokens'] / 6 if 6 > 0 else 0
                console.print(f"[dim]  [TOKEN] Token: {total_token_usage['total_tokens']:,} (提示词: {total_token_usage['prompt_tokens']:,}, 补全: {total_token_usage['completion_tokens']:,})[/dim]")

            return {
                'file_path': file_path,
                'context_analysis': context_analysis,
                'code_understanding': code_understanding,
                'risk_enumeration': risk_enumeration,
                'vulnerability_verification': vulnerability_verification,
                'attack_chain_analysis': attack_chain_analysis,
                'adversarial_validation': adversarial_validation,
                'final_decision': validated_final_decision,
                'evidence_chain': self._get_signal_summary(),
                'debug_logs': self.debug_logs
            }
        except Exception as e:
            self._current_step = 'error'
            self._trigger_checkpoint_callback('pipeline_error', {'error': str(e)})
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [bold red][X] {Path(file_path).name} 分析失败: {e}[/bold red]")
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
        all_signal_ids = set(self.evidence_chain_tracker.get_all_signals().keys())
        processed_signal_ids = set()

        for vuln in vulnerabilities:
            signal_id = vuln.get('signal_id', '') or vuln.get('id', '')
            if signal_id:
                processed_signal_ids.add(signal_id)
                evidence = vuln.get('evidence', [])
                new_state = vuln.get('signal_state', SignalState.NEW.value)
                verification_decision = vuln.get('verification_decision', '')

                if verification_decision == 'CONFIRMED':
                    new_state = 'CONFIRMED'
                elif verification_decision == 'REJECTED':
                    new_state = 'REJECTED'
                elif verification_decision == 'REFINED':
                    new_state = 'REFINED'

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
                else:
                    print(f"[WARN] Verification signal {signal_id} not found in tracker (Agent-2 original signals), may be a new signal from Agent-3")

        unverified_signals = all_signal_ids - processed_signal_ids
        if unverified_signals:
            print(f"[WARN] Signals from Agent-2 not verified by Agent-3: {unverified_signals}")

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
        """处理未在下游被消费的信号

        将未验证的信号添加到下游输出中，标记为REFINED状态，等待进一步验证。

        Args:
            missing_signals: 缺失的信号ID集合
            downstream: 下游输出（将被修改）
            signal_type: 信号类型 ('risk' 或 'attack_chain')
        """
        print(f"[WARN] Semantic gap: signals {missing_signals} were not consumed by downstream agent")

        if signal_type == 'risk' and missing_signals:
            vulnerabilities = downstream.get('vulnerabilities', [])
            if not isinstance(vulnerabilities, list):
                vulnerabilities = []
                downstream['vulnerabilities'] = vulnerabilities

            for sig_id in missing_signals:
                refined_signal = {
                    'title': 'WEAK_SECURITY_SIGNAL',
                    'severity': 'MEDIUM',
                    'location': '',
                    'evidence': [],
                    'cwe_id': '',
                    'cvss_score': '',
                    'signal_id': sig_id,
                    'signal_state': 'REFINED',
                    'verification_decision': 'REFINED',
                    'verification_reason': f'Signal {sig_id} was not consumed by vulnerability verification agent - requires manual review'
                }
                vulnerabilities.append(refined_signal)
                print(f"[DEBUG] 添加已细化信号用于未消耗的 {sig_id}")

            signal_tracking = downstream.get('signal_tracking', {})
            if isinstance(signal_tracking, dict):
                signal_tracking['signals_refined'] = signal_tracking.get('signals_refined', 0) + len(missing_signals)
                downstream['signal_tracking'] = signal_tracking

        elif signal_type == 'attack_chain' and missing_signals:
            adversarial_analysis = downstream.get('adversarial_analysis', [])
            if not isinstance(adversarial_analysis, list):
                adversarial_analysis = []
                downstream['adversarial_analysis'] = adversarial_analysis

            for sig_id in missing_signals:
                refined_signal = {
                    'attack_chain_name': sig_id,
                    'verdict': 'UNCERTAIN',
                    'confidence': 0.3,
                    'reason': f'Signal {sig_id} was not properly challenged - requires manual review',
                    'counter_arguments': [],
                    'evidence': [],
                    'requires_human_review': True,
                    'challenged_signal_id': sig_id
                }
                adversarial_analysis.append(refined_signal)
                print(f"[DEBUG] 添加待定判定用于未消耗的 {sig_id}")

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

    def _verify_location_exists(self, location: str, context: Dict[str, Any]) -> tuple[bool, str]:
        """验证 location 是否在上下文中存在

        Args:
            location: 位置字符串（格式：文件路径:行号）
            context: 上下文信息

        Returns:
            (是否有效, 错误信息)
        """
        if not location:
            return False, "Empty location"

        parts = location.rsplit(':', 1)
        if len(parts) != 2:
            return False, f"Invalid location format: {location}"

        file_path, line_str = parts

        try:
            line_num = int(line_str)
        except ValueError:
            return False, f"Invalid line number: {line_str}"

        current_file = context.get('current_file', '')
        current_file_normalized = Path(current_file).resolve()
        file_path_normalized = Path(file_path).resolve()
        if file_path_normalized != current_file_normalized:
            return False, f"File path mismatch: expected {current_file}, got {file_path}"

        file_content = context.get('file_content', '')
        if not file_content:
            return False, "No file content in context"

        line_count = file_content.count('\n') + 1
        if line_num < 1 or line_num > line_count:
            return False, f"Line number {line_num} out of range (1-{line_count})"

        return True, ""

    def _validate_final_findings(self, final_decision: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """验证并过滤最终发现中的无效 location

        Args:
            final_decision: Agent-6 的输出
            context: 上下文信息

        Returns:
            验证后的结果
        """
        from src.ai.pure_ai.line_number_mapper import LineNumberValidator

        findings = final_decision.get('final_findings', [])

        if not findings:
            return final_decision

        validator = LineNumberValidator(self.line_number_mapper)
        validator._snapshots = self.line_number_mapper._snapshots

        valid_findings = []
        rejected_count = 0
        line_validation_summary = {'total': 0, 'exact': 0, 'fuzzy': 0, 'not_found': 0, 'corrected': 0, 'unverified': 0}

        for finding in findings:
            location = finding.get('location', '')
            is_valid, error = self._verify_location_exists(location, context)

            if is_valid:
                code_snippet = finding.get('code_snippet', '')
                validation_result = validator.verify_and_correct(location, code_snippet)

                finding['ai_reported_line'] = validation_result['ai_reported_line']
                finding['verified_line'] = validation_result['verified_line']
                finding['line_match_status'] = validation_result['line_match_status']
                finding['code_snippet'] = validation_result['code_snippet']

                line_validation_summary['total'] += 1
                if validation_result['line_match_status'] == 'EXACT':
                    line_validation_summary['exact'] += 1
                elif validation_result['line_match_status'] == 'FUZZY':
                    line_validation_summary['fuzzy'] += 1
                elif validation_result['line_match_status'] == 'NOT_FOUND':
                    line_validation_summary['not_found'] += 1
                elif validation_result['line_match_status'] == 'UNVERIFIED':
                    line_validation_summary['unverified'] += 1

                if validation_result['deviation'] > 0:
                    line_validation_summary['corrected'] += 1
                    print(f"[DEBUG] Line corrected: {location} -> {validation_result['verified_line']} (deviation: {validation_result['deviation']})")

                if validation_result.get('is_valid', True):
                    valid_findings.append(finding)
                else:
                    print(f"[WARN] Filtered finding without valid code snippet: {finding.get('rule_name', 'unknown')} at {location}")
                    print(f"[WARN] Reason: {validation_result.get('warning_message', 'code_snippet is empty or invalid')}")
                    rejected_count += 1
            else:
                print(f"[WARN] Filtered invalid finding: {finding.get('rule_name', 'unknown')} at {location} - {error}")
                rejected_count += 1

        summary = final_decision.get('summary', {})
        summary['invalid_vulnerabilities'] = summary.get('invalid_vulnerabilities', 0) + rejected_count
        summary['total_vulnerabilities'] = len(valid_findings)
        summary['valid_vulnerabilities'] = len(valid_findings)
        summary['line_validation'] = line_validation_summary

        return {
            'final_findings': valid_findings,
            'summary': summary
        }

    def _validate_result_consistency(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """验证结果一致性

        检查风险枚举与验证阶段的信号数量是否一致
        如果不一致，发出警告并计算一致性评分

        Args:
            result: 分析结果

        Returns:
            添加了一致性信息的result
        """
        risk_enum = result.get('risk_enumeration', {})
        vuln_verif = result.get('vulnerability_verification', {})

        risk_signals = risk_enum.get('risks', [])
        vuln_signals = vuln_verif.get('vulnerabilities', [])

        risk_count = len(risk_signals)
        vuln_count = len(vuln_signals)

        tracker_signals = self.evidence_chain_tracker.get_all_signals() if hasattr(self, 'evidence_chain_tracker') else {}
        tracker_count = len(tracker_signals)
        tracker_verified = sum(1 for s in tracker_signals.values() if s.get('current_state') in ['CONFIRMED', 'REJECTED', 'REFINED'])
        tracker_new = sum(1 for s in tracker_signals.values() if s.get('current_state') == 'NEW')

        if vuln_count == 0 and tracker_count > 0:
            vuln_count = tracker_verified
            print(f"[DEBUG] Using tracker signal count for verification: {vuln_count} (total: {tracker_count}, verified: {tracker_verified}, new: {tracker_new})")

        consistency_score = 1.0
        if risk_count > 0:
            consistency_score = min(vuln_count / risk_count, 1.0) if vuln_count > 0 else 0.0

        stability_warning = None
        if risk_count != vuln_count and risk_count > 0:
            if vuln_count < risk_count:
                stability_warning = f"[稳定性警告] 风险枚举({risk_count})与验证({vuln_count})信号数不一致，{risk_count - vuln_count}个信号未被验证"
                print(f"[WARN] {stability_warning}")
                self.debug_logs.append(stability_warning)
            else:
                stability_warning = f"[稳定性警告] 验证阶段发现了额外的{vuln_count - risk_count}个信号"
                print(f"[WARN] {stability_warning}")
                self.debug_logs.append(stability_warning)

        result['consistency_score'] = consistency_score
        result['stability_warning'] = stability_warning
        result['signal_count'] = {
            'risk_enumeration': risk_count,
            'vulnerability_verification': vuln_count,
            'tracker_total': tracker_count,
            'tracker_verified': tracker_verified,
            'tracker_new': tracker_new,
            'difference': abs(risk_count - vuln_count)
        }

        return result

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
    
    async def _run_agent_0(self, file_path: str, context: Dict[str, Any], detected_language: str = "Unknown") -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 0：上下文构建

        Args:
            file_path: 文件路径
            context: 上下文信息
            detected_language: 检测到的语言

        Returns:
            (上下文分析结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 0 (上下文构建) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 0 (上下文构建) on: {file_path}")
        prompt = self.prompt_engine.render_agent_prompt(
            "context_builder",
            file_path=file_path,
            file_content=context['file_content'],
            related_files=PromptEngine.format_related_files(context.get('related_files', [])),
            imports=PromptEngine.format_imports(context.get('imports', [])),
            function_calls=PromptEngine.format_function_calls(context.get('function_calls', [])),
            detected_language=detected_language
        )
        
        response, token_usage = await self._generate_with_retry(prompt, "Agent 0", temperature=self.temperature)
        result = self._parse_json_response(response, schema_name="context_analysis")
        print(f"[DEBUG] Agent 0 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 0 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_1(self, file_path: str, context: Dict[str, Any], context_analysis: Dict[str, Any], detected_language: str = "Unknown") -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 1：代码理解

        Args:
            file_path: 文件路径
            context: 上下文信息
            context_analysis: 上下文分析结果
            detected_language: 检测到的语言

        Returns:
            (代码理解结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 1 (代码理解) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 1 (代码理解) on: {file_path}")
        context_info = json.dumps(context_analysis, ensure_ascii=False)
        prompt = self.prompt_engine.render_agent_prompt(
            "code_understanding",
            file_path=file_path,
            file_content=context['file_content'],
            context_info=context_info,
            detected_language=detected_language
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 1", temperature=self.temperature)
        result = self._parse_json_response(response, schema_name="code_understanding")
        print(f"[DEBUG] Agent 1 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 1 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_2(self, file_path: str, code_understanding: Dict[str, Any], detected_language: str = "Unknown") -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 2：风险枚举

        Args:
            file_path: 文件路径
            code_understanding: 代码理解结果
            detected_language: 检测到的语言

        Returns:
            (风险枚举结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 2 (风险枚举) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 2 (风险枚举) on: {file_path}")
        structured_data = json.dumps(code_understanding, ensure_ascii=False)
        known_file_paths = self._file_registry.get_known_file_paths()
        prompt = self.prompt_engine.render_agent_prompt(
            "risk_enumeration",
            file_path=file_path,
            structured_data=structured_data,
            detected_language=detected_language,
            known_file_paths=known_file_paths
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 2", temperature=self.temperature)
        result = self._parse_json_response(response, schema_name="risk_enumeration")
        print(f"[DEBUG] Agent 2 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 2 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_3(self, file_path: str, risk_enumeration: Dict[str, Any], file_content: str, detected_language: str = "Unknown") -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 3：漏洞验证

        Args:
            file_path: 文件路径
            risk_enumeration: 风险枚举结果
            file_content: 文件内容
            detected_language: 检测到的语言

        Returns:
            (漏洞验证结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 3 (漏洞验证) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 3 (漏洞验证) on: {file_path}")
        risk_list = json.dumps(risk_enumeration.get('risks', []), ensure_ascii=False)
        known_file_paths = self._file_registry.get_known_file_paths()
        line_counts = dict(self._file_registry._line_counts)
        if file_path not in known_file_paths:
            known_file_paths.append(file_path)
            line_counts[file_path] = file_content.count('\n') + 1 if file_content else 1
        known_files_summary = '\n'.join([f"- {path} ({line_counts[path]} lines)" for path in known_file_paths])
        prompt = self.prompt_engine.render_agent_prompt(
            "vulnerability_verification",
            file_path=file_path,
            risk_list=risk_list,
            file_content=file_content,
            detected_language=detected_language,
            known_files_summary=known_files_summary,
            known_file_paths=known_file_paths,
            line_counts=line_counts
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 3", temperature=self.temperature)
        result = self._parse_json_response(response, schema_name="vulnerability")
        result = self._safety_net_agent_3(result, file_content)
        print(f"[DEBUG] Agent 3 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 3 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage

    def _safety_net_agent_3(self, result: Dict[str, Any], file_content: str) -> Dict[str, Any]:
        """Agent-3 安全网：检测并修正伪 REJECTED

        当 file_content 存在但 Agent-3 仍因"无法验证 code_snippet"而拒绝时，
        系统自动将 REJECTED 降级为 REFINED。
        """
        vulnerabilities = result.get('vulnerabilities', [])
        modified = False
        for vuln in vulnerabilities:
            if vuln.get('verification_decision') == 'REJECTED':
                reason = vuln.get('verification_reason', '')
                if '无法验证' in reason or '未提供' in reason:
                    if file_content:
                        old_decision = vuln.get('verification_decision')
                        vuln['verification_decision'] = 'REFINED'
                        vuln['verification_reason'] = reason + ' [系统降级：file_content存在，降级为待复核]'
                        modified = True
                        old_decision_display = '已拒绝' if old_decision == 'REJECTED' else ('已确认' if old_decision == 'CONFIRMED' else old_decision)
                        print(f"[DEBUG] 安全网修正: {vuln.get('signal_id', 'unknown')} 从 {old_decision_display} -> 已细化")
                        self.debug_logs.append(f"[DEBUG] 安全网修正: {vuln.get('signal_id', 'unknown')} 从 {old_decision_display} -> 已细化，原始原因: {reason}")
        if modified:
            signal_tracking = result.get('signal_tracking', {})
            signal_tracking['signals_refined'] = signal_tracking.get('signals_refined', 0) + 1
            signal_tracking['signals_rejected'] = max(0, signal_tracking.get('signals_rejected', 0) - 1)
            result['signal_tracking'] = signal_tracking
        return result

    async def _run_agent_4(self, file_path: str, vulnerability_verification: Dict[str, Any], detected_language: str = "Unknown") -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 4：攻击链分析

        Args:
            file_path: 文件路径
            vulnerability_verification: 漏洞验证结果
            detected_language: 检测到的语言

        Returns:
            (攻击链分析结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 4 (攻击链分析) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 4 (攻击链分析) on: {file_path}")
        verification_results = json.dumps(vulnerability_verification, ensure_ascii=False)
        prompt = self.prompt_engine.render_agent_prompt(
            "attack_chain",
            file_path=file_path,
            verification_results=verification_results,
            detected_language=detected_language
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 4", temperature=self.temperature)
        result = self._parse_json_response(response, schema_name="attack_chain")
        print(f"[DEBUG] Agent 4 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 4 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_5(self, file_path: str, attack_chain_analysis: Dict[str, Any], file_content: str, detected_language: str = "Unknown") -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 5：对抗验证

        Args:
            file_path: 文件路径
            attack_chain_analysis: 攻击链分析结果
            file_content: 文件内容
            detected_language: 检测到的语言

        Returns:
            (对抗验证结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 5 (对抗验证) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 5 (对抗验证) on: {file_path}")
        attack_chain_json = json.dumps(attack_chain_analysis, ensure_ascii=False)
        prompt = self.prompt_engine.render_agent_prompt(
            "adversarial_validation",
            file_path=file_path,
            attack_chain_analysis=attack_chain_json,
            file_content=file_content,
            detected_language=detected_language
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 5", temperature=self.temperature)
        result = self._parse_json_response(response, schema_name="adversarial")
        print(f"[DEBUG] Agent 5 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 5 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_6(self, file_path: str, context: Dict[str, Any], adversarial_validation: Dict[str, Any], vulnerability_verification: Dict[str, Any], detected_language: str = "Unknown") -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 6：最终裁决

        Args:
            file_path: 文件路径
            context: 上下文信息
            adversarial_validation: 对抗验证结果
            vulnerability_verification: 漏洞验证结果
            detected_language: 检测到的语言

        Returns:
            (最终裁决结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 6 (最终裁决) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 6 (最终裁决) on: {file_path}")
        adversarial_results = json.dumps(adversarial_validation, ensure_ascii=False)
        verification_results = json.dumps(vulnerability_verification, ensure_ascii=False)
        known_files_summary = self._file_registry.get_file_summary()
        known_file_paths = self._file_registry.get_known_file_paths()
        line_counts = self._file_registry._line_counts
        prompt = self.prompt_engine.render_agent_prompt(
            "final_decision",
            file_path=file_path,
            file_content=context.get('file_content', ''),
            adversarial_results=adversarial_results,
            verification_results=verification_results,
            detected_language=detected_language,
            known_files_summary=known_files_summary,
            known_file_paths=known_file_paths,
            line_counts=line_counts
        )

        response, token_usage = await self._generate_with_retry(prompt, "Agent 6", temperature=self.temperature)
        result = self._parse_json_response(response, schema_name="final_decision")
        print(f"[DEBUG] Agent 6 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 6 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _generate_with_retry(self, prompt: str, agent_name: str = "unknown", temperature: float = 0.0) -> Tuple[str, Dict[str, int]]:
        """带重试的生成

        Args:
            prompt: 提示词
            agent_name: Agent名称
            temperature: 温度值

        Returns:
            (生成的响应, token使用信息)

        Raises:
            APIError: 当API错误应该立即截断时（如402、超时、连接错误）
        """
        from src.ai.providers.deepseek import APIError as DeepSeekAPIError

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

            except DeepSeekAPIError as e:
                console.print(f"[bold cyan][PURE-AI][/bold cyan] [red][ERROR] API错误 (Agent: {agent_name}): {e.message}[/red]")
                if e.should_truncate:
                    console.print(f"[bold yellow][!] 检测到需立即截断的错误，不进行重试[/bold yellow]")
                    raise
                console.print(f"[bold cyan][PURE-AI][/bold cyan] [yellow]生成失败 (Agent: {agent_name}, 尝试 {i+1}/{self.max_retries}): {e.message}[/yellow]")
                if i == self.max_retries - 1:
                    raise
                await asyncio.sleep(2)
            except Exception as e:
                console.print(f"[bold cyan][PURE-AI][/bold cyan] [yellow]生成失败 (Agent: {agent_name}, 尝试 {i+1}/{self.max_retries}): {e}[/yellow]")
                if i == self.max_retries - 1:
                    raise
                await asyncio.sleep(2)
    
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

    async def run_parallel_agents(
        self,
        file_path: str,
        agents: List[str],
        context: Dict[str, Any],
        detected_language: str
    ) -> Dict[str, Any]:
        """并行运行多个独立的 Agent

        适用于 Agent 3-5，它们可以并行执行以提高效率。

        Args:
            file_path: 文件路径
            agents: Agent 名称列表，如 ['agent_3', 'agent_4', 'agent_5']
            context: 上下文信息
            detected_language: 检测到的语言

        Returns:
            各 Agent 结果的字典
        """
        print(f"[DEBUG] 并行运行 Agents: {agents}")
        start_time = time.time()

        tasks = []
        agent_names = []

        if 'agent_3' in agents:
            tasks.append(self._run_agent_3(
                file_path,
                context.get('risk_enumeration', {}),
                context.get('file_content', ''),
                detected_language
            ))
            agent_names.append('agent_3')

        if 'agent_4' in agents:
            tasks.append(self._run_agent_4(
                file_path,
                context.get('vulnerability_verification', {}),
                detected_language
            ))
            agent_names.append('agent_4')

        if 'agent_5' in agents:
            tasks.append(self._run_agent_5(
                file_path,
                context.get('attack_chain_analysis', {}),
                context.get('file_content', ''),
                detected_language
            ))
            agent_names.append('agent_5')

        if not tasks:
            return {}

        results = await asyncio.gather(*tasks, return_exceptions=True)

        result_dict = {}
        for i, result in enumerate(results):
            agent_name = agent_names[i]
            if isinstance(result, Exception):
                console.print(f"[yellow]Agent {agent_name} failed: {result}[/yellow]")
                result_dict[agent_name] = {}
            else:
                token_usage = result[1] if isinstance(result, tuple) else {}
                result_dict[agent_name] = {
                    'result': result[0] if isinstance(result, tuple) else result,
                    'token_usage': token_usage
                }

        elapsed = time.time() - start_time
        print(f"[DEBUG] 并行 Agents 完成，耗时: {elapsed:.2f}s")

        return result_dict

    async def run_pipeline_optimized(
        self,
        file_path: str,
        enable_parallel: bool = True
    ) -> Dict[str, Any]:
        """优化版流水线运行

        Stage 1-2: 顺序执行（上下文构建 -> 代码理解）
        Stage 3-5: 可选并行执行（漏洞验证 -> 攻击链 -> 对抗验证）
        Stage 6: 顺序执行（最终裁决）

        Args:
            file_path: 文件路径
            enable_parallel: 是否启用并行执行

        Returns:
            分析结果
        """
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

        try:
            print(f"[DEBUG] 开始运行优化版多Agent流水线: {file_path}")
            total_start_time = time.time()
            self._agent_timings = {}
            self._current_step = 'started'
            self._current_file_path = file_path
            if not hasattr(self, 'evidence_chain_tracker') or self.evidence_chain_tracker is None:
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
                total_steps = 5 if enable_parallel else 8
                main_task = progress.add_task(f"[cyan]分析: {Path(file_path).name}[/cyan]", total=total_steps)

                start_time = time.time()
                context = self.context_builder.build_context(file_path)
                self._register_known_files(context)
                self.line_number_mapper.record_file_snapshot(file_path, context['file_content'])
                elapsed = time.time() - start_time
                self._agent_timings['context_build'] = elapsed
                progress.advance(main_task)

                detected_language = self._detect_language(file_path, context['file_content'])
                print(f"[DEBUG] 检测到语言: {detected_language}")

                start_time = time.time()
                context_analysis, token_usage = await self._run_agent_0(file_path, context, detected_language)
                elapsed = time.time() - start_time
                self._agent_timings['agent_0'] = elapsed
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)

                start_time = time.time()
                code_understanding, token_usage = await self._run_agent_1(file_path, context, context_analysis, detected_language)
                elapsed = time.time() - start_time
                self._agent_timings['agent_1'] = elapsed
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)

                risk_enumeration = None
                vulnerability_verification = None
                attack_chain_analysis = None
                adversarial_validation = None

                if enable_parallel:
                    start_time = time.time()

                    risk_enum_result, _ = await self._run_agent_2(file_path, code_understanding, detected_language)
                    risk_enumeration = risk_enum_result
                    self._track_risk_signals(risk_enumeration)

                    parallel_context = {
                        'file_content': context['file_content'],
                        'risk_enumeration': risk_enumeration,
                        'vulnerability_verification': {},
                        'attack_chain_analysis': {}
                    }

                    parallel_results = await self.run_parallel_agents(
                        file_path=file_path,
                        agents=['agent_3', 'agent_4', 'agent_5'],
                        context=parallel_context,
                        detected_language=detected_language
                    )

                    if 'agent_3' in parallel_results:
                        vulnerability_verification = parallel_results['agent_3']['result']
                        self._track_verification_signals(vulnerability_verification)
                        total_token_usage['prompt_tokens'] += parallel_results['agent_3']['token_usage'].get('prompt_tokens', 0)
                        total_token_usage['completion_tokens'] += parallel_results['agent_3']['token_usage'].get('completion_tokens', 0)
                        total_token_usage['total_tokens'] += parallel_results['agent_3']['token_usage'].get('total_tokens', 0)

                    if 'agent_4' in parallel_results:
                        attack_chain_analysis = parallel_results['agent_4']['result']
                        self._track_attack_chain_signals(attack_chain_analysis)
                        total_token_usage['prompt_tokens'] += parallel_results['agent_4']['token_usage'].get('prompt_tokens', 0)
                        total_token_usage['completion_tokens'] += parallel_results['agent_4']['token_usage'].get('completion_tokens', 0)
                        total_token_usage['total_tokens'] += parallel_results['agent_4']['token_usage'].get('total_tokens', 0)

                    if 'agent_5' in parallel_results:
                        adversarial_validation = parallel_results['agent_5']['result']
                        self._track_adversarial_signals(adversarial_validation)
                        total_token_usage['prompt_tokens'] += parallel_results['agent_5']['token_usage'].get('prompt_tokens', 0)
                        total_token_usage['completion_tokens'] += parallel_results['agent_5']['token_usage'].get('completion_tokens', 0)
                        total_token_usage['total_tokens'] += parallel_results['agent_5']['token_usage'].get('total_tokens', 0)

                    elapsed = time.time() - start_time
                    self._agent_timings['parallel_stage'] = elapsed
                    print(f"[DEBUG] 并行 Stage 3-5 耗时: {elapsed:.2f}s")
                else:
                    start_time = time.time()
                    risk_enumeration, token_usage = await self._run_agent_2(file_path, code_understanding, detected_language)
                    elapsed = time.time() - start_time
                    self._agent_timings['agent_2'] = elapsed
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    progress.advance(main_task)

                    vulnerability_verification, token_usage = await self._run_agent_3(
                        file_path, risk_enumeration, context['file_content'], detected_language
                    )
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    progress.advance(main_task)

                    attack_chain_analysis, token_usage = await self._run_agent_4(
                        file_path, vulnerability_verification, detected_language
                    )
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    progress.advance(main_task)

                    adversarial_validation, token_usage = await self._run_agent_5(
                        file_path, attack_chain_analysis, context['file_content'], detected_language
                    )
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    progress.advance(main_task)

                start_time = time.time()
                final_decision, token_usage = await self._run_agent_6(
                    file_path, context, adversarial_validation or {}, vulnerability_verification or {}, detected_language
                )
                validated_final_decision = self._validate_final_findings(final_decision, context)
                elapsed = time.time() - start_time
                self._agent_timings['agent_6'] = elapsed
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)

            total_elapsed = time.time() - total_start_time
            self._current_step = 'completed'

            if file_path not in self._processed_files:
                self._processed_files.append(file_path)

            console.print(f"[bold cyan][PURE-AI][/bold cyan] [bold green]OK {Path(file_path).name} 优化流水线分析完成[/bold green] [dim]({total_elapsed:.2f}s)[/dim]")

            if total_token_usage['total_tokens'] > 0:
                console.print(f"[dim]  [TOKEN] Token: {total_token_usage['total_tokens']:,} (提示词: {total_token_usage['prompt_tokens']:,}, 补全: {total_token_usage['completion_tokens']:,})[/dim]")

            consistency_result = self._validate_result_consistency({
                'risk_enumeration': risk_enumeration or {},
                'vulnerability_verification': vulnerability_verification or {}
            })
            consistency_info = {
                'consistency_score': consistency_result.get('consistency_score', 1.0),
                'stability_warning': consistency_result.get('stability_warning'),
                'signal_count': consistency_result.get('signal_count', {})
            }

            return {
                'file_path': file_path,
                'context_analysis': context_analysis,
                'code_understanding': code_understanding,
                'risk_enumeration': risk_enumeration or {},
                'vulnerability_verification': vulnerability_verification or {},
                'attack_chain_analysis': attack_chain_analysis or {},
                'adversarial_validation': adversarial_validation or {},
                'final_decision': validated_final_decision,
                'evidence_chain': self._get_signal_summary(),
                'debug_logs': self.debug_logs,
                'parallel_mode': enable_parallel,
                'consistency': consistency_info,
                'file_snapshot': {
                    'path': file_path,
                    'recorded': True,
                    'has_content': file_path in self.line_number_mapper._snapshots
                }
            }

        except Exception as e:
            self._current_step = 'error'
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [bold red][X] 优化流水线分析失败: {e}[/bold red]")
            import traceback
            traceback.print_exc()
            return {
                'file_path': file_path,
                'error': str(e)
            }

    def get_agent_dependencies(self) -> Dict[str, List[str]]:
        """获取 Agent 依赖关系

        Returns:
            Agent 名称到其依赖的 Agent 列表的映射
        """
        return {
            'agent_0': [],
            'agent_1': ['agent_0'],
            'agent_2': ['agent_1'],
            'agent_3': ['agent_2'],
            'agent_4': ['agent_3'],
            'agent_5': ['agent_4'],
            'agent_6': ['agent_3', 'agent_4', 'agent_5']
        }

    def get_parallelizable_agents(self) -> List[Tuple[str, str]]:
        """获取可并行的 Agent 对

        Returns:
            (Agent 组名, Agent 列表) 列表
        """
        return [
            ('stage_1', 'agent_0'),
            ('stage_2', 'agent_1'),
            ('stage_3_parallel', ['agent_3', 'agent_4', 'agent_5']),
            ('stage_4', 'agent_6'),
        ]
