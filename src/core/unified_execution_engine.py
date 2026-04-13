"""统一执行引擎

整合三种 AI 模式（pure-ai / standard / langgraph）的统一执行入口。
这是整个 Agent 能力系统统一化的核心组件。

核心功能：
- 统一的请求处理接口
- 自动模式选择和路由
- Pipeline 构建和执行
- 结果收集和反馈
"""

import asyncio
import time
from typing import Any, Dict, List, Optional, Type
from datetime import datetime

from .base_agent import (
    BaseAgent,
    ExecutionContext,
    AgentResult,
    ExecutionRequest,
    ExecutionResult,
    AgentStatus
)
from .agent_registry import get_agent_registry, AgentCapabilityRegistry
from .agent_pipeline import PipelineBuilder, AgentNode


class BaseExecutor:
    """执行器基类

    所有模式执行器必须继承此类。
    定义统一的执行接口。
    """

    def __init__(self, config=None, registry: Optional[AgentCapabilityRegistry] = None):
        self.config = config
        self.registry = registry or get_agent_registry()

    async def execute(
        self,
        pipeline: List[str],
        context: ExecutionContext
    ) -> ExecutionResult:
        """执行 Pipeline（子类必须实现）

        Args:
            pipeline: Agent 名称列表
            context: 执行上下文

        Returns:
            ExecutionResult: 执行结果
        """
        raise NotImplementedError

    def __repr__(self):
        return f"{self.__class__.__name__}(config={self.config is not None})"


class StandardExecutor(BaseExecutor):
    """标准模式执行器

    使用传统的规则 + AI 混合方式执行。
    适用于大多数场景，平衡速度和质量。
    """

    async def execute(
        self,
        pipeline: List[str],
        context: ExecutionContext
    ) -> ExecutionResult:
        from src.core.utils.time_utils import Timer
        from src.core.utils.agent_utils import get_agent_instance, check_agent_dependencies
        from src.core.utils.error_handling import create_error_result

        timer = Timer()
        timer.start()
        results = {}

        for agent_name in pipeline:
            agent_instance = get_agent_instance(agent_name, self.config, self.registry)

            if not agent_instance:
                results[agent_name] = create_error_result(
                    agent_name=agent_name,
                    error_message=f"Agent '{agent_name}' 未注册或无法实例化",
                    error_type="AgentNotFoundError"
                )
                continue

            try:
                # 检查Agent的依赖关系
                if not check_agent_dependencies(agent_instance, context):
                    # 依赖检查失败，创建失败结果
                    results[agent_name] = create_error_result(
                        agent_name=agent_name,
                        error_message=f"Agent '{agent_name}' 依赖检查失败，请确保其依赖的Agent已成功执行",
                        error_type="DependencyError",
                        metadata={
                            'agent_name': agent_name,
                            'completed_agents': list(context.results.keys())
                        }
                    )
                    context.add_result(agent_name, results[agent_name])
                    continue
                
                # 执行Agent
                result = await agent_instance.execute_with_hooks(context)
                # 先将结果添加到context中，再存储到results中
                # 这样后续的Agent可以看到当前Agent的结果
                context.add_result(agent_name, result)
                results[agent_name] = result

                if not result.is_success and agent_name != "report":
                    # 非 report Agent 失败时记录但继续
                    pass

            except Exception as e:
                results[agent_name] = create_error_result(
                    agent_name=agent_name,
                    error_message=str(e),
                    error_type=type(e).__name__
                )

        execution_time = timer.stop()
        all_findings = []
        for agent_name, r in results.items():
            # 跳过 ReportGeneratorAgent，因为它的 findings 是重复的（收集了其他 Agent 的 findings）
            if agent_name in ['report', 'ReportGeneratorAgent']:
                continue
            if r.findings:
                all_findings.extend(r.findings)

        return ExecutionResult(
            success=all(r.is_success for r in results.values() if r.agent_name != "report"),
            mode="standard",
            results=results,
            pipeline_used=pipeline,
            execution_time=execution_time,
            total_findings=len(all_findings),
            message=f"标准模式执行完成 ({execution_time:.2f}s)",
            metadata={'executor': 'standard'}
        )


class PureAIExecutor(BaseExecutor):
    """纯 AI 模式执行器

    所有步骤都使用 AI 完成，质量更高但更慢。
    强制使用 Agent 的 execute_ai_mode() 方法（如果有）。
    """

    async def execute(
        self,
        pipeline: List[str],
        context: ExecutionContext
    ) -> ExecutionResult:
        from src.core.utils.time_utils import Timer
        from src.core.utils.agent_utils import get_agent_instance, check_agent_dependencies
        from src.core.utils.error_handling import create_error_result

        timer = Timer()
        timer.start()
        results = {}

        if self.config:
            self.config.pure_ai = True
            if hasattr(context, 'config'):
                context.config = self.config

        for agent_name in pipeline:
            agent_instance = get_agent_instance(agent_name, self.config, self.registry)

            if not agent_instance:
                results[agent_name] = create_error_result(
                    agent_name=agent_name,
                    error_message=f"Agent '{agent_name}' 未注册",
                    error_type="AgentNotFoundError"
                )
                continue

            try:
                # 检查Agent的依赖关系
                if not check_agent_dependencies(agent_instance, context):
                    # 依赖检查失败，创建失败结果
                    results[agent_name] = create_error_result(
                        agent_name=agent_name,
                        error_message=f"Agent '{agent_name}' 依赖检查失败，请确保其依赖的Agent已成功执行",
                        error_type="DependencyError",
                        metadata={
                            'agent_name': agent_name,
                            'completed_agents': list(context.results.keys())
                        }
                    )
                    context.add_result(agent_name, results[agent_name])
                    continue
                
                # 尝试使用纯AI模式
                if hasattr(agent_instance, 'execute_ai_mode'):
                    result = await agent_instance.execute_ai_mode(context)
                else:
                    result = await agent_instance.execute_with_hooks(context)

                # 先将结果添加到context中，再存储到results中
                # 这样后续的Agent可以看到当前Agent的结果
                context.add_result(agent_name, result)
                results[agent_name] = result

            except Exception as e:
                results[agent_name] = create_error_result(
                    agent_name=agent_name,
                    error_message=f"纯AI执行失败: {str(e)}",
                    error_type=type(e).__name__
                )

        execution_time = timer.stop()
        all_findings = []
        for agent_name, r in results.items():
            # 跳过 ReportGeneratorAgent，因为它的 findings 是重复的（收集了其他 Agent 的 findings）
            if agent_name in ['report', 'ReportGeneratorAgent']:
                continue
            if r.findings:
                all_findings.extend(r.findings)

        return ExecutionResult(
            success=all(r.is_success for r in results.values() if r.agent_name != "report"),
            mode="pure-ai",
            results=results,
            pipeline_used=pipeline,
            execution_time=execution_time,
            total_findings=len(all_findings),
            message=f"纯AI模式执行完成 ({execution_time:.2f}s)",
            metadata={'executor': 'pure-ai'}
        )


class LangGraphExecutor(BaseExecutor):
    """LangGraph 流程执行器

    使用 LangGraph 的多 Agent 图流程。
    适用于复杂的分析场景，支持循环和条件分支。
    """

    async def execute(
        self,
        pipeline: List[str],
        context: ExecutionContext
    ) -> ExecutionResult:
        start_time = time.time()

        try:
            from src.core.langgraph_flow import run_pipeline as langgraph_run

            code = context.code or f"目标: {context.target}"

            langgraph_result = await langgraph_run(
                [self.registry.get(name) for name in pipeline if self.registry.get(name)],
                code=code,
                ask=context.user_query,
                focus=context.focus
            )

            # 转换 LangGraph 结果为统一的 ExecutionResult
            results = {}
            if isinstance(langgraph_result, dict):
                if 'final_report' in langgraph_result:
                    results['reason'] = AgentResult(
                        agent_name='reason',
                        status=AgentStatus.COMPLETED,
                        data=langgraph_result['final_report'],
                        message="LangGraph 分析完成",
                        confidence=langgraph_result['final_report'].get('quality_score', 0.7) if isinstance(langgraph_result['final_report'], dict) else 0.7
                    )

                if 'cve_candidates' in langgraph_result:
                    results['scan'] = AgentResult(
                        agent_name='scan',
                        status=AgentStatus.COMPLETED,
                        data={'cve_count': len(langgraph_result.get('cve_candidates', []))},
                        message=f"发现 {len(langgraph_result.get('cve_candidates', []))} 个CVE候选"
                    )

            execution_time = time.time() - start_time

            return ExecutionResult(
                success=True,
                mode="langgraph",
                results=results,
                pipeline_used=pipeline,
                execution_time=execution_time,
                total_findings=len(langgraph_result.get('cve_candidates', [])) if isinstance(langgraph_result, dict) else 0,
                message=f"LangGraph 执行完成 ({execution_time:.2f}s)",
                metadata={
                    'executor': 'langgraph',
                    'raw_result': langgraph_result if isinstance(langgraph_result, dict) else None
                }
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return ExecutionResult(
                success=False,
                mode="langgraph",
                execution_time=execution_time,
                error=f"LangGraph 执行失败: {str(e)}",
                message=f"LangGraph 错误: {str(e)}"
            )


class AutoExecutor(BaseExecutor):
    """AI 自适应执行器

    根据任务特征自动选择最佳执行模式和策略。
    这是 fix_0.md 要求的核心功能！

    工作原理：
    1. 分析请求复杂度
    2. 评估可用资源
    3. 查询历史效果（未来）
    4. 选择最优执行器
    """

    def __init__(self, config=None, registry=None, strategy_engine=None):
        super().__init__(config, registry)
        self.strategy_engine = strategy_engine

        # 内部执行器实例
        self._standard_executor = StandardExecutor(config, registry)
        self._pure_ai_executor = PureAIExecutor(config, registry)
        self._langgraph_executor = LangGraphExecutor(config, registry)

    async def execute(
        self,
        pipeline: List[str],
        context: ExecutionContext
    ) -> ExecutionResult:
        start_time = time.time()

        # 1. 分析并选择最佳执行器
        selected_executor = self._select_executor(pipeline, context)
        executor_name = selected_executor.__class__.__name__

        # 2. 记录决策过程
        decision_info = {
            'selected_executor': executor_name,
            'pipeline': pipeline,
            'decision_criteria': self._analyze_criteria(pipeline, context)
        }

        # 3. 委托给选定的执行器
        try:
            result = await selected_executor.execute(pipeline, context)

            # 注入元数据
            result.metadata['auto_decision'] = decision_info
            result.metadata['auto_mode'] = True

            return result

        except Exception as e:
            # 回退到标准执行器
            fallback_result = await self._standard_executor.execute(pipeline, context)
            fallback_result.metadata['auto_decision'] = {
                **decision_info,
                'fallback': True,
                'error': str(e)
            }
            fallback_result.message += " (从自适应模式回退)"
            return fallback_result

    def _select_executor(self, pipeline: List[str], context: ExecutionContext) -> BaseExecutor:
        """选择最佳执行器（基于规则的简单版本）"""
        config = context.config or self.config

        # 规则1：如果配置明确指定 pure-ai
        if config and getattr(config, 'pure_ai', False):
            return self._pure_ai_executor

        # 规则2：如果 Pipeline 包含需要复杂推理的步骤
        complex_agents = {'attack-chain', 'poc'}
        if any(agent in complex_agents for agent in pipeline):
            if len(pipeline) >= 4:
                return self._langgraph_executor
            elif len(pipeline) >= 3:
                return self._pure_ai_executor

        # 规则3：如果用户查询包含深度分析关键词
        query = (context.user_query or '').lower()
        deep_keywords = ['deep', 'thorough', 'comprehensive', '详细', '深入', '全面']
        if any(kw in query for kw in deep_keywords):
            return self._pure_ai_executor

        # 默认：使用标准执行器
        return self._standard_executor

    def _analyze_criteria(self, pipeline: List[str], context: ExecutionContext) -> Dict:
        """分析选择标准（用于调试和日志）"""
        return {
            'pipeline_length': len(pipeline),
            'has_complex_agents': bool({'attack-chain', 'poc'} & set(pipeline)),
            'has_user_query': bool(context.user_query),
            'target_type': 'file' if '.' in context.target and context.target.endswith(('.py', '.js', '.ts')) else 'directory'
        }


class UnifiedExecutionEngine:
    """统一执行引擎

    整合所有模式的单一入口点。
    支持多种输入格式：
    - CLI flags
    - 自然语言
    - Plan DSL

    使用示例:
        engine = UnifiedExecutionEngine(config)

        # 方式1：CLI flags
        request = ExecutionRequest(target=".", flags=["--scan", "--reason"])
        result = await engine.execute(request)

        # 方式2：自然语言
        request = ExecutionRequest(target=".", natural_language="扫描并生成报告")
        result = await engine.execute(request)
    """

    def __init__(
        self,
        config=None,
        registry: Optional[AgentCapabilityRegistry] = None,
        strategy_engine=None
    ):
        self.config = config
        self.registry = registry or get_agent_registry()
        self.strategy_engine = strategy_engine

        # 初始化各模式执行器
        self.executors = {
            'standard': StandardExecutor(config, self.registry),
            'pure-ai': PureAIExecutor(config, self.registry),
            'langgraph': LangGraphExecutor(config, self.registry),
            'auto': AutoExecutor(config, self.registry, strategy_engine)
        }

    async def execute(
        self,
        request: ExecutionRequest,
        mode: Optional[str] = None
    ) -> ExecutionResult:
        """
        统一执行入口

        Args:
            request: 执行请求（支持 flags/natural_language/plan）
            mode: 执行模式 (auto/pure-ai/standard/langgraph)
                   如果为 None，则从 request.mode 获取

        Returns:
            ExecutionResult: 统一的执行结果
        """
        start_time = time.time()

        # 确定执行模式
        exec_mode = mode or request.mode or 'auto'

        try:
            # 1. 构建 Pipeline
            pipeline = await self._build_pipeline(request)

            if not pipeline:
                return ExecutionResult(
                    success=False,
                    mode=exec_mode,
                    error="无法构建有效的 Pipeline",
                    message="请提供有效的命令或自然语言描述"
                )

            # 2. 创建执行上下文
            context = self._create_context(request)

            # 3. 选择执行器
            executor = self.executors.get(exec_mode, self.executors['auto'])

            # 4. 执行
            result = await executor.execute(pipeline, context)

            # 5. 后处理
            result.execution_time = time.time() - start_time
            result.pipeline_used = pipeline

            # 6. 收集反馈（如果启用）
            if self.config and getattr(self.config, 'feedback', None):
                if getattr(self.config.feedback, 'collect_auto', False):
                    try:
                        self._collect_feedback(request, pipeline, result)
                    except Exception as feedback_error:
                        # 反馈收集失败不应影响主流程
                        if self.config and getattr(self.config, 'debug', False):
                            print(f"[DEBUG] 反馈收集失败: {feedback_error}")

            return result
        except Exception as e:
            # 捕获所有异常，确保框架不会崩溃
            execution_time = time.time() - start_time
            error_message = f"执行失败: {str(e)}"
            
            # 在调试模式下打印详细错误信息
            if self.config and getattr(self.config, 'debug', False):
                import traceback
                traceback.print_exc()
            
            return ExecutionResult(
                success=False,
                mode=exec_mode,
                error=error_message,
                message=error_message,
                execution_time=execution_time,
                pipeline_used=[],
                total_findings=0,
                metadata={'error_details': str(e)}
            )

    async def _build_pipeline(self, request: ExecutionRequest) -> List[str]:
        """根据请求类型构建 Pipeline"""
        try:
            if request.flags:
                return self.registry.build_pipeline_from_flags(
                    request.flags,
                    auto_complete=True,
                    expand_macros=True
                )

            elif request.natural_language:
                return await self._nl_to_pipeline(request.natural_language)

            elif hasattr(request, 'plan') and request.plan:
                return self._plan_to_pipeline(request.plan)

            else:
                # 默认 Pipeline
                return ['scan', 'report']
        except Exception as e:
            # 构建 Pipeline 失败时返回默认 Pipeline
            if self.config and getattr(self.config, 'debug', False):
                print(f"[DEBUG] Pipeline 构建失败: {e}")
            return ['scan', 'report']

    async def _nl_to_pipeline(self, text: str) -> List[str]:
        """将自然语言转换为 Pipeline"""
        try:
            from src.core.intelligent_pipeline_builder import IntelligentPipelineBuilder

            ai_client = None
            if self.config:
                try:
                    from src.ai.client import get_model_manager
                    model_manager = await get_model_manager(self.config)
                    ai_client = model_manager.get_default_client()
                except Exception as client_error:
                    if self.config and getattr(self.config, 'debug', False):
                        print(f"[DEBUG] AI 客户端初始化失败: {client_error}")

            nodes = IntelligentPipelineBuilder.from_natural_language(text, ai_client, self.config)
            return [node.type.value for node in nodes]
        except Exception as e:
            # 自然语言转换失败时返回默认 Pipeline
            if self.config and getattr(self.config, 'debug', False):
                print(f"[DEBUG] 自然语言转换失败: {e}")
            return ['scan', 'report']

    def _plan_to_pipeline(self, plan) -> List[str]:
        """将 Plan 对象转换为 Pipeline"""
        try:
            nodes = IntelligentPipelineBuilder.from_plan(plan)
            return [node.type.value for node in nodes]
        except Exception as e:
            # Plan 转换失败时返回默认 Pipeline
            if self.config and getattr(self.config, 'debug', False):
                print(f"[DEBUG] Plan 转换失败: {e}")
            return ['scan', 'report']

    def _create_context(self, request: ExecutionRequest) -> ExecutionContext:
        """创建执行上下文"""
        try:
            # 直接使用原始配置引用，避免深拷贝带来的内存开销
            # 注意：这里假设执行过程中不会修改配置对象
            config = self.config
            
            # 应用测试模式参数（仅在测试模式下）
            if hasattr(request, 'test_mode') and request.test_mode:
                # 如果需要修改配置，创建一个浅拷贝
                import copy
                config = copy.copy(self.config)
                config.test_mode = True
                if hasattr(request, 'test_file_count'):
                    config.test_file_count = request.test_file_count
            
            context = ExecutionContext(
                target=request.target,
                config=config,
                user_intent=request.natural_language or str(request.flags),
                user_query=request.context.get('ask'),
                focus=request.context.get('focus')
            )

            # 如果提供了代码内容
            if request.context.get('code'):
                context.code = request.context['code']

            return context
        except Exception as e:
            # 上下文创建失败时使用默认配置
            if self.config and getattr(self.config, 'debug', False):
                print(f"[DEBUG] 上下文创建失败: {e}")
            
            # 使用原始配置
            context = ExecutionContext(
                target=request.target,
                config=self.config,
                user_intent=request.natural_language or str(request.flags),
                user_query=request.context.get('ask'),
                focus=request.context.get('focus')
            )
            
            if request.context.get('code'):
                context.code = request.context['code']
            
            return context

    def _collect_feedback(
        self,
        request: ExecutionRequest,
        pipeline: List[str],
        result: ExecutionResult
    ) -> None:
        """收集执行反馈（用于 AI 学习）"""
        feedback_data = {
            'timestamp': datetime.now().isoformat(),
            'request_type': request.request_type,
            'pipeline': pipeline,
            'mode': result.mode,
            'success': result.success,
            'execution_time': result.execution_time,
            'findings_count': result.total_findings
        }

        # TODO: 实际存储到数据库或文件
        # 这里只是示例打印
        if self.config and getattr(self.config, 'debug', False):
            print(f"[FEEDBACK] Collected: {feedback_data}")

    def get_available_modes(self) -> List[str]:
        """获取可用的执行模式列表"""
        return list(self.executors.keys())

    def get_statistics(self) -> Dict[str, Any]:
        """获取引擎统计信息"""
        registry_stats = self.registry.get_statistics()

        return {
            'registry': registry_stats,
            'available_modes': self.get_available_modes(),
            'config_loaded': self.config is not None,
            'strategy_engine_loaded': self.strategy_engine is not None
        }


__all__ = [
    'UnifiedExecutionEngine',
    'BaseExecutor',
    'StandardExecutor',
    'PureAIExecutor',
    'LangGraphExecutor',
    'AutoExecutor'
]
