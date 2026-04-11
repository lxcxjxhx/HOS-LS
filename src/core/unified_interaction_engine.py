"""统一智能交互引擎

整合聊天模式和Agent编排语言的核心类。
提供统一的交互接口，支持：
- 自然语言处理
- Agent Pipeline 构建与执行
- Plan 管理
- 双向转换（自然语言 ↔ CLI/Pipeline）
- AI API 动态配置（零硬编码）
"""

from typing import Dict, Any, Optional, List
import asyncio
import os
from datetime import datetime

from src.core.config import Config
from src.core.conversation_manager import ConversationManager
from src.core.intelligent_pipeline_builder import IntelligentPipelineBuilder
from src.core.intent_parser import IntentParser, IntentType, ParsedIntent
from src.core.plan_manager import PlanManager
from src.core.ai_config_validator import AIConfigValidator


class UnifiedInteractionEngine:
    """统一智能交互引擎
    
    这是整个智能交互模式的核心，整合了：
    - 聊天模式的自然语言理解
    - Agent 编排语言的 Pipeline 构建
    - AI 驱动的意图识别和响应生成
    
    使用示例:
    >>> engine = UnifiedInteractionEngine(config)
    >>> result = engine.process("扫描当前目录")
    >>> print(result)
    """
    
    def __init__(self, config: Config, session_name: Optional[str] = None):
        """初始化统一交互引擎

        Args:
            config: 配置对象（必须包含AI相关配置）
            session_name: 会话名称（可选，用于持久化）
        """
        self.config = config
        
        # 初始化各组件
        self.conversation_manager = ConversationManager(config, session_name)
        self.pipeline_builder = IntelligentPipelineBuilder
        self.plan_manager = PlanManager(config)
        self.intent_parser = None  # 延迟初始化
        self.ai_client = None  # 延迟初始化
        
        # 🔥 新增：统一执行引擎（用于 Agent 能力系统）
        self.unified_engine = None  # 延迟初始化
        
        # 状态标志
        self._initialized = False
        self._initialization_error = None
        
    async def initialize(self):
        """异步初始化AI客户端（懒加载）
        
        从配置动态加载AI客户端，确保零硬编码。
        
        Raises:
            RuntimeError: 如果AI客户端初始化失败
        """
        if self._initialized:
            return
            
        try:
            from src.ai.client import get_model_manager
            from src.core.unified_execution_engine import UnifiedExecutionEngine  # 🔥 新增
            
            model_manager = await get_model_manager(self.config)
            self.ai_client = model_manager.get_default_client()
            
            if not self.ai_client:
                raise RuntimeError(
                    "❌ 无法初始化AI客户端\n\n"
                    "请检查以下配置:\n"
                    "1. 设置API密钥环境变量:\n"
                    "   Windows: set DEEPSEEK_API_KEY=sk-xxx\n"
                    "   Linux/Mac: export DEEPSEEK_API_KEY=sk-xxx\n\n"
                    "2. 或在配置文件中设置:\n"
                    "   ai:\n"
                    "     provider: deepseek\n"
                    "     api_key: sk-xxx\n\n"
                    f"3. 当前配置: {AIConfigValidator.validate(self.config)[2]}"
                )
            
            # 初始化意图解析器（带AI增强能力）
            self.intent_parser = IntentParser(self.ai_client)
            
            # 🔥🔥🔥 初始化统一执行引擎（核心改动！）
            self.unified_engine = UnifiedExecutionEngine(
                config=self.config,
                strategy_engine=None  # 暂时不启用策略引擎
            )
            
            self._initialized = True
            
        except Exception as e:
            self._initialization_error = str(e)
            # 即使AI不可用也继续工作（降级到规则模式）
            self.intent_parser = IntentParser(None)  # 仅使用规则解析
            self._initialized = True  # 标记为已初始化（虽然部分功能受限）
    
    def ensure_initialized(self):
        """确保已初始化（同步包装）"""
        if not self._initialized:
            asyncio.run(self.initialize())
    
    def process(self, user_input: str) -> Dict[str, Any]:
        """处理用户输入（主入口）
        
        这是统一的入口点，自动路由到合适的处理器：
        - 自然语言命令 → IntentParser (AI增强) → AI Plan Generator → User Confirmation → Execution
        - CLI命令 → CLIParser → PipelineBuilder  
        - Plan DSL → PlanParser → PipelineExecutor
        
        Args:
            user_input: 用户输入文本
            
        Returns:
            处理结果字典
        """
        if not user_input or not user_input.strip():
            return {
                "type": "error",
                "error": "输入不能为空",
                "message": "请输入有效的命令或问题"
            }
        
        # 确保初始化
        self.ensure_initialized()
        
        # 记录到会话历史
        self.conversation_manager.add_user_message(user_input)
        
        try:
            # 解析意图（默认使用AI增强）
            intent = self.intent_parser.parse(user_input)
            
            # 处理多任务命令
            if 'tasks' in intent.entities:
                return self._handle_multi_task_with_plan(intent, user_input)
            
            # 根据意图类型分发处理（带AI计划生成）
            result = self._dispatch_intent_with_plan(intent, user_input)
            
            # 记录助手回复
            if result.get('type') != 'error':
                self.conversation_manager.add_assistant_message(
                    str(result.get('message', result.get('display', ''))),
                    metadata={"intent_type": intent.type.value}
                )
            
            # 更新上下文
            self.conversation_manager.update_context(result)
            
            return result
            
        except Exception as e:
            error_result = {
                "type": "error",
                "error": str(e),
                "message": f"处理请求时出错: {str(e)}"
            }
            self.conversation_manager.update_context(error_result)
            return error_result
    
    def _handle_multi_task_with_plan(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理多任务命令，带计划生成和用户确认
        
        Args:
            intent: 解析后的意图
            user_input: 用户输入文本
            
        Returns:
            处理结果字典
        """
        from src.core.ai_plan_generator import get_ai_plan_generator
        
        # 生成执行计划
        plan_generator = get_ai_plan_generator()
        import asyncio
        plan = asyncio.run(plan_generator.generate_plan(intent, user_input))
        
        # 生成人类友好的计划表述
        plan_text = plan_generator.generate_human_friendly_plan(plan)
        
        # 显示计划并获取用户确认
        print(plan_text)
        
        # 获取用户确认
        confirmation = input("请输入您的选择 (yes/no/modify): ").strip().lower()
        
        if confirmation == 'yes':
            # 用户确认执行计划
            return asyncio.run(self._execute_plan(plan))
        elif confirmation == 'no':
            # 用户拒绝执行
            return {
                "type": "plan_canceled",
                "message": "计划已取消"
            }
        elif confirmation == 'modify':
            # 用户要求修改计划
            user_feedback = input("请输入您的修改建议: ").strip()
            adjusted_plan = asyncio.run(plan_generator.adjust_plan(plan, user_feedback))
            adjusted_plan_text = plan_generator.generate_human_friendly_plan(adjusted_plan)
            print(adjusted_plan_text)
            
            # 获取用户对调整后计划的确认
            adjust_confirmation = input("请确认调整后的计划 (yes/no): ").strip().lower()
            if adjust_confirmation == 'yes':
                return asyncio.run(self._execute_plan(adjusted_plan))
            else:
                return {
                    "type": "plan_canceled",
                    "message": "计划已取消"
                }
        else:
            # 无效输入，默认取消
            return {
                "type": "plan_canceled",
                "message": "无效输入，计划已取消"
            }
    
    def _dispatch_intent_with_plan(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """根据意图分发处理，带计划生成和用户确认
        
        Args:
            intent: 解析后的意图
            user_input: 用户输入文本
            
        Returns:
            处理结果字典
        """
        from src.core.ai_plan_generator import get_ai_plan_generator
        
        # 生成执行计划
        plan_generator = get_ai_plan_generator()
        import asyncio
        plan = asyncio.run(plan_generator.generate_plan(intent, user_input))
        
        # 生成人类友好的计划表述
        plan_text = plan_generator.generate_human_friendly_plan(plan)
        
        # 显示计划并获取用户确认
        print(plan_text)
        
        # 获取用户确认
        confirmation = input("请输入您的选择 (yes/no/modify): ").strip().lower()
        
        if confirmation == 'yes':
            # 用户确认执行计划
            return asyncio.run(self._execute_plan(plan))
        elif confirmation == 'no':
            # 用户拒绝执行
            return {
                "type": "plan_canceled",
                "message": "计划已取消"
            }
        elif confirmation == 'modify':
            # 用户要求修改计划
            user_feedback = input("请输入您的修改建议: ").strip()
            adjusted_plan = asyncio.run(plan_generator.adjust_plan(plan, user_feedback))
            adjusted_plan_text = plan_generator.generate_human_friendly_plan(adjusted_plan)
            print(adjusted_plan_text)
            
            # 获取用户对调整后计划的确认
            adjust_confirmation = input("请确认调整后的计划 (yes/no): ").strip().lower()
            if adjust_confirmation == 'yes':
                return asyncio.run(self._execute_plan(adjusted_plan))
            else:
                return {
                    "type": "plan_canceled",
                    "message": "计划已取消"
                }
        else:
            # 无效输入，默认取消
            return {
                "type": "plan_canceled",
                "message": "无效输入，计划已取消"
            }
    
    async def _execute_plan(self, plan: Any) -> Dict[str, Any]:
        """执行计划（支持断点续扫）
        
        Args:
            plan: 执行计划
            
        Returns:
            执行结果
        """
        results = []
        
        # 初始化断点续扫管理器
        from src.core.checkpoint_manager import CheckpointManager, get_checkpoint_manager
        checkpoint_manager = get_checkpoint_manager()
        
        # 初始化增量索引管理器
        from src.utils.incremental_index import IncrementalIndexManager, get_incremental_index_manager
        index_manager = get_incremental_index_manager()
        incremental_plan = None  # 将在扫描步骤中使用
        
        # 检查是否有可恢复的Checkpoint
        plan_id = getattr(plan, 'id', f"plan_{id(plan)}")
        existing_checkpoint = await checkpoint_manager.load_latest_checkpoint(plan_id)
        
        start_step_index = 0
        
        if existing_checkpoint:
            # 发现已有Checkpoint，询问用户是否恢复
            print(f"\n{'='*80}")
            print(f"\n[bold yellow]💾 发现已保存的CheckPoint[/bold yellow]")
            print(f"   📅 保存时间: {existing_checkpoint.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   📍 上次位置: 第{existing_checkpoint.current_step_index + 1}步/{existing_checkpoint.total_steps}步")
            
            if existing_checkpoint.scan_progress:
                print(f"\n   {existing_checkpoint.scan_progress.to_summary()}")
            
            print(f"\n{'='*80}")
            
            user_choice = input("\n是否从上次中断的位置继续？(y/n/查看详情d): ").strip().lower()
            
            if user_choice == 'y' or user_choice == 'yes':
                # 恢复Checkpoint
                restore_result = await checkpoint_manager.restore_from_checkpoint(existing_checkpoint.checkpoint_id)
                
                if restore_result.success:
                    print(f"\n[bold green]✅ {restore_result.message}[/bold green]")
                    print(f"   ▶️ 从第{restore_result.resumed_step_index + 1}步继续执行")
                    
                    # 恢复已完成步骤的结果
                    if existing_checkpoint.completed_results:
                        results.extend(existing_checkpoint.completed_results.get('results', []))
                    
                    start_step_index = restore_result.resumed_index + 1
                else:
                    print(f"\n[bold red]❌ 恢复失败: {restore_result.message}[/bold red]")
                    print("   将从头开始执行...")
                    start_step_index = 0
                    
            elif user_choice == 'd' or user_choice == 'details':
                # 显示Checkpoint详细信息
                print(f"\n📋 CheckPoint详细信息:")
                print(f"   ID: {existing_checkpoint.checkpoint_id}")
                print(f"   任务类型: {existing_checkpoint.task_type}")
                print(f"   元数据: {existing_checkpoint.metadata}")
                
                # 列出所有Checkpoint
                all_ckpts = checkpoint_manager.list_all_checkpoints()
                if len(all_ckpts) > 1:
                    print(f"\n📚 其他可用Checkpoint:")
                    for ckpt in all_ckpts[:5]:
                        if ckpt['id'] != existing_checkpoint.checkpoint_id:
                            print(f"   • [{ckpt['id'][:16]}...] {ckpt['task_type']} - 步骤{ckpt['step']}")
                
                user_choice2 = input("\n选择一个Checkpoint恢复（输入ID）或按回车从头开始: ").strip()
                
                if user_choice2 and user_choice2 != '':
                    restore_result = await checkpoint_manager.restore_from_checkpoint(user_choice2)
                    if restore_result.success:
                        start_step_index = restore_result.resumed_step_index + 1
                        if existing_checkpoint.completed_results:
                            results.extend(existing_checkpoint.completed_results.get('results', []))
                    else:
                        print(f"⚠️ 无法恢复指定的Checkpoint，从头开始...")
                        start_step_index = 0
                else:
                    start_step_index = 0
            else:
                # 用户选择不恢复
                print("\nℹ️ 从头开始执行...")
                start_step_index = 0
        
        # 按顺序执行计划步骤（从start_step_index开始）
        for i, step in enumerate(plan.steps[start_step_index:], start=start_step_index + 1):
            actual_index = i - 1  # 实际在列表中的索引（从0开始）
            
            print(f"\n{'='*80}")
            print(f"\n[bold cyan]🔄 步骤 {i}/{len(plan.steps)}: {step.name}[/bold cyan]")
            print(f"📝 描述: {step.description}")
            print(f"🔧 使用模块: {step.module}")
            print(f"⚙️ 参数: {step.parameters}")
            print(f"{'='*80}")
            
            try:
                # 根据模块类型执行不同的操作
                if step.module == 'info':
                    # 执行信息查询
                    topic = step.parameters.get('topic', '漏洞扫描工作原理')
                    explanation = self._explain_scan_principle()
                    results.append({
                        "type": "info_result",
                        "message": explanation
                    })
                elif step.module == 'scan':
                    # 执行扫描
                    # 优先使用code_tool创建的测试文件路径
                    target = None
                    # 查找前面步骤中code_tool创建的测试文件
                    for prev_step in plan.steps:
                        if prev_step.module == 'code_tool' and 'target' in prev_step.parameters:
                            target = prev_step.parameters['target']
                            break
                    # 如果没有找到，使用默认值
                    if not target:
                        target = step.parameters.get('target', '.')
                    # 优先使用计划的pure_ai设置
                    mode = 'pure-ai' if plan.pure_ai else step.parameters.get('mode', 'auto')
                    
                    # ========== 增量索引优化 ==========
                    use_incremental = False
                    try:
                        # 初始化项目索引（如果尚未初始化）
                        await index_manager.initialize_for_project(target)
                        
                        # 获取增量扫描计划
                        incremental_plan = await index_manager.get_incremental_scan_plan()
                        
                        # 判断是否应该使用增量模式
                        if incremental_plan.has_changes and incremental_plan.should_use_incremental:
                            use_incremental = True
                            
                            print(f"\n[bold yellow]⚡ 增量扫描模式已启用[/bold yellow]")
                            print(f"   {incremental_plan.change_stats.to_summary()}")
                            print(f"   📁 需要扫描: {len(incremental_plan.files_to_scan)} 个文件")
                            print(f"   ⏭️ 可跳过: {len(incremental_plan.files_to_skip)} 个文件")
                            print(f"   ⏱️ 预计节省: ~{incremental_plan.estimated_time_saving:.0f}秒")
                            
                            # 将增量信息传递给扫描请求
                            if 'target_files' not in step.parameters:
                                step.parameters['target_files'] = incremental_plan.files_to_scan
                            if 'skip_files' not in step.parameters:
                                step.parameters['skip_files'] = incremental_plan.files_to_skip
                                
                    except Exception as idx_err:
                        print(f"[dim]⚠️ 增量索引初始化失败，将使用全量扫描: {str(idx_err)}[/dim]")
                        use_incremental = False
                    # ====================================
                    
                    # 构建扫描请求
                    from src.core.base_agent import ExecutionRequest
                    request = ExecutionRequest(
                        target=target,
                        natural_language=plan.user_input,
                        mode=mode,
                        test_mode=plan.test_mode,
                        test_file_count=plan.test_file_count,
                        use_incremental=use_incremental,
                        target_files=step.parameters.get('target_files') if use_incremental else None,
                        skip_files=step.parameters.get('skip_files') if use_incremental else None
                    )
                    
                    # 执行扫描
                    import asyncio
                    print(f"\n[bold cyan]⏳ 正在执行扫描...[/bold cyan]")
                    result = await self.unified_engine.execute(request, mode=mode)
                    
                    # 更新扫描进度到Checkpoint
                    if hasattr(result, 'total_files') and hasattr(result, 'processed_files'):
                        await checkpoint_manager.update_scan_progress(
                            current_file=getattr(result, 'current_file', None),
                            processed_count=getattr(result, 'processed_files', 0),
                            total_files=getattr(result, 'total_files', 0),
                            issues_found=getattr(result, 'total_findings', 0)
                        )
                        
                        # 显示当前进度
                        progress_summary = checkpoint_manager.get_progress_summary()
                        if progress_summary:
                            print(f"\n[dim]{progress_summary}[/dim]")
                        
                        # 自动保存Checkpoint（如果达到间隔）
                        saved_ckpt_id = await checkpoint_manager.auto_save_if_needed()
                        if saved_ckpt_id:
                            print(f"[dim]💾 进度已自动保存 (Checkpoint: {saved_ckpt_id[:16]}...)[/dim]")
                    
                    scan_result = {
                        "type": "scan_result",
                        "target": target,
                        "mode": mode,
                        "test_mode": plan.test_mode,
                        "test_file_count": plan.test_file_count,
                        "incremental_mode": use_incremental,
                        "result": result.to_dict() if hasattr(result, 'to_dict') else {
                            'success': result.success,
                            'message': result.message,
                            'findings_count': result.total_findings,
                            'pipeline': result.pipeline_used,
                            'execution_time': result.execution_time
                        },
                        "message": f"✅ {result.message} (模式: {mode.upper()}, {'增量' if use_incremental else '全量'}, 测试模式: {'是' if plan.test_mode else '否'}, 文件数量: {plan.test_file_count})"
                    }
                    
                    # 更新增量索引（如果使用了增量模式）
                    if use_incremental and incremental_plan:
                        try:
                            # 提取扫描结果用于更新索引
                            analyzed_files = getattr(result, 'analyzed_files', incremental_plan.files_to_scan)
                            scan_results_data = {}
                            
                            if hasattr(result, 'findings') and result.findings:
                                for finding in result.findings:
                                    if hasattr(finding, 'file_path'):
                                        scan_results_data[finding.file_path] = {
                                            'issues': [finding],
                                            'risk_score': getattr(finding, 'severity', 5.0)
                                        }
                            
                            await index_manager.update_index_after_scan(
                                analyzed_files=analyzed_files,
                                results=scan_results_data
                            )
                            
                            print(f"[dim]💾 增量索引已更新[/dim]")
                            
                        except Exception as idx_update_err:
                            print(f"[dim]⚠️ 索引更新失败（不影响扫描结果）: {str(idx_update_err)}[/dim]")
                    
                    results.append(scan_result)
                elif step.module == 'report':
                    # 生成报告
                    format = step.parameters.get('format', 'html')
                    output = step.parameters.get('output', './security-report')
                    
                    # 调用报告生成模块
                    try:
                        from src.troubleshooting.report_generator import ReportGenerator
                        import os
                        
                        # 确保输出目录存在
                        os.makedirs(os.path.dirname(output) if os.path.dirname(output) else '.', exist_ok=True)
                        
                        # 生成报告
                        generator = ReportGenerator()
                        report_path = generator.generate_report(
                            scan_results=[],  # 这里应该传递实际的扫描结果
                            format=format,
                            output_path=output
                        )
                        
                        report_result = {
                            "type": "report_result",
                            "format": format,
                            "output": report_path,
                            "message": f"✅ 报告已生成，保存到: {report_path}"
                        }
                    except Exception as e:
                        report_result = {
                            "type": "report_result",
                            "format": format,
                            "output": output,
                            "message": f"⚠️ 报告生成失败: {str(e)}"
                        }
                    
                    results.append(report_result)
                elif step.module == 'code_tool':
                    # 执行代码工具模块
                    action = step.parameters.get('action', 'prepare_test_file')
                    file_count = step.parameters.get('file_count', 1)
                    
                    try:
                        import os
                        import tempfile
                        
                        # 创建测试文件
                        if action == 'prepare_test_file' or action == 'create_test_file':
                            # 创建临时测试文件
                            test_files = []
                            for i in range(file_count):
                                with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as f:
                                    # 写入有漏洞的测试代码
                                    test_code = '''
# 测试文件 - 包含一些常见漏洞

def insecure_function():
    # SQL注入漏洞
    import sqlite3
    user_input = input("请输入用户名: ")
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # 不安全的SQL查询
    cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
    
    # XSS漏洞
    def render_user_input(user_input):
        return f"<div>{user_input}</div>"
    
    # 硬编码密码
    password = "admin123"
    
    # 不安全的文件操作
    with open("sensitive.txt", "w") as f:
        f.write("敏感信息")
'''
                                    f.write(test_code.encode('utf-8'))
                                    test_files.append(f.name)
                            
                            # 更新step的target参数，以便后续扫描使用
                            if test_files:
                                step.parameters['target'] = test_files[0]
                            
                            module_result = {
                                "type": "module_result",
                                "module": step.module,
                                "parameters": step.parameters,
                                "message": f"✅ 成功创建 {len(test_files)} 个测试文件: {', '.join(test_files)}"
                            }
                        else:
                            module_result = {
                                "type": "module_result",
                                "module": step.module,
                                "parameters": step.parameters,
                                "message": f"✅ 模块 {step.module} 执行完成 (动作: {action})"
                            }
                    except Exception as e:
                        module_result = {
                            "type": "module_result",
                            "module": step.module,
                            "parameters": step.parameters,
                            "message": f"⚠️ 模块 {step.module} 执行失败: {str(e)}"
                        }
                    
                    results.append(module_result)
                else:
                    # 其他模块
                    module_result = {
                        "type": "module_result",
                        "module": step.module,
                        "parameters": step.parameters,
                        "message": f"✅ 模块 {step.module} 执行完成"
                    }
                    
                    results.append(module_result)
                
                print(f"\n[bold green]✅ 步骤 {i}/{len(plan.steps)}: {step.name} 执行完成[/bold green]")
                print(f"{'='*80}")
                
                # 步骤完成后保存Checkpoint（关键步骤）
                try:
                    await checkpoint_manager.create_checkpoint(
                        task_type=step.module,
                        plan_id=plan_id,
                        step_index=actual_index,
                        total_steps=len(plan.steps),
                        step_status="completed",
                        results={'results': results},
                        metadata={
                            'mode': getattr(plan, 'pure_ai', False),
                            'target': target if 'target' in dir() else None
                        }
                    )
                except Exception as ckpt_err:
                    print(f"[dim]⚠️ Checkpoint保存失败（不影响执行）: {str(ckpt_err)}[/dim]")
                
                # 添加步骤过渡延迟，使执行过程更加流畅
                import time
                if i < len(plan.steps):
                    print("\n[dim]准备执行下一步...[/dim]")
                    time.sleep(1)
                
            except Exception as e:
                error_message = f"❌ 步骤 {i}/{len(plan.steps)}: {step.name} 执行失败: {str(e)}"
                print(f"\n[bold red]{error_message}[/bold red]")
                print(f"{'='*80}")
                
                # 保存错误状态到Checkpoint（用于后续恢复）
                try:
                    await checkpoint_manager.create_checkpoint(
                        task_type=step.module,
                        plan_id=plan_id,
                        step_index=actual_index,
                        total_steps=len(plan.steps),
                        step_status="failed",
                        results={'results': results, 'last_error': str(e)},
                        metadata={'error_step': step.name, 'error_time': datetime.now().isoformat()}
                    )
                    print(f"[dim]💾 已保存失败状态的Checkpoint（可稍后恢复）[/dim]")
                except Exception as ckpt_err:
                    pass  # Checkpoint保存失败不阻塞主流程
                
                results.append({
                    "type": "error",
                    "error": str(e),
                    "message": error_message
                })
        
        # 构建最终结果
        final_result = {
            "type": "plan_execution_result",
            "plan_name": plan.name,
            "steps": [step.name for step in plan.steps],
            "results": results,
            "message": "✅ 计划执行完成"
        }
        
        return final_result
    
    def _handle_multi_task(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理多任务命令
        
        Args:
            intent: 解析后的意图
            user_input: 用户输入文本
            
        Returns:
            处理结果字典
        """
        tasks = intent.entities.get('tasks', [])
        results = []
        task_status = []
        
        # 按顺序执行任务
        for task in tasks:
            task_type = task.get('type')
            task_content = task.get('content')
            
            try:
                # 记录任务开始
                task_status.append({
                    "type": task_type,
                    "status": "running",
                    "content": task_content
                })
                
                if task_type == 'explain':
                    # 执行讲解任务
                    explanation = self._explain_scan_principle()
                    results.append({
                        "type": "info_result",
                        "message": explanation
                    })
                    
                    # 记录讲解结果
                    self.conversation_manager.add_assistant_message(explanation, metadata={"task_type": "explain"})
                    
                    # 更新任务状态
                    task_status[-1]["status"] = "completed"
                    
                elif task_type == 'scan':
                    # 执行扫描任务
                    target = IntentParser.extract_target_path(user_input)
                    pure_ai = intent.entities.get('pure_ai', False)
                    test_mode = intent.entities.get('test_mode', False)
                    test_file_count = intent.entities.get('test_file_count', 1)
                    
                    # 构建扫描请求
                    from src.core.base_agent import ExecutionRequest
                    request = ExecutionRequest(
                        target=target,
                        natural_language=user_input,
                        mode="pure-ai" if pure_ai else "auto",
                        test_mode=test_mode,
                        test_file_count=test_file_count
                    )
                    
                    # 执行扫描
                    import asyncio
                    result = asyncio.run(self.unified_engine.execute(request))
                    
                    scan_result = {
                        "type": "scan_result",
                        "target": target,
                        "pure_ai": pure_ai or result.mode == "pure-ai",
                        "mode": result.mode,
                        "test_mode": test_mode,
                        "test_file_count": test_file_count,
                        "result": result.to_dict() if hasattr(result, 'to_dict') else {
                            'success': result.success,
                            'message': result.message,
                            'findings_count': result.total_findings,
                            'pipeline': result.pipeline_used,
                            'execution_time': result.execution_time
                        },
                        "message": f"✅ {result.message} (模式: {result.mode.upper()}, 测试模式: {'是' if test_mode else '否'}, 文件数量: {test_file_count})"
                    }
                    
                    results.append(scan_result)
                    
                    # 记录扫描结果
                    self.conversation_manager.add_assistant_message(
                        scan_result.get('message'),
                        metadata={"task_type": "scan"}
                    )
                    
                    # 更新任务状态
                    task_status[-1]["status"] = "completed"
                    
            except Exception as e:
                # 处理任务执行错误
                error_message = f"任务执行失败: {str(e)}"
                results.append({
                    "type": "error",
                    "error": str(e),
                    "message": error_message
                })
                
                # 记录错误
                self.conversation_manager.add_assistant_message(error_message, metadata={"task_type": task_type, "status": "error"})
                
                # 更新任务状态
                task_status[-1]["status"] = "failed"
                task_status[-1]["error"] = str(e)
        
        # 构建最终结果
        final_result = {
            "type": "multi_task_result",
            "tasks": tasks,
            "task_status": task_status,
            "results": results,
            "message": "✅ 多任务执行完成"
        }
        
        # 更新上下文
        self.conversation_manager.update_context(final_result)
        
        return final_result
    
    def _explain_scan_principle(self) -> str:
        """讲解漏扫实现原理
        
        Returns:
            漏扫原理的详细讲解
        """
        explanation = """📚 **漏洞扫描实现原理**

**1. 扫描流程**
- **文件发现**: 递归遍历目标目录，识别代码文件
- **文件分析**: 对每个文件进行静态分析
- **漏洞检测**: 应用规则匹配和AI分析
- **结果聚合**: 汇总发现的漏洞

**2. 技术实现**
- **静态分析**: 解析代码结构，检测常见漏洞模式
- **AI增强**: 利用大语言模型识别复杂漏洞
- **规则引擎**: 基于已知漏洞特征进行匹配
- **语义分析**: 理解代码上下文和业务逻辑

**3. 纯AI模式**
- 直接使用AI模型分析代码
- 不依赖预定义规则
- 能够发现未知漏洞
- 分析深度更深，但速度较慢

**4. 扫描范围**
- 代码注入漏洞
- 认证授权问题
- 敏感信息泄露
- 配置错误
- 业务逻辑漏洞

**5. 执行策略**
- 优先级评估: 先分析高风险文件
- 并发处理: 提高扫描效率
- 缓存机制: 避免重复分析
- 结果验证: 确保漏洞准确性

现在开始执行扫描任务..."""
        return explanation
    
    def _dispatch_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """根据意图分发到对应处理器"""
        intent_type = intent.type
        
        if intent_type == IntentType.SCAN:
            return self._handle_scan_intent(intent, user_input)
            
        elif intent_type == IntentType.ANALYZE:
            return self._handle_analyze_intent(intent, user_input)
            
        elif intent_type == IntentType.EXPLOIT:
            return self._handle_exploit_intent(intent, user_input)
            
        elif intent_type == IntentType.FIX:
            return self._handle_fix_intent(intent, user_input)
            
        elif intent_type == IntentType.PLAN:
            return self._handle_plan_intent(intent, user_input)
            
        elif intent_type == IntentType.GIT:
            return self._handle_git_intent(user_input)
            
        elif intent_type == IntentType.CODE_TOOL:
            return self._handle_code_tool_intent(intent, user_input)
            
        elif intent_type == IntentType.CONVERSION:
            return self._handle_conversion_intent(user_input)
            
        elif intent_type == IntentType.INFO:
            return self._handle_info_intent()
            
        else:
            return self._handle_general_intent(intent, user_input)
    
    def _handle_scan_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理扫描意图（已改造为使用统一执行引擎）"""
        target = IntentParser.extract_target_path(user_input)
        pure_ai = IntentParser.detect_pure_ai_mode(user_input)
        
        try:
            # 🔥🔥🔥 优先使用统一执行引擎
            if self.unified_engine:
                import asyncio
                
                from src.core.base_agent import ExecutionRequest
                
                request = ExecutionRequest(
                    target=target,
                    natural_language=user_input,
                    mode="pure-ai" if pure_ai else "auto"
                )
                
                result = asyncio.run(self.unified_engine.execute(request))
                
                return {
                    "type": "scan_result",
                    "target": target,
                    "pure_ai": pure_ai or result.mode == "pure-ai",
                    "mode": result.mode,
                    "result": result.to_dict() if hasattr(result, 'to_dict') else {
                        'success': result.success,
                        'message': result.message,
                        'findings_count': result.total_findings,
                        'pipeline': result.pipeline_used,
                        'execution_time': result.execution_time
                    },
                    "message": f"✅ {result.message} (模式: {result.mode.upper()})"
                }
            
            # Fallback：旧逻辑（如果统一引擎不可用）
            from src.core.scanner import create_scanner
            
            config = self.config
            config.pure_ai = pure_ai
            
            scanner = create_scanner(config)
            result = scanner.scan_sync(target)
            
            return {
                "type": "scan_result",
                "target": target,
                "pure_ai": pure_ai,
                "test_mode": False,
                "result": result.to_dict() if hasattr(result, 'to_dict') else str(result),
                "message": f"✅ 扫描完成: {target} ({'纯AI模式' if pure_ai else '标准模式'})"
            }
            
        except Exception as e:
            return {
                "type": "error",
                "error": str(e),
                "message": f"扫描失败: {str(e)}"
            }
    
    def _handle_analyze_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理分析意图"""
        target = IntentParser.extract_target_path(user_input)
        
        try:
            import asyncio
            from src.core.langgraph_flow import analyze_code
            
            code = f"目录扫描: {target}"
            result = asyncio.run(analyze_code(code))
            
            return {
                "type": "analysis_result",
                "target": target,
                "result": result,
                "message": f"✅ 分析完成: {target}"
            }
            
        except Exception as e:
            return {
                "type": "error",
                "error": str(e),
                "message": f"分析失败: {str(e)}"
            }
    
    def _handle_exploit_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理漏洞利用意图"""
        target = IntentParser.extract_target_path(user_input)
        
        try:
            from src.core.scanner import create_scanner
            from src.exploit.generator import ExploitGenerator
            
            scanner = create_scanner(self.config)
            scan_result = scanner.scan_sync(target)
            
            generator = ExploitGenerator(self.config)
            exploits = []
            
            if scan_result.findings:
                for finding in scan_result.findings[:3]:
                    try:
                        exploit = generator.generate(finding)
                        if exploit:
                            exploits.append(exploit)
                    except Exception:
                        continue
                        
            return {
                "type": "exploit_result",
                "target": target,
                "exploits": exploits,
                "message": f"✅ 生成了 {len(exploits)} 个POC"
            }
            
        except Exception as e:
            return {
                "type": "error",
                "error": str(e),
                "message": f"POC生成失败: {str(e)}"
            }
    
    def _handle_fix_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理修复建议意图"""
        target = IntentParser.extract_target_path(user_input)
        
        try:
            from src.core.scanner import create_scanner
            
            scanner = create_scanner(self.config)
            scan_result = scanner.scan_sync(target)
            
            fix_suggestions = []
            if scan_result.findings:
                for finding in scan_result.findings[:3]:
                    fix_suggestions.append({
                        "vulnerability": finding.message,
                        "rule_name": finding.rule_name,
                        "suggestion": f"修复建议: {finding.description}"
                    })
                    
            return {
                "type": "fix_result",
                "target": target,
                "fix_suggestions": fix_suggestions,
                "message": f"✅ 生成了 {len(fix_suggestions)} 条修复建议"
            }
            
        except Exception as e:
            return {
                "type": "error",
                "error": str(e),
                "message": f"生成修复建议失败: {str(e)}"
            }
    
    def _handle_plan_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理Plan相关意图"""
        user_input_lower = user_input.lower()
        
        if any(kw in user_input_lower for kw in ['生成', '创建', 'generate', 'create']):
            plan = self.plan_manager.generate_from_natural_language(user_input)
            
            from src.core.plan_dsl import PlanDSLParser
            display = PlanDSLParser.format_plan_for_display(plan)
            
            self.conversation_manager.plan_state.update_plan(plan)
            
            return {
                "type": "plan_generated",
                "plan": plan.to_dict(),
                "display": display,
                "message": "✅ 已生成执行方案\n\n" + display + "\n\n是否执行？(输入'执行方案'开始运行)"
            }
            
        elif any(kw in user_input_lower for kw in ['修改', '更新', 'modify', 'update']):
            current_plan = self.conversation_manager.plan_state.current_plan
            if current_plan:
                modified_plan = self.plan_manager.modify_plan(current_plan, user_input)
                
                from src.core.plan_dsl import PlanDSLParser
                display = PlanDSLParser.format_plan_for_display(modified_plan)
                
                return {
                    "type": "plan_modified",
                    "plan": modified_plan.to_dict(),
                    "display": display,
                    "message": "✅ 方案已修改\n\n" + display
                }
            else:
                return {
                    "type": "error",
                    "error": "没有当前方案可修改",
                    "message": "先生成一个方案再进行修改"
                }
                
        elif any(kw in user_input_lower for kw in ['执行', '运行', 'run', 'execute']):
            current_plan = self.conversation_manager.plan_state.current_plan
            if current_plan:
                from src.cli.plan_commands import _plan_to_cli_args
                
                cli_args = _plan_to_cli_args(current_plan)
                pipeline_nodes = self.pipeline_builder.from_plan(current_plan)
                
                nl_description = self.pipeline_builder.to_natural_language(pipeline_nodes)
                
                return {
                    "type": "plan_executed",
                    "plan": current_plan.to_dict(),
                    "pipeline": [n.type.value for n in pipeline_nodes],
                    "cli_args": cli_args,
                    "display": nl_description,
                    "message": f"🚀 正在执行方案...\n\n{nl_description}"
                }
            else:
                return {
                    "type": "error",
                    "error": "没有当前方案可执行",
                    "message": "先生成一个方案再执行"
                }
        else:
            plan = self.plan_manager.generate_from_natural_language(user_input)
            from src.core.plan_dsl import PlanDSLParser
            display = PlanDSLParser.format_plan_for_display(plan)
            
            return {
                "type": "plan_generated",
                "plan": plan.to_dict(),
                "display": display,
                "message": "✅ 已生成方案\n\n" + display
            }
    
    def _handle_git_intent(self, user_input: str) -> Dict[str, Any]:
        """处理Git操作意图"""
        import subprocess
        
        try:
            if 'commit' in user_input.lower() or '提交' in user_input:
                msg_match = __import__('re').search(r'(?:commit|提交)\s*(.*)', user_input)
                message = msg_match.group(1).strip() if msg_match else "安全修复"
                
                subprocess.run(["git", "add", "."], check=True, capture_output=True)
                result = subprocess.run(
                    ["git", "commit", "-m", message],
                    capture_output=True,
                    text=True
                )
                
                return {
                    "type": "git_result",
                    "operation": "commit",
                    "status": "success" if result.returncode == 0 else "error",
                    "message": "✅ 提交成功" if result.returncode == 0 else f"❌ 提交失败: {result.stderr}",
                    "output": result.stdout if result.returncode == 0 else result.stderr
                }
            else:
                return {
                    "type": "git_result",
                    "operation": "unknown",
                    "status": "error",
                    "message": "不支持的Git操作"
                }
                
        except Exception as e:
            return {
                "type": "git_result",
                "operation": "unknown",
                "status": "error",
                "message": f"Git操作失败: {str(e)}"
            }
    
    def _handle_code_tool_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理代码库工具意图"""
        entities = intent.entities
        
        if '@file:' in user_input:
            file_match = __import__('re').search(r'@file:(.+?)(?:\s|$)', user_input)
            if file_match:
                file_path = file_match.group(1).strip()
                return self._read_file(file_path)
                
        elif '@func:' in user_input:
            func_match = __import__('re').search(r'@func:(.+?)(?:\s|$)', user_input)
            if func_match:
                func_name = func_match.group(1).strip()
                return self._search_function(func_name)
                
        elif '搜索代码' in user_input or 'grep' in user_input.lower():
            keyword_match = __import__('re').search(r'(?:搜索代码|grep)[:\s]*(.*?)(?:\s|$)', user_input)
            keyword = keyword_match.group(1).strip() if keyword_match else ""
            return self._grep_code(keyword)
            
        elif '列出目录' in user_input or 'list dir' in user_input.lower():
            path_match = __import__('re').search(r'(?:列出目录|list dir)[:\s]*(.*?)(?:\s|$)', user_input)
            path = path_match.group(1).strip() if path_match else "."
            return self._list_directory(path)
            
        elif '项目摘要' in user_input or '项目信息' in user_input:
            return {
                "type": "project_summary",
                **self.conversation_manager.project_context.__dict__
            }
            
        return {
            "type": "code_tool_result",
            "message": "无法识别的代码库工具命令"
        }
    
    def _handle_conversion_intent(self, user_input: str) -> Dict[str, Any]:
        """处理CLI/自然语言转换意图"""
        if '转换为CLI' in user_input or '转为CLI' in user_input:
            request_match = __import__('re').search(r'(?:转换|转)(?:为|到)?CLI[:\s]*(.*)', user_input)
            natural_lang = request_match.group(1).strip() if request_match else user_input.replace('转换为CLI', '').replace('转为CLI', '').strip()
            
            cli_command = self.natural_language_to_cli(natural_lang)
            
            return {
                "type": "cli_conversion",
                "natural_language": natural_lang,
                "cli_command": cli_command,
                "message": f"📝 CLI命令:\n\n{cli_command}"
            }
            
        elif '解释CLI' in user_input or '解释命令' in user_input:
            cmd_match = __import__('re').search(r'(?:解释CLI|解释命令)[:\s]*(.*)', user_input)
            cli_cmd = cmd_match.group(1).strip() if cmd_match else ""
            
            if cli_cmd:
                nl_desc = self.cli_to_natural_language(cli_cmd)
                
                return {
                    "type": "cli_explanation",
                    "cli_command": cli_cmd,
                    "natural_language": nl_desc,
                    "message": f"💡 命令含义:\n\n{nl_desc}"
                }
                
        return {
            "type": "conversion_result",
            "message": "无法识别的转换请求"
        }
    
    def _handle_info_intent(self) -> Dict[str, Any]:
        """处理帮助/信息意图"""
        help_text = """
🔒 HOS-LS 智能交互模式帮助

📌 **常用命令类型:**

**1️⃣ 扫描分析**
• "扫描当前目录" - 基础安全扫描
• "用纯AI模式分析" - AI深度分析
• "全面审计这个项目" - 完整安全审计

**2️⃣ 漏洞利用**
• "生成POC" - 创建漏洞利用代码
• "验证漏洞" - 在沙箱中验证

**3️⃣ 方案管理**
• "生成审计方案" - AI生成执行计划
• "修改方案：添加POC" - 调整方案
• "执行方案" - 运行当前方案

**4️⃣ 代码工具**
• "@file:path/to/file" - 读取文件
• "@func:function_name" - 搜索函数
• "搜索代码: 关键词" - 代码搜索

**5️⃣ 转换工具**
• "转换为CLI: 扫描并生成报告"
• "解释CLI: --full-audit"

**6️⃣ 特殊命令**
• /help - 显示此帮助
• /exit - 退出对话
• /clear - 清屏

💡 **提示:** 支持中英文混合输入，AI会智能理解你的需求！
"""
        
        return {
            "type": "info_result",
            "message": help_text
        }
    
    def _handle_general_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理通用意图（回退到多Agent管道）"""
        try:
            from src.ai.pure_ai.multi_agent_pipeline import MultiAgentPipeline
            
            if self.ai_client:
                pipeline = MultiAgentPipeline(self.ai_client, self.config)
                result = pipeline.process_query(user_input)
                
                return {
                    "type": "general_result",
                    "query": user_input,
                    "result": result,
                    "message": f"✅ 已处理您的查询"
                }
            else:
                return {
                    "type": "general_result",
                    "query": user_input,
                    "result": "AI服务暂时不可用，请检查配置",
                    "message": "⚠️ AI服务不可用"
                }
                
        except Exception as e:
            return {
                "type": "general_result",
                "query": user_input,
                "result": f"处理失败: {str(e)}",
                "message": f"❌ 处理失败: {str(e)}"
            }
    
    def _read_file(self, file_path: str) -> Dict[str, Any]:
        """读取文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            return {
                "type": "file_content",
                "file_path": file_path,
                "content": content,
                "lines": len(content.split('\n')),
                "message": f"📄 文件: {file_path} ({len(content.split('\n'))} 行)"
            }
        except Exception as e:
            return {"type": "error", "error": f"读取文件失败: {str(e)}"}
    
    def _search_function(self, func_name: str) -> Dict[str, Any]:
        """搜索函数定义"""
        import ast
        matches = []
        
        for root, dirs, files in os.walk('.'):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        tree = ast.parse(content, filename=file_path)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                                start_line = node.lineno
                                end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line + 10
                                lines = content.split('\n')
                                func_code = '\n'.join(lines[start_line-1:end_line])
                                
                                matches.append({
                                    "file_path": file_path,
                                    "start_line": start_line,
                                    "end_line": end_line,
                                    "function_code": func_code
                                })
                    except Exception:
                        continue
                        
        return {
            "type": "ast_search_result",
            "function_name": func_name,
            "matches": matches,
            "message": f"🔍 找到 {len(matches)} 个匹配的函数"
        }
    
    def _grep_code(self, keyword: str) -> Dict[str, Any]:
        """搜索代码关键词"""
        import subprocess
        
        try:
            if os.name == 'nt':
                result = subprocess.run(
                    ['findstr', '/s', '/n', keyword, '*.py', '*.js', '*.ts'],
                    capture_output=True, text=True, cwd="."
                )
            else:
                result = subprocess.run(
                    ['grep', '-r', '-n', keyword, '--include=*.py', '--include=*.js', '.'],
                    capture_output=True, text=True
                )
                
            matches = [m for m in result.stdout.strip().split('\n') if m]
            
            return {
                "type": "grep_result",
                "keyword": keyword,
                "matches": matches[:50],
                "total": len(matches),
                "message": f"🔎 搜索 '{keyword}': 找到 {len(matches)} 个匹配"
            }
        except Exception as e:
            return {"type": "error", "error": f"搜索失败: {str(e)}"}
    
    def _list_directory(self, path: str = ".") -> Dict[str, Any]:
        """列出目录内容"""
        from pathlib import Path
        
        try:
            path_obj = Path(path)
            items = []
            
            if path_obj.is_dir():
                for item in sorted(path_obj.iterdir()):
                    items.append({
                        "name": item.name,
                        "type": "directory" if item.is_dir() else "file",
                        "size": item.stat().st_size if item.is_file() else 0
                    })
                    
            return {
                "type": "directory_listing",
                "path": str(path_obj.absolute()),
                "items": items[:50],
                "message": f"📁 目录: {path} ({len(items)} 项)"
            }
        except Exception as e:
            return {"type": "error", "error": f"列出目录失败: {str(e)}"}
    
    def natural_language_to_cli(self, text: str) -> str:
        """自然语言转CLI命令（公开接口）"""
        nodes = self.pipeline_builder.from_natural_language(text, self.ai_client, self.config)
        target = IntentParser.extract_target_path(text)
        return self.pipeline_builder.to_cli_command(nodes, target)
    
    def cli_to_natural_language(self, cli_command: str) -> str:
        """CLI命令转自然语言（公开接口）"""
        nodes = self.pipeline_builder.from_cli_command(cli_command)
        return self.pipeline_builder.to_natural_language(nodes)
    
    def get_conversation_history(self):
        """获取对话历史"""
        return self.conversation_manager.history
    
    def clear_history(self):
        """清空对话历史"""
        self.conversation_manager.clear()
    
    def save_session(self):
        """保存当前会话"""
        self.conversation_manager.save_session()
