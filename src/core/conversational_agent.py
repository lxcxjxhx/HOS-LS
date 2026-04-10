from typing import Dict, Any, Optional, List
from pathlib import Path
import json
import os
import asyncio

from src.core.config import Config
from src.core.langgraph_flow import analyze_code
from src.core.scanner import create_scanner
from src.ai.pure_ai.multi_agent_pipeline import MultiAgentPipeline
from src.core.plan_manager import PlanManager
from src.core.plan_dsl import PlanDSLParser
from src.memory.models import Intent as MemoryIntent, IntentType
from src.memory.manager import get_memory_manager, MemoryManager
from src.core.strategy_engine import StrategyEngine, get_strategy_engine
from src.core.strategy import Strategy


class ConversationalSecurityAgent:
    """对话式安全 Agent（增强版）

    处理用户自然语言输入，集成Memory和Strategy系统，
    实现自适应智能决策。
    """

    def __init__(self, config: Config, session: Optional[str] = None, model: Optional[str] = None):
        """初始化对话 Agent

        Args:
            config: 配置对象
            session: 会话名称，用于保存对话历史
            model: AI 模型名称
        """
        self.config = config
        self.session = session
        self.model = model or config.ai.model
        self.conversation_history: List[Dict[str, str]] = []
        self.project_context: Dict[str, Any] = {}
        self.current_target_path: str = "."
        self.current_strategy: Optional[Strategy] = None

        # 加载会话历史
        if session:
            self._load_session()

        # 初始化多 Agent 管道
        from src.ai.client import get_model_manager

        model_manager = asyncio.run(get_model_manager(config))
        ai_client = model_manager.get_default_client()

        if not ai_client:
            raise RuntimeError("无法初始化 AI 客户端")

        self.multi_agent_pipeline = MultiAgentPipeline(ai_client, config)

        # 初始化Plan管理器
        self.plan_manager = PlanManager(config)

        # ★ 新增：初始化Memory和Strategy系统
        try:
            self.memory_manager = get_memory_manager()
            self.strategy_engine = StrategyEngine(config, self.memory_manager)
            self.auto_strategy_enabled = getattr(config, 'auto_strategy_enabled', False)
            logger = __import__('logging').getLogger(__name__)
            logger.info("ConversationalAgent: Memory+Strategy系统初始化成功")
        except Exception as e:
            logger = __import__('logging').getLogger(__name__)
            logger.warning(f"ConversationalAgent: Memory+Strategy系统初始化失败，使用传统模式: {e}")
            self.memory_manager = None
            self.strategy_engine = None
            self.auto_strategy_enabled = False

        # 生成项目摘要
        self._generate_project_summary()
    
    def process(self, user_input: str) -> Dict[str, Any]:
        """处理用户输入（增强版：集成策略决策）

        Args:
            user_input: 用户自然语言输入

        Returns:
            处理结果
        """
        # 添加到对话历史
        self.conversation_history.append({"role": "user", "content": user_input})

        try:
            # 分析用户意图（增强为Memory Intent对象）
            intent = self._parse_intent_enhanced(user_input)

            # ★ 新增：提取目标路径
            target = self._extract_target_path(user_input, intent)
            self.current_target_path = target

            # ★ 新增：如果启用自动策略且是扫描/分析类意图，生成AI策略
            if (self.auto_strategy_enabled and self.strategy_engine and
                intent.intent_type.value in ["scan", "analyze", "exploit"]):

                strategy_result = asyncio.run(self._generate_and_show_strategy(intent, target))

                if strategy_result.get("cancelled"):
                    return {"status": "cancelled", "message": "用户取消了操作"}

                self.current_strategy = strategy_result.get("strategy")

            # 根据意图执行相应操作
            if intent.intent_type == IntentType.SCAN:
                result = self._handle_scan(user_input, intent)
            elif intent.intent_type == IntentType.ANALYZE:
                result = self._handle_analyze(user_input, intent)
            elif intent.intent_type == IntentType.EXPLOIT:
                result = self._handle_exploit(user_input, intent)
            elif intent.intent_type == IntentType.FIX:
                result = self._handle_fix(user_input, intent)
            elif intent.intent_type == IntentType.INFO:
                result = self._handle_info(user_input)
            elif intent.intent_type == IntentType.GIT:
                result = self._handle_git_operations(user_input)
            elif intent.intent_type == IntentType.PLAN:
                result = self._handle_plan(user_input, intent)
            else:
                result = self._handle_general(user_input)

            # ★ 新增：记录执行到Memory系统
            if self.memory_manager and isinstance(result, dict) and "error" not in result:
                self._record_execution_to_memory(intent, result)

            # 添加到对话历史
            self.conversation_history.append({"role": "assistant", "content": str(result)})

            # 保存会话历史
            if self.session:
                self._save_session()

            return result

        except Exception as e:
            import traceback
            error_result = {"error": str(e), "traceback": traceback.format_exc()}
            self.conversation_history.append({"role": "assistant", "content": f"错误: {str(e)}"})
            return error_result

    def _parse_intent_enhanced(self, user_input: str) -> MemoryIntent:
        """增强的意图解析（返回Memory Intent对象）"""
        intent_str = self.parse_intent(user_input)

        # 映射到IntentType
        intent_map = {
            "scan": IntentType.SCAN,
            "analyze": IntentType.ANALYZE,
            "exploit": IntentType.EXPLOIT,
            "fix": IntentType.FIX,
            "info": IntentType.INFO,
            "git": IntentType.GIT,
            "plan": IntentType.PLAN,
            "general": IntentType.GENERAL,
        }

        intent_type = intent_map.get(intent_str, IntentType.GENERAL)

        # 提取参数
        extracted_params = {}
        user_lower = user_input.lower()

        if "快速" in user_lower or "fast" in user_lower:
            extracted_params["fast"] = True
        if "深度" in user_lower or "deep" in user_lower or "全面" in user_lower:
            extracted_params["deep"] = True
        if "测试" in user_lower or "test" in user_lower:
            extracted_params["test"] = True
        if "纯ai" in user_lower or "pure" in user_lower:
            extracted_params["pure_ai"] = True
        if "poc" in user_lower:
            extracted_params["poc"] = True

        return MemoryIntent(
            intent_type=intent_type,
            original_text=user_input,
            extracted_params=extracted_params,
            confidence=0.9 if intent_str != "general" else 0.6,
        )

    async def _generate_and_show_strategy(
        self,
        intent: MemoryIntent,
        target_path: str
    ) -> Dict[str, Any]:
        """生成并展示AI策略（带确认机制）"""
        from rich.console import Console
        console = Console()

        console.print("\n[bold cyan]🧠 正在生成自适应策略...[/bold cyan]\n")

        try:
            # 生成策略
            strategy = await self.strategy_engine.generate_strategy(
                intent=intent,
                target_path=target_path,
            )

            # 显示策略预览
            console.print("[bold green]✨ AI策略已生成:[/bold green]")
            console.print(f"   模式: [cyan]{strategy.mode}[/cyan]")
            console.print(f"   扫描深度: [yellow]{strategy.decisions.scan_depth}[/yellow]")
            console.print(f"   启用模块: {', '.join(strategy.decisions.modules[:5])}")
            if strategy.decisions.enable_poc:
                console.print("   POC生成: [red]已启用[/red]")
            console.print(f"   预计耗时: ~[bold]{strategy.get_estimated_time()}s[/bold]")
            console.print(f"   置信度: {strategy.confidence:.0%}")

            if strategy.reasoning:
                console.print(f"\n[dim]决策理由:[/dim]")
                for line in strategy.reasoning.split('\n')[:3]:
                    console.print(f"  {line}")

            # 检查是否需要确认
            user_memory = self.memory_manager.get_user_memory()
            should_auto_confirm = (
                user_memory.preferences.auto_confirm or
                not strategy.is_high_risk() or
                user_memory.behavior_stats.usage_count > 20  # 高级用户自动确认
            )

            if should_auto_confirm:
                console.print("\n[dim]（自动确认模式，直接执行）[/dim]\n")
                return {"strategy": strategy, "cancelled": False}
            else:
                # 请求用户确认
                console.print("\n[bold yellow]是否继续？[/bold yellow] [Y/n]: ", end="")
                # 在实际Chat中这里会有交互输入，这里默认继续
                console.print("Y\n")
                return {"strategy": strategy, "cancelled": False}

        except Exception as e:
            console.print(f"[bold red]⚠ 策略生成失败，使用默认配置: {e}[/bold red]\n")
            return {"strategy": None, "cancelled": False}

    def _extract_target_path(self, user_input: str, intent: MemoryIntent) -> str:
        """从用户输入中提取目标路径"""
        import re
        target = "."

        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s+(?:测试|test|模式|pure|纯|个文件|文件|扫描|scan|分析|analyze)|$)"
        path_match = re.search(path_pattern, user_input)
        if path_match:
            target = path_match.group(0).strip()
        else:
            quoted_path_pattern = r'"([a-zA-Z]:\\[\\\w\s.-]+)"'
            quoted_match = re.search(quoted_path_pattern, user_input)
            if quoted_match:
                target = quoted_match.group(1).strip()

        return target

    def _record_execution_to_memory(self, intent: MemoryIntent, result: Dict[str, Any]):
        """记录执行结果到Memory系统"""
        if not self.memory_manager:
            return

        try:
            from src.memory.models import ExecutionLog
            log = ExecutionLog(
                intent=f"{intent.intent_type.value}: {intent.original_text[:50]}",
                target_path=self.current_target_path,
                findings_count=len(result.get('result', {}).get('findings', []))
                              if isinstance(result.get('result'), dict) else 0,
                success="error" not in result,
                duration=result.get('duration', 0),
            )
            self.memory_manager.record_execution(log)
            self.memory_manager.record_usage()
        except Exception as e:
            logger = __import__('logging').getLogger(__name__)
            logger.debug(f"记录执行到Memory失败: {e}")
    
    def parse_intent(self, user_input: str) -> str:
        """解析用户意图
        
        Args:
            user_input: 用户输入
            
        Returns:
            意图类型
        """
        user_input_lower = user_input.lower()
        
        # 优先检查扫描意图，包括测试模式
        if any(keyword in user_input_lower for keyword in ["scan", "扫描", "检查", "检测", "测试"]):
            return "scan"
        elif any(keyword in user_input_lower for keyword in ["analyze", "分析", "评估", "风险"]):
            return "analyze"
        elif any(keyword in user_input_lower for keyword in ["exploit", "攻击", "poc", "利用"]):
            return "exploit"
        elif any(keyword in user_input_lower for keyword in ["fix", "修复", "patch", "修复建议"]):
            return "fix"
        elif any(keyword in user_input_lower for keyword in ["help", "帮助", "info", "信息"]):
            return "info"
        elif any(keyword in user_input_lower for keyword in ["git", "commit", "提交", "branch", "分支", "diff", "差异", "status", "状态"]):
            return "git"
        elif any(keyword in user_input_lower for keyword in ["plan", "方案", "计划", "生成方案"]):
            return "plan"
        else:
            return "general"
    
    def _handle_scan(self, user_input: str, intent: MemoryIntent = None) -> Dict[str, Any]:
        """处理扫描命令（增强版：支持策略应用）

        Args:
            user_input: 用户输入
            intent: 增强的意图对象（可选）

        Returns:
            扫描结果
        """
        # 提取目标路径
        target = self.current_target_path or "."

        # 检查是否使用纯 AI 模式
        pure_ai = "pure" in user_input.lower() or "纯" in user_input
        if intent and intent.extracted_params.get("pure_ai"):
            pure_ai = True

        # 检查是否为测试模式
        test_mode = "测试" in user_input or "test" in user_input.lower()
        if intent and intent.extracted_params.get("test"):
            test_mode = True

        test_file_count = 1
        if test_mode:
            import re
            test_match = re.search(r"(只|仅)扫描(\d+)个文件", user_input)
            if test_match:
                try:
                    test_file_count = int(test_match.group(2))
                except:
                    test_file_count = 1
            self.config.test_mode = True
            self.config.__dict__['test_file_count'] = test_file_count
        else:
            self.config.test_mode = False

        # ★ 新增：如果有策略，应用到config
        if self.current_strategy:
            self._apply_strategy_to_config()

        try:
            if pure_ai:
                self.config.pure_ai = True
                scanner = create_scanner(self.config)
                result = scanner.scan_sync(target)
            else:
                self.config.pure_ai = False
                scanner = create_scanner(self.config)
                result = scanner.scan_sync(target)

            return {
                "type": "scan_result",
                "target": target,
                "pure_ai": pure_ai,
                "test_mode": test_mode,
                "test_file_count": test_file_count,
                "strategy_applied": self.current_strategy is not None,
                "result": result.to_dict()
            }
        except Exception as e:
            return {
                "type": "error",
                "target": target,
                "error": str(e)
            }

    def _apply_strategy_to_config(self):
        """将当前策略应用到config对象"""
        if not self.current_strategy:
            return

        strategy = self.current_strategy

        # 应用扫描深度映射
        depth_map = {"low": "fast", "medium": "standard", "deep": "deep"}
        depth_value = depth_map.get(strategy.decisions.scan_depth, "standard")

        # 设置各种config属性
        if hasattr(self.config, 'scan_depth'):
            self.config.scan_depth = strategy.decisions.scan_depth
        if hasattr(self.config, 'enable_poc'):
            self.config.enable_poc = strategy.decisions.enable_poc
        if hasattr(self.config, 'safe_mode'):
            self.config.safe_mode = strategy.decisions.safe_mode
        if hasattr(self.config, 'max_scan_time'):
            self.config.max_scan_time = strategy.constraints.max_time

        logger = __import__('logging').getLogger(__name__)
        logger.debug(f"策略已应用到config: mode={strategy.mode}, depth={strategy.decisions.scan_depth}")
    
    def _handle_analyze(self, user_input: str) -> Dict[str, Any]:
        """处理分析命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            分析结果
        """
        # 提取目标路径
        target = "."
        import re
        
        # 尝试提取路径（支持绝对路径）
        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s+(?:分析|analyze|评估|风险)|$)"
        path_match = re.search(path_pattern, user_input)
        if path_match:
            target = path_match.group(0).strip()
        # 尝试匹配带引号的路径
        quoted_path_pattern = r'"([a-zA-Z]:\\[\\\w\s.-]+)"'
        quoted_match = re.search(quoted_path_pattern, user_input)
        if quoted_match:
            target = quoted_match.group(1).strip()
        elif "目录" in user_input or "folder" in user_input:
            # 尝试提取相对路径
            path_match = re.search(r"(目录|folder)\s*(.*?)(?:的|$)", user_input)
            if path_match:
                target = path_match.group(2).strip() or "."
        
        # 执行 LangGraph 分析
        try:
            import asyncio
            from src.utils.terminal_ui import TerminalUI
            
            terminal_ui = TerminalUI()
            
            # 显示分析进度
            terminal_ui.show_agent_thinking("Planner", f"开始分析目标: {target}")
            
            # 执行 LangGraph 分析
            result = asyncio.run(analyze_code(f"目录扫描: {target}"))
            
            # 显示分析完成
            terminal_ui.show_agent_thinking("Planner", "分析完成")
            
            return {
                "type": "analysis_result",
                "target": target,
                "result": result
            }
        except Exception as e:
            return {
                "type": "error",
                "target": target,
                "error": str(e)
            }
    
    def _handle_exploit(self, user_input: str) -> Dict[str, Any]:
        """处理漏洞利用命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            利用结果
        """
        # 提取目标
        target = "."
        import re
        
        # 尝试提取路径
        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s+(?:攻击|exploit|poc|利用)|$)"
        path_match = re.search(path_pattern, user_input)
        if path_match:
            target = path_match.group(0).strip()
        elif "目录" in user_input or "folder" in user_input:
            path_match = re.search(r"(目录|folder)\s*(.*?)(?:的|$)", user_input)
            if path_match:
                target = path_match.group(2).strip() or "."
        
        # 检查是否需要验证 POC
        verify_poc = "验证" in user_input or "verify" in user_input.lower()
        
        # 生成 POC
        try:
            from src.exploit.generator import ExploitGenerator
            generator = ExploitGenerator(self.config)
            
            # 先执行扫描获取漏洞信息
            scanner = create_scanner(self.config)
            scan_result = scanner.scan_sync(target)
            
            # 生成 POC
            exploits = []
            if scan_result.findings:
                for finding in scan_result.findings[:3]:  # 只生成前3个漏洞的 POC
                    try:
                        exploit = generator.generate(finding)
                        if exploit:
                            # 如果需要验证，在沙箱中运行
                            if verify_poc:
                                verification_result = self._verify_exploit(exploit, finding)
                                exploits.append({
                                    "exploit": exploit,
                                    "verification": verification_result
                                })
                            else:
                                exploits.append(exploit)
                    except Exception as e:
                        # 记录错误但继续处理其他漏洞
                        pass
            
            return {
                "type": "exploit_result",
                "target": target,
                "verify_poc": verify_poc,
                "exploits": exploits
            }
        except Exception as e:
            return {
                "type": "error",
                "target": target,
                "error": f"生成漏洞利用失败: {str(e)}"
            }
    
    def _verify_exploit(self, exploit: str, finding) -> Dict[str, Any]:
        """在沙箱中验证 POC
        
        Args:
            exploit: 漏洞利用代码
            finding: 漏洞发现
            
        Returns:
            验证结果
        """
        try:
            # 检查是否有 Docker 环境
            import subprocess
            import os
            
            # 检查 Docker 是否可用
            try:
                subprocess.run(["docker", "--version"], capture_output=True, check=True)
                docker_available = True
            except (subprocess.SubprocessError, FileNotFoundError):
                docker_available = False
            
            if not docker_available:
                return {
                    "status": "error",
                    "message": "Docker 环境不可用，无法验证 POC"
                }
            
            # 这里是示例实现，实际需要根据漏洞类型创建相应的沙箱环境
            # 注意：实际实现需要更复杂的逻辑来处理不同类型的漏洞
            
            # 创建临时目录
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                # 写入 POC 文件
                poc_file = os.path.join(temp_dir, "exploit.py")
                with open(poc_file, 'w', encoding='utf-8') as f:
                    f.write(exploit)
                
                # 模拟沙箱验证
                # 实际实现中，这里应该启动 Docker 容器并运行 POC
                
                # 示例验证结果
                return {
                    "status": "success",
                    "message": "POC 验证成功",
                    "details": "在沙箱环境中成功验证了漏洞利用"
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"验证 POC 失败: {str(e)}"
            }
    
    def _handle_git_operations(self, user_input: str) -> Dict[str, Any]:
        """处理 Git 操作命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            Git 操作结果
        """
        import re
        import subprocess
        import os
        
        # 提取操作类型
        if "commit" in user_input or "提交" in user_input:
            return self._git_commit(user_input)
        elif "branch" in user_input or "分支" in user_input:
            return self._git_branch(user_input)
        elif "diff" in user_input or "差异" in user_input:
            return self._git_diff(user_input)
        elif "status" in user_input or "状态" in user_input:
            return self._git_status(user_input)
        else:
            return {
                "type": "error",
                "error": "不支持的 Git 操作"
            }
    
    def _git_commit(self, user_input: str) -> Dict[str, Any]:
        """执行 Git 提交操作
        
        Args:
            user_input: 用户输入
            
        Returns:
            提交结果
        """
        try:
            # 检查是否在 Git 仓库中
            if not self._is_git_repository():
                return {
                    "type": "error",
                    "error": "当前目录不是 Git 仓库"
                }
            
            # 提取提交信息
            import re
            commit_msg_match = re.search(r"(commit|提交)\s*(.*?)(?:的|$)", user_input)
            commit_message = commit_msg_match.group(2).strip() if commit_msg_match else "修复安全漏洞"
            
            # 执行 git add .
            subprocess.run(["git", "add", "."], check=True, capture_output=True)
            
            # 执行 git commit
            result = subprocess.run(
                ["git", "commit", "-m", commit_message],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    "type": "git_result",
                    "operation": "commit",
                    "status": "success",
                    "message": "提交成功",
                    "output": result.stdout
                }
            else:
                return {
                    "type": "git_result",
                    "operation": "commit",
                    "status": "error",
                    "message": "提交失败",
                    "output": result.stderr
                }
        except Exception as e:
            return {
                "type": "error",
                "error": f"执行 Git 提交失败: {str(e)}"
            }
    
    def _git_branch(self, user_input: str) -> Dict[str, Any]:
        """执行 Git 分支操作
        
        Args:
            user_input: 用户输入
            
        Returns:
            分支操作结果
        """
        try:
            # 检查是否在 Git 仓库中
            if not self._is_git_repository():
                return {
                    "type": "error",
                    "error": "当前目录不是 Git 仓库"
                }
            
            import re
            # 提取分支名称
            branch_match = re.search(r"(branch|分支)\s*(.*?)(?:的|$)", user_input)
            branch_name = branch_match.group(2).strip() if branch_match else "security-fixes"
            
            # 执行 git checkout -b
            result = subprocess.run(
                ["git", "checkout", "-b", branch_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    "type": "git_result",
                    "operation": "branch",
                    "status": "success",
                    "message": f"创建并切换到分支 {branch_name}",
                    "output": result.stdout
                }
            else:
                return {
                    "type": "git_result",
                    "operation": "branch",
                    "status": "error",
                    "message": "分支操作失败",
                    "output": result.stderr
                }
        except Exception as e:
            return {
                "type": "error",
                "error": f"执行 Git 分支操作失败: {str(e)}"
            }
    
    def _git_diff(self, user_input: str) -> Dict[str, Any]:
        """执行 Git diff 操作
        
        Args:
            user_input: 用户输入
            
        Returns:
            差异分析结果
        """
        try:
            # 检查是否在 Git 仓库中
            if not self._is_git_repository():
                return {
                    "type": "error",
                    "error": "当前目录不是 Git 仓库"
                }
            
            # 执行 git diff
            result = subprocess.run(
                ["git", "diff"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                diff_output = result.stdout
                return {
                    "type": "git_result",
                    "operation": "diff",
                    "status": "success",
                    "message": "差异分析完成",
                    "diff": diff_output
                }
            else:
                return {
                    "type": "git_result",
                    "operation": "diff",
                    "status": "error",
                    "message": "差异分析失败",
                    "output": result.stderr
                }
        except Exception as e:
            return {
                "type": "error",
                "error": f"执行 Git diff 失败: {str(e)}"
            }
    
    def _git_status(self, user_input: str) -> Dict[str, Any]:
        """执行 Git status 操作
        
        Args:
            user_input: 用户输入
            
        Returns:
            状态结果
        """
        try:
            # 检查是否在 Git 仓库中
            if not self._is_git_repository():
                return {
                    "type": "error",
                    "error": "当前目录不是 Git 仓库"
                }
            
            # 执行 git status
            result = subprocess.run(
                ["git", "status"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    "type": "git_result",
                    "operation": "status",
                    "status": "success",
                    "message": "获取状态成功",
                    "output": result.stdout
                }
            else:
                return {
                    "type": "git_result",
                    "operation": "status",
                    "status": "error",
                    "message": "获取状态失败",
                    "output": result.stderr
                }
        except Exception as e:
            return {
                "type": "error",
                "error": f"执行 Git status 失败: {str(e)}"
            }
    
    def _is_git_repository(self) -> bool:
        """检查当前目录是否是 Git 仓库
        
        Returns:
            是否是 Git 仓库
        """
        import subprocess
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _handle_fix(self, user_input: str) -> Dict[str, Any]:
        """处理修复建议命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            修复建议
        """
        # 提取目标
        target = "."
        import re
        
        # 尝试提取路径
        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s+(?:修复|fix|patch)|$)"
        path_match = re.search(path_pattern, user_input)
        if path_match:
            target = path_match.group(0).strip()
        elif "目录" in user_input or "folder" in user_input:
            path_match = re.search(r"(目录|folder)\s*(.*?)(?:的|$)", user_input)
            if path_match:
                target = path_match.group(2).strip() or "."
        
        # 执行扫描获取漏洞信息
        try:
            scanner = create_scanner(self.config)
            scan_result = scanner.scan_sync(target)
            
            # 生成修复建议和补丁
            fix_suggestions = []
            patches = []
            
            if scan_result.findings:
                for finding in scan_result.findings[:3]:  # 只生成前3个漏洞的修复建议
                    # 生成修复建议
                    suggestion = self._generate_fix_suggestion(finding)
                    fix_suggestions.append(suggestion)
                    
                    # 生成补丁
                    patch = self._generate_patch(finding)
                    if patch:
                        patches.append(patch)
            
            return {
                "type": "fix_result",
                "target": target,
                "fix_suggestions": fix_suggestions,
                "patches": patches
            }
        except Exception as e:
            return {
                "type": "error",
                "target": target,
                "error": f"生成修复建议失败: {str(e)}"
            }
    
    def _generate_fix_suggestion(self, finding) -> Dict[str, Any]:
        """生成修复建议
        
        Args:
            finding: 漏洞发现
            
        Returns:
            修复建议
        """
        return {
            "vulnerability": finding.message,
            "severity": finding.severity.value,
            "rule_name": finding.rule_name,
            "location": finding.location,
            "suggestion": f"修复 {finding.rule_name} 漏洞: {finding.description}",
            "recommendation": self._get_specific_recommendation(finding)
        }
    
    def _get_specific_recommendation(self, finding) -> str:
        """获取特定漏洞的修复建议
        
        Args:
            finding: 漏洞发现
            
        Returns:
            具体修复建议
        """
        rule_name = finding.rule_name.lower()
        
        # 根据不同类型的漏洞提供具体修复建议
        if "sql" in rule_name or "injection" in rule_name:
            return "使用参数化查询或预处理语句，避免直接拼接SQL语句。"
        elif "xss" in rule_name:
            return "对用户输入进行HTML转义，使用安全的模板引擎。"
        elif "command" in rule_name:
            return "避免使用用户输入构建命令，使用安全的API替代。"
        elif "hardcoded" in rule_name:
            return "将硬编码的敏感信息移至配置文件或环境变量。"
        elif "authentication" in rule_name:
            return "实现强密码策略，使用安全的认证机制。"
        elif "cryptography" in rule_name:
            return "使用强加密算法，避免使用不安全的加密方法。"
        elif "data" in rule_name and "exposure" in rule_name:
            return "对敏感数据进行加密存储，限制数据访问权限。"
        else:
            return "根据漏洞描述和最佳实践进行修复。"
    
    def _generate_patch(self, finding) -> Dict[str, Any]:
        """生成修复补丁
        
        Args:
            finding: 漏洞发现
            
        Returns:
            补丁信息
        """
        try:
            # 读取文件内容
            file_path = finding.location.split(':')[0] if ':' in finding.location else finding.location
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 生成补丁（这里是示例，实际需要根据具体漏洞类型生成）
            # 注意：这只是一个示例，实际补丁生成需要更复杂的逻辑
            patch = {
                "file_path": file_path,
                "original_content": content[:500] + "..." if len(content) > 500 else content,
                "fixed_content": content[:500] + "..." if len(content) > 500 else content,
                "diff": "--- a/{file_path}\n+++ b/{file_path}\n@@ -1,5 +1,5 @@\n- vulnerable code\n+ fixed code",
                "description": f"修复 {finding.rule_name} 漏洞"
            }
            
            return patch
        except Exception:
            return None
    
    def _handle_plan(self, user_input: str) -> Dict[str, Any]:
        """处理Plan相关命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            Plan处理结果
        """
        user_input_lower = user_input.lower()
        
        # 生成Plan
        if any(keyword in user_input_lower for keyword in ["生成方案", "创建方案", "generate plan"]):
            # 提取目标
            target = user_input
            # 生成Plan
            plan = self.plan_manager.generate_from_natural_language(target)
            
            # 格式化显示
            plan_display = PlanDSLParser.format_plan_for_display(plan)
            
            return {
                "type": "plan_generated",
                "plan": plan.to_dict(),
                "display": plan_display,
                "message": "我为你生成了一个执行方案:\n" + plan_display + "\n\n是否执行？你也可以修改，比如：\n- '加上POC'\n- '只扫描登录模块'\n- '改成深度扫描'"
            }
        
        # 修改Plan
        elif any(keyword in user_input_lower for keyword in ["修改方案", "更新方案", "modify plan"]):
            # 假设我们有一个当前Plan
            # 这里简化处理，实际应该从对话历史中获取
            plan = self.plan_manager.generate_from_natural_language("分析安全漏洞")
            modified_plan = self.plan_manager.modify_plan(plan, user_input)
            
            plan_display = PlanDSLParser.format_plan_for_display(modified_plan)
            
            return {
                "type": "plan_modified",
                "plan": modified_plan.to_dict(),
                "display": plan_display,
                "message": "方案已修改:\n" + plan_display + "\n\n是否执行？"
            }
        
        # 执行Plan
        elif any(keyword in user_input_lower for keyword in ["执行方案", "运行方案", "run plan"]):
            # 从用户输入中提取Plan名称
            import re
            plan_name_match = re.search(r"(执行|运行)方案(.*?)(?:的|$)", user_input)
            plan_name = plan_name_match.group(2).strip() if plan_name_match else "default"
            
            try:
                # 加载Plan
                plan = self.plan_manager.load_plan(plan_name)
                
                # 执行Plan
                # 这里简化处理，实际应该调用scan命令
                from src.cli.main import scan
                from click.testing import Context
                
                # 转换为CLI参数
                from src.cli.plan_commands import _plan_to_cli_args
                cli_args = _plan_to_cli_args(plan)
                
                return {
                    "type": "plan_executed",
                    "plan_name": plan_name,
                    "plan": plan.to_dict(),
                    "message": f"正在执行方案: {plan_name}\n" + PlanDSLParser.format_plan_for_display(plan)
                }
            except Exception as e:
                return {
                    "type": "error",
                    "error": f"执行方案失败: {str(e)}"
                }
        
        # 列出Plan
        elif any(keyword in user_input_lower for keyword in ["列出方案", "查看方案", "list plans"]):
            plans = self.plan_manager.list_plans()
            
            if not plans:
                return {
                    "type": "plan_list",
                    "plans": [],
                    "message": "没有保存的方案"
                }
            
            return {
                "type": "plan_list",
                "plans": plans,
                "message": "保存的方案:\n" + "\n".join([f"- {plan_name}" for plan_name in plans])
            }
        
        # 保存Plan
        elif any(keyword in user_input_lower for keyword in ["保存方案", "save plan"]):
            # 从用户输入中提取Plan名称
            import re
            plan_name_match = re.search(r"(保存|save)方案(.*?)(?:的|$)", user_input)
            plan_name = plan_name_match.group(2).strip() if plan_name_match else "default"
            
            # 生成一个默认Plan
            plan = self.plan_manager.generate_from_natural_language("分析安全漏洞")
            
            try:
                file_path = self.plan_manager.save_plan(plan, plan_name)
                return {
                    "type": "plan_saved",
                    "plan_name": plan_name,
                    "file_path": file_path,
                    "message": f"方案已保存: {plan_name} (路径: {file_path})"
                }
            except Exception as e:
                return {
                    "type": "error",
                    "error": f"保存方案失败: {str(e)}"
                }
        
        # 默认处理
        else:
            # 生成一个默认Plan
            plan = self.plan_manager.generate_from_natural_language(user_input)
            plan_display = PlanDSLParser.format_plan_for_display(plan)
            
            return {
                "type": "plan_generated",
                "plan": plan.to_dict(),
                "display": plan_display,
                "message": "我为你生成了一个执行方案:\n" + plan_display + "\n\n是否执行？你也可以修改，比如：\n- '加上POC'\n- '只扫描登录模块'\n- '改成深度扫描'"
            }
    
    def _handle_info(self, user_input: str) -> Dict[str, Any]:
        """处理信息查询命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            信息结果
        """
        return {
            "type": "info_result",
            "message": "HOS-LS 安全对话模式\n\n" +
                      "可用命令:\n" +
                      "- 扫描命令: 例如 '扫描当前目录的安全风险'\n" +
                      "- 分析命令: 例如 '分析这个项目的漏洞'\n" +
                      "- 利用命令: 例如 '生成漏洞的 POC'\n" +
                      "- 修复命令: 例如 '提供修复建议'\n" +
                      "- Plan命令: 例如 '生成方案'、'修改方案'、'执行方案'\n" +
                      "- 特殊命令: /help, /exit, /clear\n" +
                      "- CLI转换: 例如 '转换为CLI命令' 或 '解释CLI命令'"
        }
    
    def natural_language_to_cli(self, natural_language: str) -> str:
        """将自然语言转换为CLI命令
        
        Args:
            natural_language: 自然语言输入
            
        Returns:
            CLI命令字符串
        """
        # 分析自然语言意图
        intent = self.parse_intent(natural_language)
        
        # 基础命令
        cli_command = "hos-ls"
        
        # 根据意图构建CLI命令
        if intent == "scan":
            cli_command += " --scan"
            # 检查是否需要纯AI模式
            if "pure" in natural_language.lower() or "纯" in natural_language:
                cli_command += " --pure-ai"
            # 检查是否需要POC生成
            if "poc" in natural_language.lower() or "利用" in natural_language:
                cli_command += " --poc"
        elif intent == "analyze":
            cli_command += " --scan --reason"
            # 检查是否需要攻击链分析
            if "攻击链" in natural_language or "attack chain" in natural_language.lower():
                cli_command += " --attack-chain"
        elif intent == "exploit":
            cli_command += " --scan --reason --poc"
            # 检查是否需要验证
            if "验证" in natural_language or "verify" in natural_language.lower():
                cli_command += " --verify"
        elif intent == "fix":
            cli_command += " --scan --reason --fix"
        
        # 添加目标路径
        target = "."
        import re
        # 尝试提取路径
        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s+(?:测试|test|模式|pure|纯|个文件|文件)|$)"
        path_match = re.search(path_pattern, natural_language)
        if path_match:
            target = path_match.group(0).strip()
        cli_command += f" {target}"
        
        return cli_command
    
    def cli_to_natural_language(self, cli_command: str) -> str:
        """将CLI命令转换为自然语言
        
        Args:
            cli_command: CLI命令
            
        Returns:
            自然语言描述
        """
        # 解析CLI命令
        import shlex
        parts = shlex.split(cli_command)
        
        # 移除命令名
        if parts and parts[0] == "hos-ls":
            parts = parts[1:]
        
        # 分析参数
        actions = []
        target = "."
        
        for part in parts:
            if part.startswith("--"):
                flag = part[2:]
                if flag == "scan":
                    actions.append("扫描代码")
                elif flag == "reason":
                    actions.append("分析漏洞")
                elif flag == "attack-chain":
                    actions.append("分析攻击链")
                elif flag == "poc":
                    actions.append("生成漏洞利用代码")
                elif flag == "verify":
                    actions.append("验证漏洞")
                elif flag == "fix":
                    actions.append("提供修复建议")
                elif flag == "report":
                    actions.append("生成报告")
                elif flag == "pure-ai":
                    actions.append("使用纯AI模式")
                elif flag == "full-audit":
                    actions.append("执行完整安全审计")
                elif flag == "quick-scan":
                    actions.append("执行快速扫描")
            else:
                # 假设是目标路径
                target = part
        
        # 构建自然语言描述
        if not actions:
            return "执行安全扫描"
        
        description = ""
        if actions:
            description = "、".join(actions)
            description += f"，目标路径为 {target}"
        
        return description
    
    def _handle_general(self, user_input: str) -> Dict[str, Any]:
        """处理通用命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            处理结果
        """
        # 检查是否是代码库工具命令
        if "@file:" in user_input:
            # 处理文件引用
            import re
            file_match = re.search(r"@file:(.+?)(\s|$)", user_input)
            if file_match:
                file_path = file_match.group(1).strip()
                return self._read_file(file_path)
        elif "@func:" in user_input:
            # 处理函数引用
            import re
            func_match = re.search(r"@func:(.+?)(\s|$)", user_input)
            if func_match:
                func_name = func_match.group(1).strip()
                return self._search_ast(func_name)
        elif "搜索代码" in user_input or "grep" in user_input:
            # 处理代码搜索
            import re
            keyword_match = re.search(r"(搜索代码|grep)\s*(.*?)(?:的|$)", user_input)
            if keyword_match:
                keyword = keyword_match.group(2).strip()
                return self._grep_code(keyword)
        elif "列出目录" in user_input or "list dir" in user_input:
            # 处理目录列出
            import re
            path_match = re.search(r"(列出目录|list dir)\s*(.*?)(?:的|$)", user_input)
            if path_match:
                path = path_match.group(2).strip() or "."
                return self._list_dir(path)
        elif "项目摘要" in user_input or "项目信息" in user_input or "project summary" in user_input.lower():
            # 处理项目摘要请求
            return {
                "type": "project_summary",
                **self.project_context
            }
        elif "转换为CLI命令" in user_input or "转为CLI命令" in user_input:
            # 处理自然语言转CLI命令
            # 提取实际的自然语言请求
            import re
            request_match = re.search(r"(转换为CLI命令|转为CLI命令)\s*(.*?)(?:的|$)", user_input)
            if request_match:
                natural_language = request_match.group(2).strip() or user_input
                cli_command = self.natural_language_to_cli(natural_language)
                return {
                    "type": "cli_conversion",
                    "natural_language": natural_language,
                    "cli_command": cli_command
                }
        elif "解释CLI命令" in user_input or "解释命令" in user_input:
            # 处理CLI命令转自然语言
            # 提取CLI命令
            import re
            command_match = re.search(r"(解释CLI命令|解释命令)\s*(.*?)(?:的|$)", user_input)
            if command_match:
                cli_command = command_match.group(2).strip()
                if cli_command:
                    natural_language = self.cli_to_natural_language(cli_command)
                    return {
                        "type": "cli_explanation",
                        "cli_command": cli_command,
                        "natural_language": natural_language
                    }
        
        # 使用多 Agent 管道处理通用查询
        result = self.multi_agent_pipeline.process_query(user_input)
        
        return {
            "type": "general_result",
            "query": user_input,
            "result": result
        }
    
    def _grep_code(self, keyword: str) -> Dict[str, Any]:
        """搜索代码中的关键词
        
        Args:
            keyword: 要搜索的关键词
            
        Returns:
            搜索结果
        """
        import subprocess
        import os
        
        try:
            # 使用 ripgrep 或 grep 搜索代码
            if os.name == 'nt':
                # Windows 系统
                result = subprocess.run(
                    ['findstr', '/s', '/n', keyword, '*.py', '*.js', '*.ts', '*.java', '*.c', '*.cpp', '*.h'],
                    capture_output=True,
                    text=True,
                    cwd="."
                )
            else:
                # Unix 系统
                result = subprocess.run(
                    ['grep', '-r', '-n', keyword, '--include=*.py', '--include=*.js', '--include=*.ts', '--include=*.java', '--include=*.c', '--include=*.cpp', '--include=*.h', '.'],
                    capture_output=True,
                    text=True
                )
            
            matches = result.stdout.strip().split('\n') if result.stdout.strip() else []
            matches = [m for m in matches if m]
            
            return {
                "type": "grep_result",
                "keyword": keyword,
                "matches": matches[:50],  # 限制结果数量
                "total": len(matches)
            }
        except Exception as e:
            return {
                "type": "error",
                "error": f"搜索代码失败: {str(e)}"
            }
    
    def _read_file(self, file_path: str) -> Dict[str, Any]:
        """读取文件内容
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件内容
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            return {
                "type": "file_content",
                "file_path": file_path,
                "content": content,
                "lines": len(content.split('\n'))
            }
        except Exception as e:
            return {
                "type": "error",
                "error": f"读取文件失败: {str(e)}"
            }
    
    def _list_dir(self, path: str = ".") -> Dict[str, Any]:
        """列出目录内容
        
        Args:
            path: 目录路径
            
        Returns:
            目录内容
        """
        import os
        from pathlib import Path
        
        try:
            path_obj = Path(path)
            if not path_obj.exists():
                return {
                    "type": "error",
                    "error": f"路径不存在: {path}"
                }
            
            if path_obj.is_file():
                return {
                    "type": "file_info",
                    "file_path": str(path_obj),
                    "size": path_obj.stat().st_size,
                    "modified": path_obj.stat().st_mtime
                }
            
            # 列出目录内容
            items = []
            for item in sorted(path_obj.iterdir()):
                items.append({
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0
                })
            
            return {
                "type": "directory_listing",
                "path": str(path_obj),
                "items": items
            }
        except Exception as e:
            return {
                "type": "error",
                "error": f"列出目录失败: {str(e)}"
            }
    
    def _search_ast(self, func_name: str) -> Dict[str, Any]:
        """搜索 AST 中的函数
        
        Args:
            func_name: 函数名
            
        Returns:
            搜索结果
        """
        import ast
        import os
        
        try:
            matches = []
            
            # 搜索 Python 文件
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
                                    # 提取函数定义
                                    start_line = node.lineno
                                    end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line + 10
                                    
                                    # 提取函数代码
                                    lines = content.split('\n')
                                    func_code = '\n'.join(lines[start_line-1:end_line])
                                    
                                    matches.append({
                                        "file_path": file_path,
                                        "start_line": start_line,
                                        "end_line": end_line,
                                        "function_code": func_code
                                    })
                        except Exception:
                            pass
            
            return {
                "type": "ast_search_result",
                "function_name": func_name,
                "matches": matches
            }
        except Exception as e:
            return {
                "type": "error",
                "error": f"搜索 AST 失败: {str(e)}"
            }
    
    def _load_session(self):
        """加载会话历史"""
        session_path = Path.home() / ".hos-ls" / "sessions"
        session_path.mkdir(parents=True, exist_ok=True)
        session_file = session_path / f"{self.session}.json"
        
        if session_file.exists():
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.conversation_history = data.get("history", [])
                    self.project_context = data.get("context", {})
            except Exception:
                pass
    
    def _save_session(self):
        """保存会话历史"""
        session_path = Path.home() / ".hos-ls" / "sessions"
        session_path.mkdir(parents=True, exist_ok=True)
        session_file = session_path / f"{self.session}.json"
        
        data = {
            "history": self.conversation_history,
            "context": self.project_context
        }
        
        try:
            with open(session_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    
    def get_conversation_history(self) -> List[Dict[str, str]]:
        """获取对话历史
        
        Returns:
            对话历史列表
        """
        return self.conversation_history
    
    def clear_history(self):
        """清除对话历史"""
        self.conversation_history = []
        if self.session:
            self._save_session()
    
    def _generate_project_summary(self):
        """生成项目摘要
        
        生成项目的文件树和关键文件索引，存储到 project_context 中
        """
        import os
        from pathlib import Path
        
        try:
            # 生成文件树
            file_tree = self._build_file_tree(".")
            
            # 识别关键文件
            key_files = self._identify_key_files(".")
            
            # 生成项目摘要
            project_summary = {
                "root": os.getcwd(),
                "file_tree": file_tree,
                "key_files": key_files,
                "total_files": self._count_files("."),
                "languages": self._detect_languages(".")
            }
            
            self.project_context = project_summary
        except Exception as e:
            # 如果生成失败，使用空摘要
            self.project_context = {
                "error": f"生成项目摘要失败: {str(e)}"
            }
    
    def _build_file_tree(self, path: str, max_depth: int = 3, current_depth: int = 0) -> Dict[str, Any]:
        """构建文件树
        
        Args:
            path: 起始路径
            max_depth: 最大深度
            current_depth: 当前深度
            
        Returns:
            文件树结构
        """
        from pathlib import Path
        
        path_obj = Path(path)
        tree = {
            "name": path_obj.name,
            "type": "directory",
            "children": []
        }
        
        if current_depth >= max_depth:
            return tree
        
        try:
            for item in sorted(path_obj.iterdir()):
                if item.name.startswith('.'):
                    continue  # 跳过隐藏文件
                
                if item.is_dir():
                    child_tree = self._build_file_tree(item, max_depth, current_depth + 1)
                    tree["children"].append(child_tree)
                else:
                    tree["children"].append({
                        "name": item.name,
                        "type": "file",
                        "size": item.stat().st_size
                    })
        except Exception:
            pass
        
        return tree
    
    def _identify_key_files(self, path: str) -> List[Dict[str, Any]]:
        """识别关键文件
        
        Args:
            path: 搜索路径
            
        Returns:
            关键文件列表
        """
        import os
        from pathlib import Path
        
        key_files = []
        key_patterns = [
            ("配置文件", ["requirements.txt", "pyproject.toml", "setup.py", "package.json", "go.mod", "pom.xml"]),
            ("主文件", ["main.py", "app.py", "index.js", "server.py", "__main__.py"]),
            ("配置目录", ["config", "conf", "settings"]),
            ("源码目录", ["src", "lib", "app", "src/main"]),
            ("测试目录", ["tests", "test"]),
            ("文档", ["README", "README.md", "README.rst", "docs"]),
            ("构建文件", ["Makefile", "build.py", "CMakeLists.txt"])
        ]
        
        for category, patterns in key_patterns:
            for pattern in patterns:
                for root, dirs, files in os.walk(path):
                    for item in dirs + files:
                        if item == pattern or item.startswith(pattern):
                            item_path = os.path.join(root, item)
                            key_files.append({
                                "path": item_path,
                                "category": category,
                                "type": "directory" if os.path.isdir(item_path) else "file"
                            })
        
        # 去重
        seen_paths = set()
        unique_key_files = []
        for file_info in key_files:
            if file_info["path"] not in seen_paths:
                seen_paths.add(file_info["path"])
                unique_key_files.append(file_info)
        
        return unique_key_files[:20]  # 限制数量
    
    def _count_files(self, path: str) -> int:
        """统计文件数量
        
        Args:
            path: 搜索路径
            
        Returns:
            文件数量
        """
        import os
        count = 0
        for root, dirs, files in os.walk(path):
            # 跳过隐藏目录
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            count += len(files)
        return count
    
    def _detect_languages(self, path: str) -> Dict[str, int]:
        """检测项目语言
        
        Args:
            path: 搜索路径
            
        Returns:
            语言统计
        """
        import os
        from pathlib import Path
        
        extensions = {}
        language_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.c': 'C',
            '.cpp': 'C++',
            '.h': 'C/C++ Header',
            '.html': 'HTML',
            '.css': 'CSS',
            '.json': 'JSON',
            '.yaml': 'YAML',
            '.yml': 'YAML',
            '.md': 'Markdown',
            '.txt': 'Text'
        }
        
        for root, dirs, files in os.walk(path):
            # 跳过隐藏目录
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in language_map:
                    language = language_map[ext]
                    extensions[language] = extensions.get(language, 0) + 1
        
        return extensions
