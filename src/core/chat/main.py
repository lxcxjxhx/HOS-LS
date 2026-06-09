import asyncio
import sys
import re
from typing import Optional, List, Dict, Any
from pathlib import Path

from src.core.config import Config
from src.core.chat.terminal_ui import TerminalUI
from src.core.chat.pipeline_builder import PipelineBuilder
from src.core.chat.session_manager import ChatSessionManager, ChatSession
from src.ai.pure_ai.context_memory import ContextMemoryManager
from src.ai.pure_ai.multi_agent_pipeline import MultiAgentPipeline
from src.ai.intent.classifier import AIIntentClassifier
from src.ai.entity.extractor import AIEntityExtractor
try:
    from src.ai.pipeline.configurator import AIPipelineConfigurator
    _HAS_AI_CONFIGURATOR = True
except ModuleNotFoundError:
    AIPipelineConfigurator = None  # type: ignore
    _HAS_AI_CONFIGURATOR = False


class ConversationalSecurityAgent:
    def __init__(self, config: Config):
        self.config = config
        self.context_memory: Optional[ContextMemoryManager] = None
        self.ui: Optional[TerminalUI] = None
        self.pipeline_builder = PipelineBuilder()
        self._initialized = False

    def set_context_memory(self, context_memory: ContextMemoryManager) -> None:
        self.context_memory = context_memory

    def set_ui(self, ui: TerminalUI) -> None:
        self.ui = ui

    async def process_message(self, user_input: str) -> str:
        if not self.context_memory:
            return "Context memory not initialized"

        entities = self.context_memory.extract_entities(user_input)
        resolved_input = self.context_memory.resolve_pronouns(user_input)
        intent = self.context_memory.track_intent(resolved_input, entities)

        response = await self._generate_response(resolved_input, intent, entities)

        self.context_memory.add_to_history(
            user_input=user_input,
            entities=entities,
            intent=intent,
            response_summary=response[:100] if response else ""
        )

        return response

    async def _generate_response(self, user_input: str, intent: Optional[str], entities: List[Any]) -> str:
        if not self.ui:
            return f"Processing: {user_input}"

        return f"Understood intent: {intent or 'unknown'}. Processing {len(entities)} entities..."


class ChatMain:
    BUILTIN_COMMANDS = {
        "/help": "显示帮助信息",
        "/exit": "退出聊天",
        "/quit": "退出聊天",
        "/clear": "清除对话历史",
        "/history": "显示对话历史",
        "/scan": "开始安全扫描 (支持 --select 和路径参数)",
        "/resume": "恢复最近一次中断的扫描",
        "/sessions": "列出所有会话",
        "/load <id>": "加载指定会话",
        "/new": "创建新会话",
        "/last-scan": "显示最近一次扫描的摘要",
        "/pentest": "AI 驱动渗透测试 (支持路径和 --mode 参数)",
        "/export <format>": "导出当前会话和扫描结果 (html/json/markdown)",
        "/status": "显示系统状态",
    }

    CODEBASE_COMMANDS = {
        "@file": {"pattern": r"@file\s+([^\s]+)", "desc": "查看文件内容"},
        "@func": {"pattern": r"@func\s+([^\s]+)", "desc": "查看函数定义"},
        "@search": {"pattern": r"@search\s+['\"]([^'\"]+)['\"]", "desc": "搜索代码"},
        "@grep": {"pattern": r"@grep\s+([^\s]+)", "desc": "grep搜索"},
    }

    def __init__(self, config: Config):
        self.config = config
        self.ui = TerminalUI()
        self.context_memory = ContextMemoryManager()
        self.pipeline_builder = PipelineBuilder()
        self.session_manager = ChatSessionManager()
        self.agent = ConversationalSecurityAgent(config)
        self.agent.set_context_memory(self.context_memory)
        self.agent.set_ui(self.ui)
        self._running = False
        self._history_limit = 50
        self._use_ai = True
        self._intent_classifier: Optional[AIIntentClassifier] = None
        self._entity_extractor: Optional[AIEntityExtractor] = None
        self._pipeline_configurator: Optional[AIPipelineConfigurator] = None
        # 命令历史
        self._command_history: list[str] = []
        self._history_path = Path(".hos-ls-cache") / "chat_history.json"
        self._history_index: int = -1
        self._last_scan_summary: Optional[Dict[str, Any]] = None
        self._load_history()

    async def _get_ai_components(self) -> tuple:
        """获取AI组件（延迟初始化）"""
        if self._intent_classifier is None:
            self._intent_classifier = AIIntentClassifier(self.config)
            await self._intent_classifier.initialize()
        if self._entity_extractor is None:
            self._entity_extractor = AIEntityExtractor(self.config)
            await self._entity_extractor.initialize()
        if _HAS_AI_CONFIGURATOR and AIPipelineConfigurator is not None and self._pipeline_configurator is None:
            self._pipeline_configurator = AIPipelineConfigurator()
            await self._pipeline_configurator.initialize()
        return self._intent_classifier, self._entity_extractor, self._pipeline_configurator

    def _load_history(self) -> None:
        """从磁盘加载命令历史"""
        try:
            if self._history_path.exists():
                import json
                data = json.loads(self._history_path.read_text(encoding="utf-8"))
                self._command_history = data.get("history", [])[-200:]
        except Exception:
            self._command_history = []

    def _save_history(self) -> None:
        """保存命令历史到磁盘（限制最近200条）"""
        try:
            import json
            self._history_path.parent.mkdir(parents=True, exist_ok=True)
            limited = self._command_history[-200:]
            self._history_path.write_text(
                json.dumps({"history": limited}, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
        except Exception:
            pass

    def _get_context_hint(self) -> str:
        """根据当前状态返回上下文提示"""
        if self._last_scan_summary:
            total = self._last_scan_summary.get("total", 0)
            if total > 0:
                return f"发现 {total} 个漏洞，输入 /last-scan 查看，或提问"
            return "扫描完成，未发现问题，可以继续提问"
        return "输入 /scan 开始扫描，或提问安全问题"

    def _autocomplete_command(self, text: str) -> str:
        """自动补全当前输入的命令"""
        if not text or not text.endswith("\t"):
            return text

        # 移除末尾的 Tab
        text = text.rstrip("\t")
        words = text.split()
        if not words:
            return text

        last_word = words[-1]
        if not last_word.startswith(("/", "@")):
            return text

        # 收集所有可能的补全项
        candidates = []
        # 内置命令
        for cmd in self.BUILTIN_COMMANDS:
            cmd_base = cmd.split()[0]  # 如 /export <format> → /export
            if cmd_base.startswith(last_word) and cmd_base != last_word:
                candidates.append(cmd_base)
        # 代码库命令
        for cmd in self.CODEBASE_COMMANDS:
            if cmd.startswith(last_word) and cmd != last_word:
                candidates.append(cmd)

        if len(candidates) == 1:
            words[-1] = candidates[0]
            return " ".join(words) + " "
        elif len(candidates) > 1:
            self.ui.print_info("可能的命令: " + ", ".join(candidates))

        return text

    async def run(self) -> None:
        self._running = True
        # 创建新会话
        self.session_manager.create_session()
        self.ui.print_header(
            "HOS-LS Security Chat",
            "Type /help for available commands"
        )

        while self._running:
            try:
                user_input = await self._get_input()
                if not user_input or not user_input.strip():
                    continue

                user_input = user_input.strip()

                # 保存用户消息
                self.session_manager.current_session.add_message(
                    "user", user_input
                )

                # 判断是否需要显示思考动画
                needs_thinking = self._use_ai and not user_input.startswith("/") and not user_input.startswith("@")
                response = None

                if user_input.startswith("/"):
                    response = await self._handle_command(user_input)
                    # 扫描和恢复命令后显示快捷操作
                    if user_input.lower() in ("/scan", "/resume", "/pentest") or user_input.lower().startswith("/scan ") or user_input.lower().startswith("/pentest "):
                        self.ui.print_quick_actions(["/last-scan", "/export json", "/help"])
                elif user_input.startswith("@") and self._use_ai:
                    response = self._handle_codebase_command(user_input)
                elif self._use_ai:
                    with self.ui.show_thinking_spinner("思考中..."):
                        response = await self._handle_ai_command(user_input)
                else:
                    if user_input.startswith("@"):
                        response = self._handle_codebase_command(user_input)
                    else:
                        response = await self.agent.process_message(user_input)

                if response:
                    # 对较长响应使用打字动画
                    if len(response) > 200:
                        self.ui.print_typing_animation(response)
                    else:
                        self.ui.print_info(response)
                    # 保存AI回复
                    self.session_manager.current_session.add_message(
                        "assistant", response
                    )
                    # 持久化到磁盘
                    self.session_manager.save_session(self.session_manager.current_session)

            except KeyboardInterrupt:
                self.ui.print_warning("\nUse /exit to quit")
            except EOFError:
                self.ui.print_warning("\nInput ended, use /exit to quit")
            except Exception as e:
                self.ui.print_error(f"Error: {e}")

    async def _handle_ai_command(self, user_input: str) -> str:
        """使用AI处理自然语言命令"""
        # 自然语言扫描识别（无需AI分类器即可识别的简单模式）
        natural_scan = self._try_parse_natural_scan(user_input)
        if natural_scan:
            return await natural_scan()

        try:
            classifier, extractor, _ = await self._get_ai_components()

            intent_result = await classifier.classify(user_input)
            entity_result = await extractor.extract(user_input)

            if intent_result.is_confident:
                from src.ai.intent.intent_model import IntentType

                intent_map = {
                    IntentType.SCAN: lambda: self._execute_scan(entity_result.target_path or "."),
                    IntentType.ANALYZE: self._execute_ai_analysis,
                    IntentType.EXPLAIN: self._execute_ai_explain,
                    IntentType.SEARCH: self._execute_ai_search,
                    IntentType.RESUME: self._execute_resume,
                    IntentType.PENTEST: lambda: self._execute_pentest(entity_result.target_path or ".", "full"),
                    IntentType.HELP: lambda: self._format_help(),
                    IntentType.EXIT: lambda: "Goodbye!",
                    IntentType.STATUS: self._format_status,
                }

                handler = intent_map.get(intent_result.intent)
                if handler:
                    target = entity_result.target_path if entity_result.target_path else "."
                    if callable(handler):
                        if asyncio.iscoroutinefunction(handler):
                            return await handler(target)
                        else:
                            return handler()

            return await self.agent.process_message(user_input)

        except Exception as e:
            self.ui.print_error(f"AI command handling failed: {e}")
            return await self.agent.process_message(user_input)

    def _try_parse_natural_scan(self, user_input: str):
        """尝试识别自然语言扫描请求，返回可执行的协程函数或None
        
        支持的模式：
        - "帮我扫描 xxx" / "scan xxx"
        - "只扫描 Controller 文件"
        - "上次扫描结果怎么样" / "结果"
        - "继续上次的扫描" / "恢复"
        """
        text = user_input.lower()

        # "继续上次" / "恢复" → resume
        if any(kw in text for kw in ['继续', '恢复', 'resume', 'continue']):
            if any(kw in text for kw in ['上次', '扫描', 'scan']):
                return self._execute_resume

        # "上次结果" / "结果怎么样" → last-scan
        if any(kw in text for kw in ['上次结果', '结果怎么样', '上次扫描', 'last scan', 'last result']):
            return lambda: self._show_last_scan()

        # "扫描" + 路径 → scan with path
        if any(kw in text for kw in ['扫描', 'scan', '扫一下', '帮我扫']):
            # 提取路径：尝试从输入中提取类似路径的文本
            import re
            # 匹配常见路径模式
            path_patterns = [
                r'扫描\s+([^\s，,。.!?]+)',
                r'scan\s+([^\s，,。.!?]+)',
                r'扫\s+([^\s，,。.!?]+)',
                r'帮我扫描?\s+([^\s，,。.!?]+)',
            ]
            for pat in path_patterns:
                match = re.search(pat, user_input)
                if match:
                    path = match.group(1).strip()
                    if path and not path.startswith(('的', '了', '吗', '呢')):
                        return lambda p=path: self._execute_scan(p)

            # 没有提取到路径，扫描当前目录
            return lambda: self._execute_scan(".")

        return None

    async def _execute_ai_analysis(self, target: str) -> str:
        """AI增强的分析"""
        try:
            from src.core.scanner import create_scanner
            scanner = create_scanner(self.config)
            result = scanner.scan_sync(target)

            summary = result.to_dict()["summary"]
            total = summary.get("total", 0)

            if total > 0:
                return (
                    f"分析完成。发现 {total} 个问题:\n"
                    f"- 严重/高危: {summary.get('critical', 0) + summary.get('high', 0)}\n"
                    f"- 中危: {summary.get('medium', 0)}\n"
                    f"- 低危/信息: {summary.get('low', 0) + summary.get('info', 0)}"
                )
            else:
                return "分析完成，未发现问题。"

        except Exception as e:
            return f"分析错误: {e}"

    async def _execute_ai_explain(self, target: str) -> str:
        """AI增强的解释"""
        try:
            from src.ai.pure_ai.context_builder import ContextBuilder

            builder = ContextBuilder(self.config)
            context = builder.build_context(target)

            response = f"文件分析: {target}\n\n"
            response += f"- 函数数量: {len(context['file_structure'].get('functions', []))}\n"
            response += f"- 类数量: {len(context['file_structure'].get('classes', []))}\n"
            response += f"- 导入语句: {len(context['imports'])}\n"
            response += f"- 函数调用: {len(context['function_calls'])}\n"

            return response

        except Exception as e:
            return f"解释失败: {str(e)}"

    async def _execute_ai_search(self, query: str) -> str:
        """AI增强的搜索"""
        if not query:
            return "请提供搜索关键词。"

        results = []
        search_extensions = {".py", ".js", ".ts", ".java", ".cpp", ".c", ".h"}

        for ext in search_extensions:
            for file_path in Path(".").rglob(f"*{ext}"):
                if self._should_exclude_path(file_path):
                    continue
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    if query.lower() in content.lower():
                        lines = content.lower().split("\n")
                        matching_lines = [
                            (i + 1, line)
                            for i, line in enumerate(lines)
                            if query.lower() in line.lower()
                        ]
                        if matching_lines[:3]:
                            snippets = [
                                f"  行{ln}: {line.strip()[:100]}"
                                for ln, line in matching_lines[:3]
                            ]
                            results.append(
                                f"**{file_path}** (显示前3个匹配):\n" + "\n".join(snippets)
                            )
                except Exception:
                    continue

        if results:
            return f"找到匹配于 {len(results)} 个文件:\n\n" + "\n---\n".join(results[:10])
        else:
            return f"未找到匹配: {query}"

    async def _get_input(self) -> Optional[str]:
        try:
            session = self.session_manager.current_session
            session_id = session.session_id[:8] if session else ""
            topic = session.topic if session else ""
            context_hint = self._get_context_hint()
            prompt = self.ui.get_prompt(session_id, topic, context_hint)
            print(prompt, end="", flush=True)

            line = await asyncio.get_event_loop().run_in_executor(
                None, sys.stdin.readline
            )

            if not line:
                return None

            text = line.rstrip("\n\r")

            # Tab 自动补全（检测末尾是否有 Tab 字符）
            if text.endswith("\t"):
                text = self._autocomplete_command(text)
                if text.endswith(" "):
                    # 补全后有尾部空格，提示用户继续输入
                    print(text, end="", flush=True)

            # !! 重复上一条命令
            if text == "!!" and self._command_history:
                text = self._command_history[-1]
                self.ui.print_info(f"重复命令: {text}")

            if text.strip():
                self._command_history.append(text.strip())
                self._save_history()
                self._history_index = -1

            return text.strip() if text else None

        except Exception:
            return None

    async def _handle_command(self, command: str) -> Optional[str]:
        cmd_lower = command.lower()

        if cmd_lower in ("/exit", "/quit"):
            self.stop()
            return "Goodbye!"

        if cmd_lower == "/help":
            return self._format_help()

        if cmd_lower == "/clear":
            self.context_memory._conversation_history.clear()
            self.context_memory._entities.clear()
            return "History cleared."

        if cmd_lower == "/history":
            return self._format_history()

        if cmd_lower == "/scan":
            return await self._execute_scan()

        if cmd_lower.startswith("/scan "):
            # /scan <path> 或 /scan --select 或 /scan <path> --select
            return await self._handle_scan_command(command)

        if cmd_lower == "/resume":
            return await self._execute_resume()

        if cmd_lower == "/pentest" or cmd_lower.startswith("/pentest "):
            return await self._handle_pentest_command(command)

        if cmd_lower == "/status":
            return self._format_status()

        if cmd_lower == "/sessions":
            return self._list_sessions()

        if cmd_lower.startswith("/load "):
            session_id = command[6:].strip()
            return self._load_session(session_id)

        if cmd_lower == "/new":
            return self._new_session()

        if cmd_lower == "/last-scan":
            return self._show_last_scan()

        if cmd_lower.startswith("/export "):
            fmt = command[8:].strip().lower()
            return self._export_session(fmt)

        unknown_cmd = command.split()[0] if command else ""
        return f"Unknown command: {unknown_cmd}. Type /help for available commands."

    def _handle_codebase_command(self, command: str) -> str:
        for cmd_name, cmd_info in self.CODEBASE_COMMANDS.items():
            pattern = cmd_info["pattern"]
            match = re.search(pattern, command)
            if match:
                arg = match.group(1)
                if cmd_name == "@file":
                    return self._handle_file_command(arg)
                elif cmd_name == "@func":
                    return self._handle_func_command(arg)
                elif cmd_name in ("@search", "@grep"):
                    return self._handle_search_command(arg)

        return f"Unknown codebase command. Use @file, @func, @search, or @grep."

    def _handle_file_command(self, file_path: str) -> str:
        try:
            path = Path(file_path)
            if not path.exists():
                return f"File not found: {file_path}"

            if path.is_dir():
                return f"Path is a directory, not a file: {file_path}"

            max_size = 100 * 1024
            if path.stat().st_size > max_size:
                return f"File too large: {file_path} (max {max_size} bytes)"

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            lines = content.split("\n")
            if len(lines) > 100:
                content = "\n".join(lines[:100]) + f"\n... ({len(lines) - 100} more lines)"
            else:
                content = f"```\n{content}\n```"

            return f"**File: {file_path}**\n\n{content}"

        except Exception as e:
            return f"Error reading file: {e}"

    def _handle_func_command(self, func_name: str) -> str:
        try:
            search_patterns = [
                rf"def\s+{re.escape(func_name)}\s*\(",
                rf"function\s+{re.escape(func_name)}\s*\(",
                rf"class\s+{re.escape(func_name)}\s*[:\(]",
            ]

            results = []
            for pattern in search_patterns:
                for py_file in Path(".").rglob("*.py"):
                    if self._should_exclude_path(py_file):
                        continue
                    try:
                        content = py_file.read_text(encoding="utf-8", errors="ignore")
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            start = max(0, match.start() - 50)
                            end = min(len(content), match.end() + 200)
                            snippet = content[start:end]
                            results.append(f"**{py_file}:{match.group()}**\n```\n{snippet}\n```")
                    except Exception:
                        continue

            if results:
                return f"Found {len(results)} matches for '{func_name}':\n\n" + "\n---\n".join(results[:5])
            else:
                return f"No function or class found matching: {func_name}"

        except Exception as e:
            return f"Error searching for function: {e}"

    def _handle_search_command(self, query: str) -> str:
        try:
            results = []
            search_extensions = {".py", ".js", ".ts", ".java", ".cpp", ".c", ".h"}

            for ext in search_extensions:
                for file_path in Path(".").rglob(f"*{ext}"):
                    if self._should_exclude_path(file_path):
                        continue
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        if query.lower() in content.lower():
                            lines = content.lower().split("\n")
                            matching_lines = [
                                (i + 1, line)
                                for i, line in enumerate(lines)
                                if query.lower() in line.lower()
                            ]
                            if matching_lines[:3]:
                                snippets = [
                                    f"  Line {ln}: {line.strip()[:100]}"
                                    for ln, line in matching_lines[:3]
                                ]
                                results.append(
                                    f"**{file_path}** (showing first 3 matches):\n" + "\n".join(snippets)
                                )
                    except Exception:
                        continue

            if results:
                return f"Found matches in {len(results)} files:\n\n" + "\n---\n".join(results[:10])
            else:
                return f"No matches found for: {query}"

        except Exception as e:
            return f"Error searching: {e}"

    async def _should_exclude_path(self, path: Path) -> bool:
        exclude_dirs = {
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            "dist", "build", ".idea", ".vscode", "generated",
            "nvd_json_data_feeds", ".cache", "site-packages"
        }
        return any(excl in path.parts for excl in exclude_dirs)

    def _format_help(self) -> str:
        lines = [
            "**Available Commands:**",
            "",
            "**Built-in Commands:**",
        ]
        for cmd, desc in self.BUILTIN_COMMANDS.items():
            lines.append(f"  {cmd:<12} - {desc}")

        lines.append("")
        lines.append("**Codebase Tools:**")
        for cmd_name, cmd_info in self.CODEBASE_COMMANDS.items():
            lines.append(f"  {cmd_name:<12} - {cmd_info['desc']}")

        lines.append("")
        lines.append("**Examples:**")
        lines.append("  @file src/core/scanner.py")
        lines.append("  @func SecurityAgent")
        lines.append("  @search password")
        lines.append("  /scan")
        lines.append("  /pentest example.com --mode full")
        lines.append("  帮我扫描 src 目录")
        lines.append("  对 example.com 进行渗透测试")

        return "\n".join(lines)

    def _format_history(self) -> str:
        history = self.context_memory.get_conversation_history()
        if not history:
            return "No conversation history."

        lines = ["**Recent Conversation:**", ""]
        for i, turn in enumerate(history[-10:], 1):
            lines.append(f"{i}. **[{turn.intent or 'unknown'}]** {turn.user_input[:60]}")

        return "\n".join(lines)

    def _format_status(self) -> str:
        stats = self.context_memory.get_entity_stats()

        lines = [
            "**System Status:**",
            "",
            "  Memory:",
            f"    - Entities: {stats['total_entities']}",
            f"    - History turns: {stats['total_history']}",
        ]

        if stats.get("by_type"):
            lines.append("    - By type:")
            for entity_type, count in stats["by_type"].items():
                lines.append(f"      {entity_type}: {count}")

        if stats.get("recent_intent"):
            lines.append(f"    - Current intent: {stats['recent_intent']}")

        lines.append("")
        lines.append("  Pipeline:")
        enabled = self.pipeline_builder.get_enabled_agents(
            self.pipeline_builder.build_pipeline(list(self.pipeline_builder._nodes.keys()))
        )
        lines.append(f"    - Enabled agents: {len(enabled)}")

        return "\n".join(lines)

    def _list_sessions(self) -> str:
        """列出所有持久化会话"""
        sessions = self.session_manager.list_sessions()
        if not sessions:
            return "No saved sessions."

        lines = ["**Saved Sessions:** (按时间倒序)", ""]
        for i, s in enumerate(sessions[:10], 1):
            current = " <-- 当前" if self.session_manager.current_session and self.session_manager.current_session.session_id == s.session_id else ""
            lines.append(f"{i}. **{s.session_id}** - {s.topic}{current}")
            lines.append(f"   消息: {len(s.messages)} | 更新: {s.updated_at[:16]}")

        if len(sessions) > 10:
            lines.append(f"\n... 还有 {len(sessions) - 10} 个会话")

        return "\n".join(lines)

    def _load_session(self, session_id: str) -> str:
        """加载会话并恢复历史到 context_memory"""
        session = self.session_manager.load_session(session_id)
        if not session:
            return f"Session not found: {session_id}"

        # 恢复历史到 context_memory
        self.context_memory._conversation_history.clear()
        for msg in session.messages:
            if msg.role == "user":
                self.context_memory.add_to_history(
                    user_input=msg.content,
                    entities=[],
                    intent=None,
                    response_summary=""
                )

        self.ui.print_info(f"已加载会话: {session.topic} ({len(session.messages)} 条消息)")
        return f"Session loaded: {session.get_summary()}"

    def _new_session(self) -> str:
        """创建新会话"""
        old = self.session_manager.current_session
        old_id = old.session_id if old else "none"
        self.session_manager.create_session()
        # 清空内存历史
        self.context_memory._conversation_history.clear()
        return f"New session created. (旧会话: {old_id})"

    async def _execute_resume(self) -> str:
        """恢复最近一次中断的扫描"""
        try:
            import time
            from src.core.scan_cache import get_scan_cache_manager
            cache_mgr = get_scan_cache_manager()
            session = cache_mgr.load_latest_session()
            if not session:
                return "No scan session found. Run /scan first."
            if session.progress.completed_files >= session.progress.total_files:
                return f"Session {session.session_id} is already complete. Run /scan for a new scan."

            pending = cache_mgr.get_pending_files(session.session_id, [])
            if not pending:
                return "No pending files to resume. Session may be complete."

            # Trigger resume scan
            self.ui.print_info(f"Resuming scan session: {session.session_id}")
            self.ui.print_info(f"Pending files: {len(pending)}")
            self.ui.print_context_hint(f"正在恢复扫描: {session.target}")

            from src.core.scanner import create_scanner
            scanner = create_scanner(self.config)
            scan_start = time.time()
            result = scanner.scan_sync(session.target)
            elapsed = time.time() - scan_start

            summary = result.to_dict()["summary"]
            total = summary.get("total", 0)
            cache_mgr.mark_session_completed(session.session_id)

            # Save scan result to chat session
            if self.session_manager.current_session:
                self.session_manager.current_session.scan_results.append({
                    "session_id": session.session_id,
                    "target": session.target,
                    "total": total,
                    "summary": summary,
                })
                self.session_manager.save_session(self.session_manager.current_session)

            # 更新扫描摘要用于上下文提示
            self._last_scan_summary = {"total": total, "summary": summary}

            # 显示扫描摘要面板
            self.ui.print_scan_summary_panel(
                total=total,
                critical=summary.get("critical", 0),
                high=summary.get("high", 0),
                medium=summary.get("medium", 0),
                low=summary.get("low", 0),
                info=summary.get("info", 0),
                elapsed=elapsed,
                files_scanned=summary.get("files_scanned", 0),
            )

            # 显示快捷操作
            self.ui.print_quick_actions(["/last-scan", "/export json", "/help"])

            if total > 0:
                return (
                    f"Scan resumed and completed. Found {total} issues:\n"
                    f"- Critical/High: {summary.get('critical', 0) + summary.get('high', 0)}\n"
                    f"- Medium: {summary.get('medium', 0)}\n"
                    f"- Low/Info: {summary.get('low', 0) + summary.get('info', 0)}"
                )
            return "Scan resumed and completed. No issues found."

        except Exception as e:
            return f"Resume error: {e}"

    async def _handle_scan_command(self, command: str) -> str:
        """处理 /scan 命令的参数"""
        parts = command.split()
        target = "."
        use_select = False

        for part in parts[1:]:
            if part.lower() == "--select":
                use_select = True
            elif not part.startswith("-"):
                target = part

        if use_select:
            return await self._execute_scan_with_select(target)

        return await self._execute_scan(target)

    async def _execute_scan(self, target: str = ".") -> str:
        """执行安全扫描"""
        try:
            import time
            from src.core.scanner import create_scanner
            from src.core.scan_cache import get_scan_cache_manager

            # 扫描前提示
            self.ui.print_context_hint(f"正在扫描: {target}")

            scanner = create_scanner(self.config)
            scan_start = time.time()
            result = scanner.scan_sync(target)
            elapsed = time.time() - scan_start

            summary = result.to_dict()["summary"]
            total = summary.get("total", 0)

            # 显示扫描摘要面板
            self.ui.print_scan_summary_panel(
                total=total,
                critical=summary.get("critical", 0),
                high=summary.get("high", 0),
                medium=summary.get("medium", 0),
                low=summary.get("low", 0),
                info=summary.get("info", 0),
                elapsed=elapsed,
                files_scanned=summary.get("files_scanned", 0),
            )

            # Save scan result to chat session
            if self.session_manager.current_session:
                self.session_manager.current_session.scan_results.append({
                    "target": target,
                    "total": total,
                    "summary": summary,
                    "timestamp": self.session_manager.current_session.updated_at,
                })
                self.session_manager.current_session.target_path = target
                self.session_manager.save_session(self.session_manager.current_session)

            # Also save to scan cache for --resume
            try:
                cache_mgr = get_scan_cache_manager()
                session = cache_mgr.create_session(target=str(target), config={})
            except Exception:
                pass

            # 更新扫描摘要用于上下文提示
            self._last_scan_summary = {"total": total, "summary": summary}

            # 显示快捷操作
            self.ui.print_quick_actions(["/last-scan", "/export json", "/export html", "/help"])

            if total > 0:
                return (
                    f"Scan complete. Found {total} issues:\n"
                    f"- Critical/High: {summary.get('critical', 0) + summary.get('high', 0)}\n"
                    f"- Medium: {summary.get('medium', 0)}\n"
                    f"- Low/Info: {summary.get('low', 0) + summary.get('info', 0)}"
                )
            return "Scan complete. No issues found."

        except Exception as e:
            return f"Scan error: {e}"

    async def _execute_scan_with_select(self, target: str = ".") -> str:
        """执行扫描并交互式选择文件"""
        try:
            from src.utils.file_selector import InteractiveFileSelector
            from rich.console import Console

            console = Console(emoji=False, force_terminal=True)
            selector = InteractiveFileSelector(console)
            selected_files = selector.run(target)

            if not selected_files:
                return "Scan cancelled. No files selected."

            self.ui.print_info(f"Selected {len(selected_files)} files for scanning")

            from src.core.scanner import create_scanner
            from src.core.scan_cache import get_scan_cache_manager
            from src.core.engine import ScanResult, Finding, Location, Severity, ScanStatus
            from datetime import datetime as dt

            scanner = create_scanner(self.config)
            # Pass selected files via config
            self.config.__dict__['selected_files'] = selected_files
            result = scanner.scan_sync(target)

            summary = result.to_dict()["summary"]
            total = summary.get("total", 0)

            if self.session_manager.current_session:
                self.session_manager.current_session.scan_results.append({
                    "target": target,
                    "total": total,
                    "summary": summary,
                    "selected_files": len(selected_files),
                    "timestamp": self.session_manager.current_session.updated_at,
                })
                self.session_manager.save_session(self.session_manager.current_session)

            if total > 0:
                return (
                    f"Scan complete ({len(selected_files)} files). Found {total} issues:\n"
                    f"- Critical/High: {summary.get('critical', 0) + summary.get('high', 0)}\n"
                    f"- Medium: {summary.get('medium', 0)}\n"
                    f"- Low/Info: {summary.get('low', 0) + summary.get('info', 0)}"
                )
            return f"Scan complete ({len(selected_files)} files). No issues found."

        except Exception as e:
            return f"Interactive scan error: {e}"

    async def _handle_pentest_command(self, command: str) -> str:
        """处理 /pentest 命令的参数"""
        parts = command.split()
        target = "."
        mode = "full"

        for i, part in enumerate(parts[1:], 1):
            if part.lower() == "--mode" and i + 1 < len(parts) - 1:
                mode = parts[i + 2].lower()
                if mode not in ("recon", "scan", "full", "exploit"):
                    return f"无效的模式: {mode}。支持: recon, scan, full, exploit"
            elif part.lower().startswith("--mode="):
                mode = part.split("=", 1)[1].lower()
                if mode not in ("recon", "scan", "full", "exploit"):
                    return f"无效的模式: {mode}。支持: recon, scan, full, exploit"
            elif not part.startswith("-"):
                target = part

        return await self._execute_pentest(target, mode)

    async def _execute_pentest(self, target: str = ".", mode: str = "full") -> str:
        """执行AI渗透测试（实时发现输出）"""
        try:
            import time
            from src.cli.commands.pentest import _run_pentest

            self.ui.print_context_hint(f"正在启动渗透测试: {target} (模式: {mode})")
            self.ui.print_info("=" * 60)
            self.ui.print_info("[bold]渗透测试开始[/bold]")
            self.ui.print_info(f"  目标: {target}")
            self.ui.print_info(f"  模式: {mode}")
            self.ui.print_info("=" * 60)

            pentest_start = time.time()

            # 跟踪已输出的发现，避免重复输出
            previous_finding_count = 0
            previous_phase = ""

            def _progress_callback(iteration: int, max_iter: int, step: str, findings: list):
                """渗透测试实时进度回调"""
                nonlocal previous_finding_count, previous_phase

                current_count = len(findings) if findings else 0
                new_count = current_count - previous_finding_count

                # 阶段映射：根据 step 和发现类型判断当前阶段
                phase_labels = {
                    "ai_reason": "AI 决策",
                    "tool_exec": "工具执行",
                    "ai_analyze": "AI 分析",
                    "ai_decide": "AI 评估",
                }
                phase_label = phase_labels.get(step, step)

                # 阶段推断：根据发现的类型判断当前处于哪个渗透阶段
                current_phase = self._infer_pentest_phase(findings)
                if current_phase != previous_phase:
                    self.ui.print_info(f"\n{'─' * 40}")
                    self.ui.print_info(f"[bold cyan]▸ 阶段: {current_phase}[/bold cyan]")
                    previous_phase = current_phase

                # 输出新发现
                if new_count > 0:
                    new_findings = findings[previous_finding_count:] if findings else []
                    for f in new_findings:
                        self._print_pentest_finding(f)
                    previous_finding_count = current_count

                # 每3步输出一次进度摘要（避免过于频繁）
                if step == "ai_decide":
                    progress_pct = int((iteration + 1) / max_iter * 100) if max_iter > 0 else 0
                    self.ui.print_info(
                        f"  [dim]进度: {iteration + 1}/{max_iter} ({progress_pct}%) | "
                        f"发现: {current_count} 个[/dim]"
                    )

            result = await _run_pentest(
                config=self.config,
                target=target,
                mode=mode,
                tool_list=[],
                deep=False,
                sandbox=False,
                authorized_targets=None,
                session_id=None,
                progress_callback=_progress_callback,
            )
            elapsed = time.time() - pentest_start

            findings = result.get("findings", [])
            total = len(findings)

            # Count severities
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                sev = f.get("severity", "info").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

            self.ui.print_info("=" * 60)
            self.ui.print_info("[bold green]✓ 渗透测试完成[/bold green]")
            self.ui.print_info(f"  耗时: {elapsed:.2f}s | 总发现: {total} 个")
            self.ui.print_info("=" * 60)

            self.ui.print_scan_summary_panel(
                total=total,
                critical=severity_counts["critical"],
                high=severity_counts["high"],
                medium=severity_counts["medium"],
                low=severity_counts["low"],
                info=severity_counts["info"],
                elapsed=elapsed,
                files_scanned=0,
            )

            self.ui.print_quick_actions(["/last-scan", "/export json", "/help"])

            if total > 0:
                return f"渗透测试完成。发现 {total} 个问题:\n- Critical: {severity_counts['critical']}\n- High: {severity_counts['high']}\n- Medium: {severity_counts['medium']}\n- Low: {severity_counts['low']}\n- Info: {severity_counts['info']}"
            return "渗透测试完成，未发现问题。"
        except Exception as e:
            return f"渗透测试失败: {e}"

    def _infer_pentest_phase(self, findings: list) -> str:
        """根据发现列表推断当前渗透测试阶段"""
        if not findings:
            return "🔍 初始侦察"

        # 检查发现的类型分布
        types = [f.get("type", "") for f in findings if isinstance(f, dict)]
        type_set = set(types)

        # Exploit 阶段特征
        if any(t in type_set for t in ("exploit", "poc", "rce", "sqli", "xss", "command_injection", "auth_bypass")):
            return "💥 漏洞利用"

        # Scan 阶段特征
        if any(t in type_set for t in ("cve", "vulnerability", "misconfiguration", "tech_detection", "version")):
            return "🔬 漏洞扫描"

        # Recon 阶段特征
        if any(t in type_set for t in ("open_port", "subdomain", "tech_detection", "service", "crawl")):
            return "🔍 信息收集"

        # 默认根据发现数量判断
        if len(findings) < 5:
            return "🔍 信息收集"
        elif len(findings) < 15:
            return "🔬 漏洞扫描"
        else:
            return "💥 漏洞利用"

    def _print_pentest_finding(self, finding: dict) -> None:
        """输出单个渗透测试发现"""
        if not isinstance(finding, dict):
            self.ui.print_info(f"  发现: {finding}")
            return

        sev = finding.get("severity", "info").lower()
        f_type = finding.get("type", "unknown")
        evidence = finding.get("evidence", finding.get("description", ""))[:120]
        target = finding.get("target", finding.get("url", finding.get("port", "")))

        # 严重级别样式
        sev_config = {
            "critical": ("red", "⚡"),
            "high": ("orange_red1", "🔴"),
            "medium": ("yellow", "🟡"),
            "low": ("green", "🟢"),
            "info": ("dim", "ℹ️"),
        }
        color, icon = sev_config.get(sev, ("white", "•"))

        # 构建发现描述
        desc_parts = []
        if target:
            desc_parts.append(f"目标: {target}")
        if f_type != "unknown":
            desc_parts.append(f"类型: {f_type}")

        desc = " | ".join(desc_parts)
        if desc:
            desc = f" [{desc}]"

        if evidence:
            self.ui.print_info(f"  [{color}]{icon} [{sev.upper()}]{desc}[/{color}]")
            self.ui.print_info(f"    [dim]{evidence}[/dim]")
        else:
            self.ui.print_info(f"  [{color}]{icon} [{sev.upper()}]{desc}[/{color}]")

    def _show_last_scan(self) -> str:
        """显示最近一次扫描的摘要"""
        session = self.session_manager.current_session
        if not session or not session.scan_results:
            return "No scan results in current session. Run /scan first."

        last = session.scan_results[-1]
        summary = last.get("summary", {})
        total = last.get("total", 0)

        lines = [
            f"**Last Scan Result:**",
            f"- Target: {last.get('target', 'unknown')}",
            f"- Total issues: {total}",
            f"- Critical/High: {summary.get('critical', 0) + summary.get('high', 0)}",
            f"- Medium: {summary.get('medium', 0)}",
            f"- Low/Info: {summary.get('low', 0) + summary.get('info', 0)}",
        ]
        if last.get("selected_files"):
            lines.append(f"- Files scanned: {last['selected_files']}")

        return "\n".join(lines)

    def _export_session(self, fmt: str = "json") -> str:
        """导出当前会话和扫描结果"""
        session = self.session_manager.current_session
        if not session:
            return "No active session to export."

        fmt = fmt.lower()
        if fmt not in ("json", "html", "markdown", "md"):
            return f"Unsupported format: {fmt}. Use json, html, or markdown."

        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = Path(".hos-ls-cache") / "exports"
            output_dir.mkdir(parents=True, exist_ok=True)

            if fmt == "json":
                output_path = output_dir / f"session_{session.session_id}_{timestamp}.json"
                with open(output_path, 'w', encoding='utf-8') as f:
                    import json
                    json.dump(session.to_dict(), f, ensure_ascii=False, indent=2)
            else:
                output_path = output_dir / f"session_{session.session_id}_{timestamp}.{fmt}"
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(f"# HOS-LS Chat Session Export\n\n")
                    f.write(f"**Session ID:** {session.session_id}\n")
                    f.write(f"**Topic:** {session.topic}\n")
                    f.write(f"**Target:** {session.target_path}\n")
                    f.write(f"**Created:** {session.created_at}\n\n")
                    f.write("## Conversation\n\n")
                    for msg in session.messages:
                        role = "User" if msg.role == "user" else "AI"
                        f.write(f"### {role}\n\n{msg.content}\n\n")
                    if session.scan_results:
                        f.write("## Scan Results\n\n")
                        for sr in session.scan_results:
                            f.write(f"- Target: {sr.get('target', 'unknown')}")
                            f.write(f", Issues: {sr.get('total', 0)}\n")

            return f"Session exported to: {output_path}"

        except Exception as e:
            return f"Export error: {e}"

    def stop(self) -> None:
        self._running = False


async def run_chat(config: Config) -> None:
    chat = ChatMain(config)
    await chat.run()


if __name__ == "__main__":
    from src.core.config import get_config
    config = get_config()
    asyncio.run(run_chat(config))