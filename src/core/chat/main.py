import asyncio
import sys
import re
from typing import Optional, List, Dict, Any
from pathlib import Path

from src.core.config import Config
from src.core.chat.terminal_ui import TerminalUI
from src.core.chat.pipeline_builder import PipelineBuilder
from src.ai.pure_ai.context_memory import ContextMemoryManager
from src.ai.pure_ai.multi_agent_pipeline import MultiAgentPipeline
from src.ai.intent.classifier import AIIntentClassifier
from src.ai.entity.extractor import AIEntityExtractor
from src.ai.pipeline.configurator import AIPipelineConfigurator


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
        "/scan": "开始安全扫描",
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
        self.agent = ConversationalSecurityAgent(config)
        self.agent.set_context_memory(self.context_memory)
        self.agent.set_ui(self.ui)
        self._running = False
        self._history_limit = 50
        self._use_ai = True
        self._intent_classifier: Optional[AIIntentClassifier] = None
        self._entity_extractor: Optional[AIEntityExtractor] = None
        self._pipeline_configurator: Optional[AIPipelineConfigurator] = None

    async def _get_ai_components(self) -> tuple:
        """获取AI组件（延迟初始化）"""
        if self._intent_classifier is None:
            self._intent_classifier = AIIntentClassifier(self.config)
            await self._intent_classifier.initialize()
        if self._entity_extractor is None:
            self._entity_extractor = AIEntityExtractor(self.config)
            await self._entity_extractor.initialize()
        if self._pipeline_configurator is None:
            self._pipeline_configurator = AIPipelineConfigurator()
            await self._pipeline_configurator.initialize()
        return self._intent_classifier, self._entity_extractor, self._pipeline_configurator

    async def run(self) -> None:
        self._running = True
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

                if user_input.startswith("/"):
                    response = await self._handle_command(user_input)
                elif user_input.startswith("@") and self._use_ai:
                    response = self._handle_codebase_command(user_input)
                elif self._use_ai:
                    response = await self._handle_ai_command(user_input)
                else:
                    if user_input.startswith("@"):
                        response = self._handle_codebase_command(user_input)
                    else:
                        response = await self.agent.process_message(user_input)

                if response:
                    self.ui.print_info(response)

            except KeyboardInterrupt:
                self.ui.print_warning("\nUse /exit to quit")
            except EOFError:
                self.ui.print_warning("\nInput ended, use /exit to quit")
            except Exception as e:
                self.ui.print_error(f"Error: {e}")

    async def _handle_ai_command(self, user_input: str) -> str:
        """使用AI处理自然语言命令"""
        try:
            classifier, extractor, _ = await self._get_ai_components()

            intent_result = await classifier.classify(user_input)
            entity_result = await extractor.extract(user_input)

            if intent_result.is_confident:
                from src.ai.intent.intent_model import IntentType

                intent_map = {
                    IntentType.SCAN: self._execute_scan,
                    IntentType.ANALYZE: self._execute_ai_analysis,
                    IntentType.EXPLAIN: self._execute_ai_explain,
                    IntentType.SEARCH: self._execute_ai_search,
                    IntentType.RESUME: self._execute_resume,
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
            loop = asyncio.get_event_loop()
            reader = asyncio.StreamReader()

            if sys.platform == "win32":
                import os
                os.system("")

            prompt = self.ui.get_prompt()
            print(prompt, end="", flush=True)

            line = await asyncio.get_event_loop().run_in_executor(
                None, sys.stdin.readline
            )

            return line.rstrip("\n\r") if line else None

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

        if cmd_lower == "/status":
            return self._format_status()

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

    def _should_exclude_path(self, path: Path) -> bool:
        exclude_dirs = {
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            "dist", "build", ".idea", ".vscode", "generated",
            "nvd_json_data_feeds", ".cache", "site-packages"
        }
        return any(excl in path.parts for excl in exclude_dirs)

    async def _execute_scan(self) -> str:
        try:
            from src.core.scanner import create_scanner
            scanner = create_scanner(self.config)
            target = "."
            result = scanner.scan_sync(target)

            summary = result.to_dict()["summary"]
            total = summary.get("total", 0)

            if total > 0:
                return (
                    f"Scan complete. Found {total} issues:\n"
                    f"- Critical/High: {summary.get('critical', 0) + summary.get('high', 0)}\n"
                    f"- Medium: {summary.get('medium', 0)}\n"
                    f"- Low/Info: {summary.get('low', 0) + summary.get('info', 0)}"
                )
            else:
                return "Scan complete. No issues found."

        except Exception as e:
            return f"Scan error: {e}"

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

    def stop(self) -> None:
        self._running = False


async def run_chat(config: Config) -> None:
    chat = ChatMain(config)
    await chat.run()


if __name__ == "__main__":
    from src.core.config import get_config
    config = get_config()
    asyncio.run(run_chat(config))