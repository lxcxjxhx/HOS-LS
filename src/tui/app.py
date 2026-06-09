"""HOS-LS Textual TUI 应用

基于 Textual 框架的终端用户界面，提供会话管理、AI 安全问答、代码分析等功能。
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import (
    Header,
    Footer,
    Input,
    RichLog,
    Label,
    Button,
    Static,
    Tree,
)
from textual.binding import Binding
from textual.events import Event
from textual.screen import ModalScreen
from textual import work
from textual.worker import get_current_worker
from rich.markdown import Markdown
from rich.text import Text

from src.core.config import Config


# ---------------------------------------------------------------------------
# 主题系统
# ---------------------------------------------------------------------------

THEMES = {
    "dark": {
        "bg": "#1a1a2e",
        "surface": "#16213e",
        "primary": "#0f3460",
        "accent": "#e94560",
        "text": "#eee",
        "text_muted": "#888",
        "user_msg": "#0f3460",
        "ai_msg": "#1a3a2a",
    },
    "light": {
        "bg": "#f5f5f5",
        "surface": "#ffffff",
        "primary": "#1976d2",
        "accent": "#d32f2f",
        "text": "#212121",
        "text_muted": "#757575",
        "user_msg": "#e3f2fd",
        "ai_msg": "#e8f5e9",
    },
    "monokai": {
        "bg": "#272822",
        "surface": "#3e3d32",
        "primary": "#66d9ef",
        "accent": "#f92672",
        "text": "#f8f8f2",
        "text_muted": "#75715e",
        "user_msg": "#3e3d32",
        "ai_msg": "#2d2e27",
    },
    "solarized": {
        "bg": "#002b36",
        "surface": "#073642",
        "primary": "#268bd2",
        "accent": "#dc322f",
        "text": "#839496",
        "text_muted": "#586e75",
        "user_msg": "#073642",
        "ai_msg": "#003845",
    },
}


# ---------------------------------------------------------------------------
# WelcomeScreen 欢迎界面
# ---------------------------------------------------------------------------

WELCOME_ART = """\
    ███╗   ███╗ ██████╗
    ████╗ ████║ ██╔══██╗
    ██╔████╔██║ ██████╔╝
    ██║╚██╔╝██║ ██╔═══╝
    ██║ ╚═╝ ██║ ██║
    ╚═╝     ╚═╝ ╚═╝"""

WELCOME_FEATURES = """核心功能:
 🔍  AI 驱动代码安全扫描
 💬  自然语言安全问答
 📊  漏洞分析与攻击链解释
 📁  交互式文件选择扫描

快捷操作:
 • 输入问题直接对话
 • /scan 开始扫描
 • /help 查看帮助
 • Ctrl+N 新会话"""


class WelcomeScreen(ModalScreen):
    """首次启动时的欢迎界面"""

    DEFAULT_CSS = """
    WelcomeScreen {
        align: center middle;
        background: $background 80%;
    }
    WelcomeScreen #welcome-box {
        width: 64;
        height: auto;
        max-height: 90%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    WelcomeScreen #art-label {
        text-align: center;
        color: $accent;
        content-align: center middle;
    }
    WelcomeScreen #title-label {
        text-align: center;
        text-style: bold;
        content-align: center middle;
        margin: 1 0;
    }
    WelcomeScreen #subtitle-label {
        text-align: center;
        color: $text-muted;
        content-align: center middle;
        margin-bottom: 1;
    }
    WelcomeScreen #divider {
        text-align: center;
        color: $primary;
        margin: 1 0;
    }
    WelcomeScreen #features-label {
        margin: 1 0;
        color: $text;
    }
    WelcomeScreen #welcome-btn {
        width: 100%;
        margin-top: 1;
        text-align: center;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="welcome-box"):
            yield Label(WELCOME_ART, id="art-label")
            yield Label("HOS-LS 安全扫描助手 v1.x", id="title-label")
            yield Label("AI-powered Security Analysis", id="subtitle-label")
            yield Label("─" * 40, id="divider")
            yield Label(WELCOME_FEATURES, id="features-label")
            yield Button("开始使用 (Enter)", id="welcome-btn", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#welcome-btn", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "welcome-btn":
            self.dismiss()

    def on_key(self, event) -> None:
        if event.key == "enter":
            self.dismiss()


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

@dataclass
class ChatMessage:
    """聊天消息"""
    role: str
    content: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class Session:
    """会话"""
    id: str
    name: str
    messages: List[ChatMessage] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)


class SessionChanged(Event):
    """会话切换事件"""

    def __init__(self, session_id: Optional[str]):
        super().__init__()
        self.session_id = session_id


# ---------------------------------------------------------------------------
# Widget: 消息显示区域
# ---------------------------------------------------------------------------

class MessageLog(RichLog):
    """支持 Markdown 和代码高亮的消息日志"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.markup = True

    def add_user_message(self, content: str) -> None:
        now = time.strftime("%H:%M:%S")
        header = Text(f"\n  [USER] {now} ", style="bold white on #0f3460")
        self.write(header)
        self.write(Text(f"  {content}", style="bold cyan"))
        self.write("\n")

    def add_assistant_message(self, content: str) -> None:
        now = time.strftime("%H:%M:%S")
        header = Text(f"\n  [AI] {now} ", style="bold white on #1a3a2a")
        self.write(header)
        md = Markdown(self._render_content(content))
        self.write(md)
        self.write("\n")

    def add_system_message(self, content: str) -> None:
        self.write(Text(f"\n  {content}", style="dim yellow"))
        self.write("\n")

    def add_loading(self) -> None:
        self.write(Text("\n  思考中...", style="italic yellow"))

    @staticmethod
    def _render_content(content: str) -> str:
        if not content:
            return ""
        return content


# ---------------------------------------------------------------------------
# Widget: 会话侧边栏
# ---------------------------------------------------------------------------

class SessionSidebar(Vertical):
    """会话列表侧边栏"""

    DEFAULT_CSS = """
    SessionSidebar {
        width: 28;
        background: $surface;
        dock: left;
    }
    SessionSidebar .sidebar-title {
        text-align: center;
        padding: 1 0;
        background: $primary;
        color: $text;
    }
    SessionSidebar .sidebar-meta {
        padding: 0 1;
        color: $text-muted;
    }
    SessionSidebar .sidebar-actions {
        dock: bottom;
        padding: 1 0;
        border-top: solid $primary;
    }
    SessionSidebar .sidebar-actions Button {
        width: 100%;
        margin: 0 1;
    }
    SessionSidebar #session-tree {
        height: 1fr;
    }
    SessionSidebar .pentest-btn {
        width: 100%;
        margin: 0 1;
        color: $text;
        background: $primary;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.sessions: List[Session] = []
        self.active_session_id: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield Label("  会话列表", classes="sidebar-title")
        yield Label("", id="session-meta", classes="sidebar-meta")
        yield Tree("sessions", id="session-tree")
        with Vertical(classes="sidebar-actions"):
            yield Button("＋ 新会话", id="new-session", variant="primary")
            yield Button("🎨 切换主题", id="theme-btn")
            yield Button("🔓 渗透测试", id="pentest-btn", classes="pentest-btn")
            yield Button("❓ 帮助", id="help-btn")

    def on_mount(self) -> None:
        self.add_new_session()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "new-session":
            self.add_new_session()
            self.post_message(SessionChanged(self.active_session_id))
        elif event.button.id == "theme-btn":
            app = self.app
            if hasattr(app, "action_switch_theme"):
                app.action_switch_theme("light")
        elif event.button.id == "help-btn":
            app = self.app
            if hasattr(app, "_handle_user_input"):
                app._handle_user_input("/help")
        elif event.button.id == "pentest-btn":
            app = self.app
            if hasattr(app, "_handle_user_input"):
                app._handle_user_input("/pentest")

    def add_new_session(self) -> Session:
        session = Session(
            id=str(uuid.uuid4())[:8],
            name=f"会话 {len(self.sessions) + 1}"
        )
        self.sessions.append(session)
        self.active_session_id = session.id
        self._refresh_tree()
        return session

    def switch_session(self, session_id: str) -> None:
        self.active_session_id = session_id
        self._refresh_tree()
        self.post_message(SessionChanged(session_id))

    def delete_session(self, session_id: str) -> None:
        self.sessions = [s for s in self.sessions if s.id != session_id]
        if self.active_session_id == session_id:
            if self.sessions:
                self.active_session_id = self.sessions[-1].id
            else:
                self.add_new_session()
                return
        self._refresh_tree()
        self.post_message(SessionChanged(self.active_session_id))

    def get_active_session(self) -> Optional[Session]:
        for s in self.sessions:
            if s.id == self.active_session_id:
                return s
        return None

    def _refresh_tree(self) -> None:
        tree = self.query_one("#session-tree", Tree)
        tree.clear()
        for s in self.sessions:
            icon = "●" if s.id == self.active_session_id else "○"
            tree.add(f" {icon} {s.name}", data=s.id)
        tree.expand_all()
        self._update_meta()

    def _update_meta(self) -> None:
        meta_label = self.query_one("#session-meta", Label)
        session = self.get_active_session()
        if session:
            created = time.strftime("%m-%d %H:%M", time.localtime(session.created_at))
            msg_count = len(session.messages)
            meta_label.update(f" 创建: {created}\n 消息: {msg_count} 条")
        else:
            meta_label.update("")

    def update_meta(self) -> None:
        """公开方法，供外部调用更新元信息"""
        self._update_meta()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        session_id = event.node.data
        if session_id:
            self.switch_session(session_id)


# ---------------------------------------------------------------------------
# Widget: 状态栏
# ---------------------------------------------------------------------------

class StatusBar(Static):
    """底部状态栏，显示模型信息"""

    DEFAULT_CSS = """
    StatusBar {
        background: $surface;
        color: $text-muted;
        padding: 0 2;
        height: 1;
    }
    """

    def __init__(self, config: Config, **kwargs):
        super().__init__(**kwargs)
        self.config = config

    def on_mount(self) -> None:
        self.update_status()

    def update_status(self) -> None:
        provider = self.config.ai.provider
        model = self.config.ai.model
        self.update(f" 模型: {provider}/{model}  │  HOS-LS 安全扫描助手  │  /help 查看帮助")


# ---------------------------------------------------------------------------
# 主 App
# ---------------------------------------------------------------------------

class HOSLSApp(App):
    """HOS-LS 安全扫描助手 TUI 应用"""

    TITLE = "HOS-LS 安全扫描助手"
    SUB_TITLE = "AI-powered Security Analysis"

    CSS = """
    Screen {
        layout: vertical;
    }
    #main-container {
        flex: 1;
    }
    #chat-area {
        flex: 1;
        border: solid $primary;
        margin: 0 1;
    }
    #input-area {
        height: 3;
        padding: 1 2;
        border-top: solid $primary;
    }
    #chat-input {
        width: 1fr;
    }
    #send-btn {
        width: 8;
        margin-left: 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+n", "new_session", "新会话", show=True),
        Binding("ctrl+s", "send_message", "发送", show=True),
        Binding("escape", "clear_input", "清空输入", show=False),
        Binding("ctrl+l", "clear_chat", "清屏", show=False),
        Binding("ctrl+d", "delete_session", "删除会话", show=False),
        Binding("ctrl+t", "switch_theme", "切换主题", show=True),
    ]

    def __init__(self, config: Config, **kwargs):
        super().__init__(**kwargs)
        self.config = config
        self._agent = None
        self._agent_ready = False
        self.current_theme = "dark"
        self._welcome_shown = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="main-container"):
            yield SessionSidebar(id="sidebar")
            with Vertical():
                yield MessageLog(id="chat-area")
                with Horizontal(id="input-area"):
                    yield Input(
                        placeholder="输入问题或命令... (Ctrl+S 发送)",
                        id="chat-input"
                    )
                    yield Button("发送", id="send-btn", variant="primary")
            yield StatusBar(self.config, id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self._apply_theme(self.current_theme)
        msg_log = self.query_one("#chat-area", MessageLog)
        msg_log.add_system_message("欢迎使用 HOS-LS 安全扫描助手！")
        msg_log.add_system_message("正在初始化 AI 模块...")
        if not self._welcome_shown:
            self._welcome_shown = True
            self.push_screen(WelcomeScreen())
        self._init_agent()

    # -------------------------------------------------------------------
    # 主题系统
    # -------------------------------------------------------------------

    def _apply_theme(self, theme_name: str) -> None:
        """应用指定主题的 CSS 变量"""
        theme = THEMES.get(theme_name, THEMES["dark"])
        self.styles.background = theme["bg"]

    def action_switch_theme(self, theme_name: str = "") -> None:
        """切换主题。如果 theme_name 为空，则循环切换到下一个主题"""
        theme_names = list(THEMES.keys())
        if theme_name and theme_name.lower() in THEMES:
            new_theme = theme_name.lower()
        else:
            idx = theme_names.index(self.current_theme)
            new_theme = theme_names[(idx + 1) % len(theme_names)]
        self.current_theme = new_theme
        self._apply_theme(new_theme)
        self._refresh_screens()

    def _refresh_screens(self) -> None:
        """刷新所有屏幕以应用新主题"""
        try:
            msg_log = self.query_one("#chat-area", MessageLog)
            msg_log.refresh()
        except Exception:
            pass

    # -------------------------------------------------------------------
    # AI Agent 初始化（后台线程 worker）
    # -------------------------------------------------------------------

    @work(exclusive=True, thread=True, description="初始化AI Agent")
    def _init_agent(self) -> None:
        """在后台线程初始化 ConversationalSecurityAgent"""
        worker = get_current_worker()
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            agent = loop.run_until_complete(self._async_init_agent())
            loop.close()

            if not worker.is_cancelled:
                self.call_from_thread(self._on_agent_ready, agent)
        except Exception as e:
            if not worker.is_cancelled:
                self.call_from_thread(self._on_agent_init_error, str(e))

    async def _async_init_agent(self):
        from src.core.chat.conversational_agent import ConversationalSecurityAgent

        agent = ConversationalSecurityAgent(self.config)
        try:
            if self.config.ai.enabled and self.config.ai.api_key:
                await agent._get_intent_classifier()
                await agent._get_entity_extractor()
        except Exception:
            pass
        return agent

    def _on_agent_ready(self, agent) -> None:
        self._agent = agent
        self._agent_ready = True
        msg_log = self.query_one("#chat-area", MessageLog)
        msg_log.add_system_message(
            "AI 模块就绪。输入问题开始对话，或使用 /scan 扫描代码。"
        )
        self.query_one("#chat-input", Input).focus()

    def _on_agent_init_error(self, error: str) -> None:
        msg_log = self.query_one("#chat-area", MessageLog)
        msg_log.add_system_message(f"AI 模块初始化失败: {error}")
        msg_log.add_system_message("已启用基础模式（无 AI 增强）。")
        from src.core.chat.conversational_agent import ConversationalSecurityAgent
        self._agent = ConversationalSecurityAgent(self.config)
        self._agent.set_ai_enabled(False)
        self._agent_ready = True
        self.query_one("#chat-input", Input).focus()

    # -------------------------------------------------------------------
    # 消息发送
    # -------------------------------------------------------------------

    def action_send_message(self) -> None:
        input_widget = self.query_one("#chat-input", Input)
        text = input_widget.value.strip()
        if not text:
            return
        input_widget.value = ""
        self._handle_user_input(text)

    def _handle_user_input(self, text: str) -> None:
        session = self._get_active_session()
        if not session:
            return

        # Handle /pentest command
        if text.lower().startswith("/pentest"):
            parts = text.split()
            target = "."
            mode = "full"
            for p in parts[1:]:
                if p.startswith("--mode="):
                    mode = p.split("=", 1)[1]
                elif p.startswith("--mode"):
                    mode = parts[parts.index(p) + 1] if parts.index(p) + 1 < len(parts) else "full"
                elif not p.startswith("-"):
                    target = p
            asyncio.create_task(self._run_pentest_in_tui(target, mode))
            return

        # Handle /theme command
        if text.lower().startswith("/theme"):
            parts = text.split(None, 1)
            if len(parts) < 2:
                theme_list = ", ".join(THEMES.keys())
                msg_log = self.query_one("#chat-area", MessageLog)
                msg_log.add_system_message(f"可用主题: {theme_list}")
                msg_log.add_system_message(f"当前主题: {self.current_theme}")
                msg_log.add_system_message(f"用法: /theme <名称>")
            else:
                theme_name = parts[1].strip().lower()
                if theme_name in THEMES:
                    self.action_switch_theme(theme_name)
                    msg_log = self.query_one("#chat-area", MessageLog)
                    msg_log.add_system_message(f"已切换至主题: {theme_name}")
                else:
                    msg_log = self.query_one("#chat-area", MessageLog)
                    msg_log.add_system_message(f"未知主题: {theme_name}。可用: {', '.join(THEMES.keys())}")
            return

        msg_log = self.query_one("#chat-area", MessageLog)
        msg_log.add_user_message(text)
        session.messages.append(ChatMessage(role="user", content=text))

        if text.lower() in ("/exit", "/quit"):
            self.exit()
            return

        msg_log.add_loading()
        self._process_message(text, session)

    @work(exclusive=True, thread=True, group="chat", description="处理消息")
    def _process_message(self, text: str, session: Session) -> None:
        """在后台线程处理消息并获取 AI 响应"""
        worker = get_current_worker()
        try:
            if not self._agent:
                if not worker.is_cancelled:
                    self.call_from_thread(
                        self._on_response_error, "Agent 未初始化，请稍候...", session
                    )
                return

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            response = loop.run_until_complete(
                self._agent.process_message(text)
            )
            loop.close()

            if not worker.is_cancelled:
                self.call_from_thread(
                    self._on_response_ready, response, session
                )
        except Exception as e:
            if not worker.is_cancelled:
                self.call_from_thread(
                    self._on_response_error, str(e), session
                )

    def _on_response_ready(self, response: str, session: Session) -> None:
        msg_log = self.query_one("#chat-area", MessageLog)
        msg_log.add_assistant_message(response)
        session.messages.append(
            ChatMessage(role="assistant", content=response)
        )
        msg_log.scroll_end()

    def _on_response_error(self, error: str, session: Session) -> None:
        msg_log = self.query_one("#chat-area", MessageLog)
        msg_log.add_system_message(f"处理失败: {error}")
        msg_log.scroll_end()

    # -------------------------------------------------------------------
    # AI 渗透测试
    # -------------------------------------------------------------------

    # 阶段映射：根据 iteration 和 mode 推断当前阶段
    _PENTEST_PHASES = [
        ("recon", "🔍 Recon 侦察", "#00b4d8"),
        ("scan", "🔬 Scan 扫描", "#fca311"),
        ("exploit", "💥 Exploit 利用", "#e63946"),
        ("report", "📝 Report 报告", "#06d6a0"),
    ]

    _STEP_NAMES = {
        "ai_reason": "AI 决策",
        "tool_exec": "工具执行",
        "ai_analyze": "AI 分析",
        "ai_decide": "AI 评估",
    }

    _SEVERITY_COLORS = {
        "critical": "red",
        "high": "orange_red1",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
    }

    async def _run_pentest_in_tui(self, target: str, mode: str) -> str:
        """在 TUI 中流式执行渗透测试，实时输出每个发现"""
        try:
            from src.cli.commands.pentest import _run_pentest
            from asyncio import Queue

            msg_log = self.query_one("#chat-area", MessageLog)
            msg_log.add_system_message(
                f"[bold cyan]🔓 渗透测试启动: {target} (模式: {mode})[/bold cyan]"
            )

            start_time = time.time()
            progress_events: Queue = Queue()
            all_findings: list = []
            cancelled = False

            # 进度回调：将事件推入队列
            def progress_callback(iteration, max_iter, step, findings):
                self.call_from_thread(
                    lambda: asyncio.ensure_future(
                        progress_events.put(("progress", iteration, max_iter, step, findings))
                    )
                )

            # 后台执行渗透测试
            async def run_pentest_bg():
                nonlocal cancelled
                try:
                    result = await _run_pentest(
                        config=self.config,
                        target=target,
                        mode=mode,
                        tool_list=[],
                        deep=False,
                        sandbox=False,
                        authorized_targets=None,
                        session_id=None,
                        progress_callback=progress_callback,
                    )
                    return result
                except asyncio.CancelledError:
                    cancelled = True
                    raise
                finally:
                    # 发送完成信号
                    await progress_events.put(("done",))

            task = asyncio.create_task(run_pentest_bg())

            # 阶段追踪
            last_phase_idx = -1
            prev_finding_count = 0
            current_progress_bar = "[░░░░░░░░░░░░░░░░░░░░] 0%"

            # 实时消费进度事件
            while True:
                try:
                    event = await asyncio.wait_for(progress_events.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    # 检查任务是否已完成
                    if task.done():
                        break
                    continue

                if event[0] == "done":
                    break

                if event[0] == "progress":
                    _, iteration, max_iter, step, findings = event
                    step_label = self._STEP_NAMES.get(step, step)

                    # 计算进度
                    progress_val = min(100, int((iteration + 0.5) / max_iter * 100))
                    bar_len = 22
                    filled = int(bar_len * progress_val / 100)
                    current_progress_bar = (
                        f"[{'█' * filled}{'░' * (bar_len - filled)}] {progress_val}%"
                    )

                    # 推断当前阶段
                    phase_idx = self._guess_phase(iteration, max_iter, mode)
                    phase_name = self._PENTEST_PHASES[phase_idx][1]

                    # 阶段切换通知
                    if phase_idx != last_phase_idx:
                        last_phase_idx = phase_idx
                        if phase_idx > 0:
                            # 上一阶段摘要
                            prev_phase = self._PENTEST_PHASES[phase_idx - 1]
                            phase_findings = len(all_findings)
                            msg_log.add_system_message(
                                f"[bold {prev_phase[2]}]✓ {prev_phase[1]} 完成 — "
                                f"累计发现 {phase_findings} 项[/bold {prev_phase[2]}]"
                            )
                        msg_log.add_system_message(
                            f"[bold {self._PENTEST_PHASES[phase_idx][2]}]"
                            f"▶ {phase_name} 进行中...[/bold {self._PENTEST_PHASES[phase_idx][2]}]"
                        )

                    # 新发现实时输出
                    new_findings = findings[prev_finding_count:]
                    for f in new_findings:
                        sev = f.get("severity", "info").lower()
                        color = self._SEVERITY_COLORS.get(sev, "dim")
                        desc = (f.get("description", "") or f.get("analysis", "") or f.get("summary", "") or "")[:120]
                        finding_type = f.get("type", "unknown")
                        finding_target = f.get("target", "")[:40]

                        msg_log.add_system_message(
                            f"[bold {color}]  ⚡ [{sev.upper()}] {finding_type}[/bold {color}]"
                        )
                        if desc:
                            msg_log.add_system_message(f"     {desc}")
                        if finding_target:
                            msg_log.add_system_message(f"     目标: {finding_target}")

                        # 高严重级别弹窗通知
                        if sev in ("critical", "high"):
                            self.notify(
                                f"🔴 {sev.upper()} 发现: {desc[:60]}",
                                severity="error" if sev == "critical" else "warning",
                                timeout=5,
                            )

                        all_findings.append(f)
                        prev_finding_count = len(findings)

                    # 更新状态行（进度）
                    session = self._get_active_session()
                    if session:
                        session.messages.append(
                            ChatMessage(
                                role="system",
                                content=f"[{step_label}] {current_progress_bar} | "
                                f"阶段: {phase_name} | 发现: {len(findings)}",
                            )
                        )

                    msg_log.scroll_end()

            # 等待任务完成
            try:
                result = await task
            except asyncio.CancelledError:
                cancelled = True
                result = {}

            elapsed = time.time() - start_time

            # 最终阶段摘要
            if not cancelled and last_phase_idx >= 0:
                last_phase = self._PENTEST_PHASES[last_phase_idx]
                msg_log.add_system_message(
                    f"[bold {last_phase[2]}]✓ {last_phase[1]} 完成[/bold {last_phase[2]}]"
                )

            # 最终汇总
            total = len(all_findings)
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in all_findings:
                sev = f.get("severity", "info").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

            risk_level = "low"
            if severity_counts["critical"] > 0:
                risk_level = "critical"
            elif severity_counts["high"] > 0:
                risk_level = "high"
            elif severity_counts["medium"] > 0:
                risk_level = "medium"

            risk_colors = {"critical": "red", "high": "orange_red1", "medium": "yellow", "low": "green"}
            risk_color = risk_colors.get(risk_level, "white")

            summary_text = (
                f"[bold]{'━' * 40}[/bold]\n"
                f"[bold]渗透测试完成[/bold] ({elapsed:.1f}s) — "
                f"风险级别: [{risk_color}]{risk_level.upper()}[/{risk_color}]\n"
                f"总计: [yellow]{total}[/yellow] | "
                f"[red]Critical: {severity_counts['critical']}[/red] | "
                f"[orange_red1]High: {severity_counts['high']}[/orange_red1] | "
                f"[yellow]Medium: {severity_counts['medium']}[/yellow] | "
                f"[green]Low: {severity_counts['low']}[/green] | "
                f"[dim]Info: {severity_counts['info']}[/dim]"
            )
            msg_log.add_system_message(summary_text)

            # 展示 top 发现
            if all_findings:
                msg_log.add_system_message("[bold]关键发现详情:[/bold]")
                for f in all_findings[:10]:
                    sev = f.get("severity", "info").lower()
                    color = self._SEVERITY_COLORS.get(sev, "dim")
                    desc = (f.get("description", "") or f.get("analysis", "") or f.get("summary", "") or "")[:100]
                    msg_log.add_system_message(f"[{color}][{sev.upper()}] {desc}")

                if len(all_findings) > 10:
                    msg_log.add_system_message(
                        f"[dim]... 还有 {len(all_findings) - 10} 条发现未显示[/dim]"
                    )

            msg_log.scroll_end()
            self.notify(f"渗透测试完成，共发现 {total} 个问题", severity="information")

            return f"渗透测试完成，发现 {total} 个问题。"

        except asyncio.CancelledError:
            msg_log = self.query_one("#chat-area", MessageLog)
            msg_log.add_system_message("[bold yellow]渗透测试已取消[/bold yellow]")
            return "渗透测试已取消"
        except Exception as e:
            try:
                msg_log = self.query_one("#chat-area", MessageLog)
                msg_log.add_system_message(f"[bold red]渗透测试失败: {e}[/bold red]")
            except Exception:
                pass
            self.notify(f"渗透测试失败: {e}", severity="error")
            return f"渗透测试失败: {e}"

    def _guess_phase(self, iteration: int, max_iter: int, mode: str) -> int:
        """根据当前迭代进度推测渗透测试阶段"""
        if max_iter == 0:
            return 0

        progress = iteration / max_iter

        # 根据 mode 调整阶段边界
        if mode == "recon":
            return 0  # 始终在 recon
        elif mode == "scan":
            return 0 if progress < 0.3 else 1
        elif mode == "exploit":
            return 1 if progress < 0.3 else 2 if progress < 0.7 else 3
        else:  # full
            if progress < 0.25:
                return 0  # recon
            elif progress < 0.5:
                return 1  # scan
            elif progress < 0.75:
                return 2  # exploit
            else:
                return 3  # report

    # -------------------------------------------------------------------
    # 会话管理
    # -------------------------------------------------------------------

    def _get_active_session(self) -> Optional[Session]:
        sidebar = self.query_one("#sidebar", SessionSidebar)
        return sidebar.get_active_session()

    def action_new_session(self) -> None:
        sidebar = self.query_one("#sidebar", SessionSidebar)
        sidebar.add_new_session()
        self._clear_chat_display()
        msg_log = self.query_one("#chat-area", MessageLog)
        msg_log.add_system_message("新会话已创建。")
        self.query_one("#chat-input", Input).focus()

    def action_delete_session(self) -> None:
        sidebar = self.query_one("#sidebar", SessionSidebar)
        active = sidebar.get_active_session()
        if active and len(sidebar.sessions) > 1:
            sidebar.delete_session(active.id)
            self._clear_chat_display()
            msg_log = self.query_one("#chat-area", MessageLog)
            msg_log.add_system_message("会话已删除。")

    def action_clear_input(self) -> None:
        self.query_one("#chat-input", Input).value = ""

    def action_clear_chat(self) -> None:
        self._clear_chat_display()
        session = self._get_active_session()
        if session:
            session.messages.clear()
        msg_log = self.query_one("#chat-area", MessageLog)
        msg_log.add_system_message("对话历史已清除。")

    def _clear_chat_display(self) -> None:
        msg_log = self.query_one("#chat-area", MessageLog)
        msg_log.clear()

    # -------------------------------------------------------------------
    # Session 切换事件
    # -------------------------------------------------------------------

    def on_session_changed(self, event: SessionChanged) -> None:
        """会话切换时更新聊天区域"""
        self._clear_chat_display()
        session = self._get_active_session()
        msg_log = self.query_one("#chat-area", MessageLog)
        if session and session.messages:
            for msg in session.messages:
                if msg.role == "user":
                    msg_log.add_user_message(msg.content)
                else:
                    msg_log.add_assistant_message(msg.content)
        else:
            msg_log.add_system_message("新会话已创建。")
        msg_log.scroll_end()

    # -------------------------------------------------------------------
    # 按钮/输入事件
    # -------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "send-btn":
            self.action_send_message()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "chat-input":
            self.action_send_message()


# ---------------------------------------------------------------------------
# 入口函数
# ---------------------------------------------------------------------------

def run_tui(config: Config) -> None:
    """启动 TUI 应用

    Args:
        config: HOS-LS 配置对象
    """
    app = HOSLSApp(config)
    app.run()


if __name__ == "__main__":
    from src.core.config import get_config
    cfg = get_config()
    run_tui(cfg)
