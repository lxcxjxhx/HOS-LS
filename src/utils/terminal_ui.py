from typing import Dict, Any, Optional
import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.progress import SpinnerColumn, TextColumn
from rich.table import Table
from rich.markdown import Markdown


class TerminalUI:
    """终端 UI 类
    
    处理交互式终端界面，包括用户输入、思考状态显示和结果展示
    """
    
    # 标准颜色映射
    COLOR_MAP = {
        "primary": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "red",
        "info": "blue",
        "debug": "dim",
        "bold": "bold",
        "italic": "italic",
        "underline": "underline"
    }
    
    def __init__(self):
        """初始化终端 UI"""
        # 优化Rich控制台配置，确保颜色支持
        from rich.console import ConsoleOptions, RenderableType
        from rich.theme import Theme
        
        # 自定义主题，确保颜色一致性
        custom_theme = Theme({
            "prompt": "bold green",
            "info": "cyan",
            "success": "green",
            "warning": "yellow",
            "error": "bold red",
            "debug": "dim",
            "title": "bold cyan",
            "subtitle": "bold blue"
        })
        
        # 确保启用颜色支持，即使在不支持的终端中也能优雅降级
        self.console = Console(
            force_terminal=None, 
            color_system="auto",
            theme=custom_theme,
            highlight=True,
            emoji=True
        )
        self.history = []
        self.history_index = -1
        self.color_supported = self.is_color_supported()
        self.color_level = self.get_color_level()
        
    def is_color_supported(self) -> bool:
        """检测终端是否支持颜色"""
        return self.console.color_system is not None
    
    def get_color_level(self) -> int:
        """获取终端支持的颜色级别"""
        if not self.is_color_supported():
            return 0
        try:
            return self.console.color_system.level
        except:
            return 0
    
    def get_supported_colors(self) -> int:
        """获取终端支持的颜色数量"""
        color_level = self.get_color_level()
        if color_level == 0:
            return 2  # 黑白
        elif color_level == 1:
            return 16  # ANSI 16色
        elif color_level == 2:
            return 256  # ANSI 256色
        else:
            return 16777216  # True Color
    
    def get_color(self, color_name: str) -> str:
        """获取颜色代码，支持自动 fallback
        
        Args:
            color_name: 颜色名称
            
        Returns:
            颜色代码或空字符串（如果不支持颜色）
        """
        if not self.color_supported:
            return ""
        return self.COLOR_MAP.get(color_name, "")
    
    def print_with_color(self, text: str, style: str = ""):
        """带颜色打印文本
        
        Args:
            text: 要打印的文本
            style: Rich样式字符串或颜色名称
        """
        # 检查是否是颜色名称
        if style in self.COLOR_MAP:
            color_code = self.get_color(style)
            if color_code:
                self.console.print(f"[{color_code}]{text}[/{color_code}]")
            else:
                self.console.print(text)
        elif style:
            # 使用自定义样式
            if self.color_supported:
                self.console.print(f"[{style}]{text}[/{style}]")
            else:
                self.console.print(text)
        else:
            self.console.print(text)
    
    def get_input(self, prompt: str) -> str:
        """获取用户输入
        
        Args:
            prompt: 输入提示
            
        Returns:
            用户输入的文本
        """
        try:
            # 使用 prompt_toolkit 获取用户输入，支持历史记录和自动补全
            from prompt_toolkit import prompt as pt_prompt
            from prompt_toolkit.history import InMemoryHistory
            from prompt_toolkit.completion import WordCompleter
            
            # 常见命令补全
            commands = [
                # 扫描命令
                "扫描当前目录",
                "使用纯 AI 模式扫描",
                "扫描测试模式",
                # 分析命令
                "分析当前项目",
                "评估代码安全性",
                # 利用命令
                "生成漏洞的 POC",
                "创建攻击脚本",
                # 修复命令
                "提供修复建议",
                "生成修复补丁",
                # 特殊命令
                "/help",
                "/exit",
                "/clear",
                "/pause",
                "/step",
                "/explain"
            ]
            
            completer = WordCompleter(commands, ignore_case=True)
            history = InMemoryHistory()
            
            # 添加历史记录
            for item in self.history:
                history.append_string(item)
            
            user_input = pt_prompt(
                prompt,
                history=history,
                completer=completer,
                enable_history_search=True,
                complete_while_typing=True
            )
            
            # 添加到历史记录
            if user_input.strip():
                self.history.append(user_input)
                if len(self.history) > 100:  # 限制历史记录长度
                    self.history.pop(0)
            
            return user_input or ""
        except ImportError:
            # 回退到 questionary
            try:
                import questionary
                user_input = questionary.text(prompt, qmark="").ask()
                if user_input and user_input.strip():
                    self.history.append(user_input)
                return user_input or ""
            except EOFError:
                return "/exit"
            except KeyboardInterrupt:
                return "/exit"
            except Exception:
                # 回退到标准 input
                try:
                    user_input = input(prompt)
                    if user_input and user_input.strip():
                        self.history.append(user_input)
                    return user_input
                except:
                    return "/exit"
    
    def show_thinking(self):
        """显示思考状态"""
        from rich.live import Live
        from rich.text import Text
        
        # 检查颜色支持
        if self.is_color_supported():
            with Live(Text("[bold cyan][Planner] 正在分析您的请求...[/bold cyan]"), refresh_per_second=10) as live:
                # 模拟思考过程
                import time
                steps = [
                    "分析用户意图...",
                    "构建分析计划...",
                    "准备执行步骤...",
                    "调用相应的安全 Agent..."
                ]
                
                for step in steps:
                    time.sleep(0.5)
                    live.update(Text(f"[bold cyan][Planner] {step}[/bold cyan]"))
                
                time.sleep(0.5)
                live.update(Text("[bold cyan][Planner] 分析完成，开始执行...[/bold cyan]"))
        else:
            # 无颜色模式
            import time
            print("[Planner] 正在分析您的请求...")
            steps = [
                "分析用户意图...",
                "构建分析计划...",
                "准备执行步骤...",
                "调用相应的安全 Agent..."
            ]
            
            for step in steps:
                time.sleep(0.5)
                print(f"[Planner] {step}")
            
            time.sleep(0.5)
            print("[Planner] 分析完成，开始执行...")
    
    def show_result(self, result: Dict[str, Any]):
        """显示处理结果
        
        Args:
            result: 处理结果
        """
        result_type = result.get("type", "unknown")
        
        if result_type == "scan_result":
            self._show_scan_result(result)
        elif result_type == "analysis_result":
            self._show_analysis_result(result)
        elif result_type == "exploit_result":
            self._show_exploit_result(result)
        elif result_type == "fix_result":
            self._show_fix_result(result)
        elif result_type == "info_result":
            self._show_info_result(result)
        elif result_type == "general_result":
            self._show_general_result(result)
        elif result_type == "grep_result":
            self._show_grep_result(result)
        elif result_type == "file_content":
            self._show_file_content(result)
        elif result_type == "directory_listing":
            self._show_directory_listing(result)
        elif result_type == "ast_search_result":
            self._show_ast_search_result(result)
        elif result_type == "file_info":
            self._show_file_info(result)
        elif result_type == "project_summary":
            self._show_project_summary(result)
        elif result_type == "git_result":
            self._show_git_result(result)
        elif result_type == "plan_execution_result":
            self._show_plan_execution_result(result)
        elif "error" in result:
            self._show_error(result)
        else:
            self._show_generic_result(result)
    
    def _show_project_summary(self, result: Dict[str, Any]):
        """显示项目摘要
        
        Args:
            result: 项目摘要结果
        """
        root = result.get("root", "")
        total_files = result.get("total_files", 0)
        languages = result.get("languages", {})
        key_files = result.get("key_files", [])
        
        self.console.print(Panel(
            f"[bold]项目摘要[/bold]\n" +
            f"根目录: {root}\n" +
            f"文件总数: {total_files}",
            border_style="magenta"
        ))
        
        # 显示语言统计
        if languages:
            self.console.print("[bold magenta]语言统计:[/bold magenta]")
            table = Table()
            table.add_column("语言", style="cyan")
            table.add_column("文件数", style="green")
            
            for lang, count in sorted(languages.items(), key=lambda x: x[1], reverse=True):
                table.add_row(lang, str(count))
            
            self.console.print(table)
        
        # 显示关键文件
        if key_files:
            self.console.print("[bold magenta]关键文件:[/bold magenta]")
            table = Table()
            table.add_column("类别", style="cyan")
            table.add_column("路径", style="green")
            table.add_column("类型", style="yellow")
            
            for file_info in key_files[:10]:  # 限制显示数量
                category = file_info.get("category", "")
                path = file_info.get("path", "")
                file_type = file_info.get("type", "")
                
                table.add_row(category, path, file_type)
            
            self.console.print(table)
            
            if len(key_files) > 10:
                self.console.print(f"[dim]... 还有 {len(key_files) - 10} 个关键文件[/dim]")
    
    def _show_grep_result(self, result: Dict[str, Any]):
        """显示代码搜索结果
        
        Args:
            result: 搜索结果
        """
        keyword = result.get("keyword", "")
        matches = result.get("matches", [])
        total = result.get("total", 0)
        
        self.console.print(Panel(
            f"[bold]代码搜索结果[/bold]\n" +
            f"关键词: {keyword}\n" +
            f"找到匹配: {total}",
            border_style="cyan"
        ))
        
        if matches:
            self.console.print("[bold cyan]匹配结果:[/bold cyan]")
            for i, match in enumerate(matches[:10], 1):
                self.console.print(f"[cyan]{i}.[/cyan] {match}")
            
            if len(matches) > 10:
                self.console.print(f"[dim]... 还有 {len(matches) - 10} 个匹配[/dim]")
    
    def _show_file_content(self, result: Dict[str, Any]):
        """显示文件内容
        
        Args:
            result: 文件内容结果
        """
        file_path = result.get("file_path", "")
        content = result.get("content", "")
        lines = result.get("lines", 0)
        
        self.console.print(Panel(
            f"[bold]文件内容[/bold]\n" +
            f"文件: {file_path}\n" +
            f"行数: {lines}",
            border_style="green"
        ))
        
        # 显示文件内容，支持语法高亮
        if content:
            # 尝试根据文件扩展名判断语言
            import os
            ext = os.path.splitext(file_path)[1].lower()
            language_map = {
                '.py': 'python',
                '.js': 'javascript',
                '.ts': 'typescript',
                '.java': 'java',
                '.c': 'c',
                '.cpp': 'cpp',
                '.h': 'c',
                '.html': 'html',
                '.css': 'css',
                '.json': 'json',
                '.yaml': 'yaml',
                '.yml': 'yaml'
            }
            language = language_map.get(ext, 'text')
            self.show_code(content, language)
    
    def _show_directory_listing(self, result: Dict[str, Any]):
        """显示目录列表
        
        Args:
            result: 目录列表结果
        """
        path = result.get("path", "")
        items = result.get("items", [])
        
        self.console.print(Panel(
            f"[bold]目录内容[/bold]\n" +
            f"路径: {path}",
            border_style="blue"
        ))
        
        if items:
            table = Table()
            table.add_column("类型", style="cyan")
            table.add_column("名称", style="green")
            table.add_column("大小", style="yellow")
            
            for item in items:
                item_type = item.get("type", "file")
                name = item.get("name", "")
                size = item.get("size", 0)
                
                type_icon = "📁" if item_type == "directory" else "📄"
                size_str = "-" if item_type == "directory" else f"{size} bytes"
                
                table.add_row(type_icon, name, size_str)
            
            self.console.print(table)
    
    def _show_ast_search_result(self, result: Dict[str, Any]):
        """显示 AST 搜索结果
        
        Args:
            result: AST 搜索结果
        """
        function_name = result.get("function_name", "")
        matches = result.get("matches", [])
        
        self.console.print(Panel(
            f"[bold]函数搜索结果[/bold]\n" +
            f"函数名: {function_name}\n" +
            f"找到匹配: {len(matches)}",
            border_style="purple"
        ))
        
        if matches:
            for i, match in enumerate(matches, 1):
                file_path = match.get("file_path", "")
                start_line = match.get("start_line", 0)
                end_line = match.get("end_line", 0)
                function_code = match.get("function_code", "")
                
                self.console.print(f"[bold purple]{i}. {file_path}:{start_line}-{end_line}[/bold purple]")
                self.show_code(function_code, "python")
                self.console.print()
    
    def _show_file_info(self, result: Dict[str, Any]):
        """显示文件信息
        
        Args:
            result: 文件信息结果
        """
        file_path = result.get("file_path", "")
        size = result.get("size", 0)
        modified = result.get("modified", 0)
        
        import datetime
        modified_str = datetime.datetime.fromtimestamp(modified).strftime("%Y-%m-%d %H:%M:%S") if modified else "未知"
        
        self.console.print(Panel(
            f"[bold]文件信息[/bold]\n" +
            f"文件: {file_path}\n" +
            f"大小: {size} bytes\n" +
            f"修改时间: {modified_str}",
            border_style="yellow"
        ))
    
    def _show_scan_result(self, result: Dict[str, Any]):
        """显示扫描结果
        
        Args:
            result: 扫描结果
        """
        target = result.get("target", ".")
        pure_ai = result.get("pure_ai", False)
        scan_result = result.get("result", {})
        
        # 显示扫描摘要
        summary = scan_result.get("summary", {})
        total_issues = summary.get("total", 0)
        high_risk = summary.get("high", 0) + summary.get("critical", 0)
        medium_risk = summary.get("medium", 0)
        
        self.console.print(Panel(
            f"[bold]扫描结果[/bold]\n" +
            f"目标: {target}\n" +
            f"模式: {'纯 AI 模式' if pure_ai else '传统模式'}\n" +
            f"发现问题: {total_issues}\n" +
            f"[red]高风险:[/red] {high_risk}\n" +
            f"[yellow]中风险:[/yellow] {medium_risk}",
            border_style="cyan"
        ))
        
        # 显示详细发现
        findings = scan_result.get("findings", [])
        if findings:
            self.console.print("[bold cyan]详细发现:[/bold cyan]")
            table = Table()
            table.add_column("#", style="cyan")
            table.add_column("严重程度", style="green")
            table.add_column("规则", style="yellow")
            table.add_column("描述", style="white")
            
            for i, finding in enumerate(findings[:10], 1):
                severity = finding.get("severity", "medium")
                severity_color = "red" if severity in ["critical", "high"] else "yellow" if severity == "medium" else "blue"
                
                table.add_row(
                    str(i),
                    f"[{severity_color}]{severity}[/{severity_color}]",
                    finding.get("rule_name", "Unknown"),
                    finding.get("message", "No message")[:80] + "..." if len(finding.get("message", "")) > 80 else finding.get("message", "No message")
                )
            
            self.console.print(table)
            
            if len(findings) > 10:
                self.console.print(f"[dim]... 还有 {len(findings) - 10} 个问题[/dim]")
    
    def _show_analysis_result(self, result: Dict[str, Any]):
        """显示分析结果
        
        Args:
            result: 分析结果
        """
        target = result.get("target", ".")
        analysis_result = result.get("result", {})
        
        self.console.print(Panel(
            f"[bold]分析结果[/bold]\n" +
            f"目标: {target}",
            border_style="green"
        ))
        
        # 显示 LangGraph 分析结果
        if "final_report" in analysis_result:
            final_report = analysis_result["final_report"]
            
            self.console.print("[bold green]分析报告:[/bold green]")
            if "analysis" in final_report:
                self.console.print(final_report["analysis"])
            
            if "fix_suggestions" in final_report:
                self.console.print("[bold green]修复建议:[/bold green]")
                self.console.print(final_report["fix_suggestions"])
        else:
            self.console.print("[yellow]未生成分析报告[/yellow]")
    
    def _show_exploit_result(self, result: Dict[str, Any]):
        """显示漏洞利用结果
        
        Args:
            result: 利用结果
        """
        target = result.get("target", ".")
        exploits = result.get("exploits", [])
        verify_poc = result.get("verify_poc", False)
        
        self.console.print(Panel(
            f"[bold]漏洞利用结果[/bold]\n" +
            f"目标: {target}\n" +
            f"生成的 POC 数量: {len(exploits)}\n" +
            f"验证模式: {'启用' if verify_poc else '禁用'}",
            border_style="red"
        ))
        
        if exploits:
            self.console.print("[bold red]生成的 POC:[/bold red]")
            for i, exploit_item in enumerate(exploits, 1):
                if isinstance(exploit_item, dict) and "exploit" in exploit_item:
                    # 包含验证结果的 POC
                    exploit = exploit_item.get("exploit", "")
                    verification = exploit_item.get("verification", {})
                    
                    self.console.print(f"[cyan]{i}. POC 代码:[/cyan]")
                    self.show_code(exploit, "python")
                    
                    # 显示验证结果
                    if verification:
                        status = verification.get("status", "unknown")
                        message = verification.get("message", "")
                        details = verification.get("details", "")
                        
                        status_color = "green" if status == "success" else "red"
                        self.console.print(f"[bold {status_color}]验证结果: {status}[/bold {status_color}]")
                        self.console.print(f"[dim]消息: {message}[/dim]")
                        if details:
                            self.console.print(f"[dim]详情: {details}[/dim]")
                else:
                    # 普通 POC
                    exploit = exploit_item
                    self.console.print(f"[cyan]{i}.[/cyan]")
                    self.show_code(exploit, "python")
                self.console.print()
    
    def _show_fix_result(self, result: Dict[str, Any]):
        """显示修复建议结果
        
        Args:
            result: 修复建议结果
        """
        target = result.get("target", ".")
        fix_suggestions = result.get("fix_suggestions", [])
        patches = result.get("patches", [])
        
        self.console.print(Panel(
            f"[bold]修复建议[/bold]\n" +
            f"目标: {target}\n" +
            f"修复建议数量: {len(fix_suggestions)}\n" +
            f"生成的补丁数量: {len(patches)}",
            border_style="blue"
        ))
        
        if fix_suggestions:
            self.console.print("[bold blue]详细修复建议:[/bold blue]")
            table = Table()
            table.add_column("#", style="cyan")
            table.add_column("严重程度", style="green")
            table.add_column("漏洞", style="yellow")
            table.add_column("修复建议", style="white")
            
            for i, suggestion in enumerate(fix_suggestions, 1):
                severity = suggestion.get("severity", "medium")
                severity_color = "red" if severity in ["critical", "high"] else "yellow" if severity == "medium" else "blue"
                
                table.add_row(
                    str(i),
                    f"[{severity_color}]{severity}[/{severity_color}]",
                    suggestion.get("vulnerability", "Unknown")[:40] + "..." if len(suggestion.get("vulnerability", "")) > 40 else suggestion.get("vulnerability", "Unknown"),
                    suggestion.get("suggestion", "No suggestion")[:60] + "..." if len(suggestion.get("suggestion", "")) > 60 else suggestion.get("suggestion", "No suggestion")
                )
            
            self.console.print(table)
        
        # 显示补丁
        if patches:
            self.console.print("[bold blue]生成的补丁:[/bold blue]")
            for i, patch in enumerate(patches, 1):
                file_path = patch.get("file_path", "")
                description = patch.get("description", "")
                diff = patch.get("diff", "")
                
                self.console.print(f"[bold cyan]{i}. {file_path}[/bold cyan]")
                self.console.print(f"[dim]描述: {description}[/dim]")
                if diff:
                    self.show_diff(diff)
                self.console.print()
    
    def _show_info_result(self, result: Dict[str, Any]):
        """显示信息结果
        
        Args:
            result: 信息结果
        """
        message = result.get("message", "")
        self.console.print(Panel(message, border_style="cyan"))
    
    def _show_general_result(self, result: Dict[str, Any]):
        """显示通用结果
        
        Args:
            result: 通用结果
        """
        query = result.get("query", "")
        general_result = result.get("result", "")
        
        self.console.print(Panel(
            f"[bold]查询结果[/bold]\n" +
            f"查询: {query}\n" +
            f"结果: {general_result}",
            border_style="purple"
        ))
    
    def _show_error(self, result: Dict[str, Any]):
        """显示错误结果
        
        Args:
            result: 错误结果
        """
        error = result.get("error", "未知错误")
        self.console.print(Panel(f"[bold red]错误[/bold red]\n{error}", border_style="red"))
    
    def _show_generic_result(self, result: Dict[str, Any]):
        """显示通用结果
        
        Args:
            result: 通用结果
        """
        self.console.print(Panel(str(result), border_style="dim"))

    def _show_git_result(self, result: Dict[str, Any]):
        """显示 Git 操作结果
        
        Args:
            result: Git 操作结果
        """
        operation = result.get("operation", "unknown")
        status = result.get("status", "unknown")
        message = result.get("message", "")
        output = result.get("output", "")
        diff = result.get("diff", "")
        
        status_color = "green" if status == "success" else "red"
        
        self.console.print(Panel(
            f"[bold]Git 操作结果[/bold]\n" +
            f"操作: {operation}\n" +
            f"状态: [{status_color}]{status}[/{status_color}]\n" +
            f"消息: {message}",
            border_style=status_color
        ))
        
        if output:
            self.console.print("[bold blue]输出:[/bold blue]")
            self.console.print(output)
        
        if diff:
            self.console.print("[bold blue]差异:[/bold blue]")
            self.show_diff(diff)

    def show_code(self, code: str, language: str = "python"):
        """显示带语法高亮的代码
        
        Args:
            code: 代码文本
            language: 编程语言
        """
        from rich.syntax import Syntax
        syntax = Syntax(code, language, theme="monokai", line_numbers=True)
        self.console.print(syntax)
    
    def show_diff(self, diff: str):
        """显示代码差异
        
        Args:
            diff: 差异文本
        """
        from rich.syntax import Syntax
        syntax = Syntax(diff, "diff", theme="monokai")
        self.console.print(syntax)
    
    def show_help(self):
        """显示帮助信息"""
        help_text = """
        [bold cyan]HOS-LS 安全对话模式帮助[/bold cyan]
        
        [bold]可用命令:[/bold]
        - [green]扫描命令[/green]: 例如 '扫描当前目录的安全风险'、'用纯 AI 模式扫描项目'
        - [green]分析命令[/green]: 例如 '分析这个项目的漏洞'、'评估代码安全性'
        - [green]利用命令[/green]: 例如 '生成漏洞的 POC'、'创建攻击脚本'
        - [green]修复命令[/green]: 例如 '提供修复建议'、'生成修复补丁'
        
        [bold]特殊命令:[/bold]
        - [cyan]/help[/cyan]: 显示此帮助信息
        - [cyan]/exit[/cyan]: 退出对话模式
        - [cyan]/clear[/cyan]: 清除屏幕
        - [cyan]/pause[/cyan]: 暂停当前执行
        - [cyan]/step[/cyan]: 单步执行
        - [cyan]/explain[/cyan]: 详细解释当前步骤
        """
        self.console.print(help_text)
    
    def clear_screen(self):
        """清除屏幕"""
        # 跨平台清屏
        if os.name == 'nt':  # Windows
            os.system('cls')
        else:  # Unix/Linux/Mac
            os.system('clear')
    
    def show_loading(self, message: str = "处理中..."):
        """显示加载状态
        
        Args:
            message: 加载消息
        """
        with Live(
            TextColumn("[bold cyan]{task.description}"),
            refresh_per_second=10
        ) as live:
            live.update(Text(f"[bold cyan]{message}[/bold cyan]"))
    
    def show_agent_thinking(self, agent_name: str, message: str):
        """显示 Agent 思考过程
        
        Args:
            agent_name: Agent 名称
            message: 思考消息
        """
        self.console.print(f"[bold cyan][{agent_name}] {message}[/bold cyan]")
    
    def stream_output(self, text: str, speed: float = 0.02):
        """流式输出文本
        
        Args:
            text: 要输出的文本
            speed: 每个字符的延迟时间
        """
        import time
        for char in text:
            print(char, end='', flush=True)
            time.sleep(speed)
        print()
    
    def show_agent_streaming(self, agent_name: str, content: str):
        """显示 Agent 流式思考过程
        
        Args:
            agent_name: Agent 名称
            content: 思考内容
        """
        self.console.print(f"[bold cyan][{agent_name}][/bold cyan] ", end='')
        self.stream_output(content)
    
    def show_progress(self, steps: list):
        """显示进度
        
        Args:
            steps: 进度步骤列表
        """
        with Live(refresh_per_second=4) as live:
            for i, step in enumerate(steps):
                # 创建新表格
                table = Table()
                table.add_column("Step")
                table.add_column("Status")
                
                # 添加已完成的步骤
                for j in range(i):
                    table.add_row(steps[j], "[green]Done")
                
                # 添加当前步骤
                table.add_row(step, "[yellow]Running...")
                
                # 更新显示
                live.update(table)
                import time
                time.sleep(0.5)
            
            # 显示最终完成状态
            final_table = Table()
            final_table.add_column("Step")
            final_table.add_column("Status")
            for step in steps:
                final_table.add_row(step, "[green]Done")
            live.update(final_table)
    
    def show_pipeline_preview(self, nodes):
        """显示Pipeline预览
        
        Args:
            nodes: AgentNode列表
        """
        from rich.table import Table
        
        agent_descriptions = {
            "scan": "代码扫描",
            "reason": "漏洞推理",
            "attack-chain": "攻击链分析",
            "poc": "POC生成",
            "verify": "漏洞验证",
            "fix": "修复建议",
            "report": "报告生成"
        }
        
        table = Table(title="🔧 生成的执行Pipeline", show_header=True)
        table.add_column("#", style="cyan", width=4)
        table.add_column("Agent", style="green", width=15)
        table.add_column("说明", style="yellow", width=20)
        table.add_column("状态", style="blue", width=10)
        
        for i, node in enumerate(nodes, 1):
            desc = agent_descriptions.get(node.type.value, node.type.value)
            params_info = ""
            if hasattr(node, 'params') and node.params:
                params_info = f" ({node.params})"
            
            table.add_row(
                str(i),
                f"[bold]{node.type.value}[/bold]",
                f"{desc}{params_info}",
                "[green]待执行[/green]"
            )
        
        self.console.print(table)
        self.console.print("\n[dim]是否执行？(y/n) 或 输入修改意见[/dim]\n")
    
    def show_ai_suggestion(self, suggestion: str, confidence: float = 1.0):
        """显示AI建议
        
        Args:
            suggestion: 建议内容
            confidence: 置信度 (0.0 - 1.0)
        """
        if confidence > 0.8:
            color = "bold green"
        elif confidence > 0.5:
            color = "bold yellow"
        else:
            color = "bold red"
            
        self.console.print(f"\n[{color}]💡 AI建议:[/{color}] {suggestion}")
        self.console.print(f"[dim]置信度: {confidence:.0%}[/dim]\n")
    
    def show_unified_help(self):
        """显示统一交互模式的增强帮助"""
        help_text = """
[bold cyan]🔒 HOS-LS 智能交互模式帮助[/bold cyan]

[dim]整合了聊天模式和Agent编排语言的统一体验[/dim]

[bold]📌 核心能力:[/bold]
• [green]自然语言命令[/green]: '扫描当前目录'、'全面审计项目'
• [green]Agent Pipeline[/green]: '执行 --scan+reason+poc'
• [green]方案管理[/green]: '生成审计方案'、'修改方案'
• [green]双向转换[/green]: '转换为CLI: 完整审计'

[bold]🎯 快速示例:[/bold]
1. [cyan]'扫描当前项目并生成报告'[/cyan]
   → 自动构建: scan → reason → report
   
2. [cyan]'用纯AI模式分析认证模块'[/cyan]
   → 启用PureAI + 聚焦认证逻辑
   
3. [cyan]'生成完整审计方案'[/cyan]
   → AI生成Plan，可修改后执行

4. [cyan]'解释CLI: --full-audit'[/cyan]
   → 显示: 扫描→分析→攻击链→POC→验证→报告

5. [cyan]'@file:src/main.py'[/cyan]
   → 读取文件内容

6. [cyan]'转换为CLI: 深度审计+POC验证'[/cyan]
   → 输出: hos-ls scan --deep-audit --verify

[bold]⚙️ 特殊命令:[/bold]
• /help      - 显示此帮助
• /exit      - 退出对话
• /clear     - 清除屏幕
• /context   - 查看当前上下文
• /history   - 查看对话历史

[bold]💡 提示:[/bold]
• 支持中英文混合输入
• AI会智能理解您的意图
• 可随时切换到CLI命令格式
"""
        self.console.print(help_text)
    
    def show_context_summary(self, context_data):
        """显示上下文摘要
        
        Args:
            context_data: 上下文数据字典
        """
        from rich.panel import Panel
        
        parts = []
        
        if hasattr(context_data, 'root'):
            parts.append(f"📁 项目根目录: {context_data.root}")
        if hasattr(context_data, 'total_files') and context_data.total_files > 0:
            parts.append(f"📄 文件总数: {context_data.total_files}")
        if hasattr(context_data, 'languages') and context_data.languages:
            top_langs = sorted(context_data.languages.items(), 
                            key=lambda x: x[1], reverse=True)[:3]
            lang_str = ", ".join([f"{l}({c})" for l, c in top_langs])
            parts.append(f"💻 主要语言: {lang_str}")
        if hasattr(context_data, 'key_files') and context_data.key_files:
            parts.append(f"🔑 关键文件数: {len(context_data.key_files)}")
            
        if parts:
            panel = Panel(
                "\n".join(parts),
                title="[bold blue]📊 当前项目上下文[/bold blue]",
                border_style="blue"
            )
            self.console.print(panel)
    
    def show_welcome_banner(self):
        """显示统一交互模式的欢迎横幅"""
        from rich.panel import Panel
        from rich.text import Text

        content = Text()
        content.append("  🔒 HOS-LS 智能交互模式\n", style="bold green")
        content.append("\n")
        content.append("  ✨ 整合聊天模式 + Agent 编排语言\n", style="dim")
        content.append("  🤖 支持自然语言 + CLI命令 + Plan管理\n", style="dim")
        content.append("\n")
        content.append("  快速开始:\n", style="bold")
        content.append("  • 输入自然语言: ", style="white")
        content.append("'扫描当前目录'\n", style="green")
        content.append("  • 使用CLI命令: ", style="white")
        content.append("'--full-audit'\n", style="green")
        content.append("  • 管理执行方案: ", style="white")
        content.append("'生成审计方案'\n", style="green")
        content.append("\n")
        content.append("  输入 '/help' 查看更多命令", style="dim")

        banner = Panel(
            content,
            title="[bold cyan]Welcome[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
            width=70
        )
        self.console.print(banner)
    
    def _show_ai_response(self, result: Dict[str, Any], step_num: int = 1):
        """显示AI智能回答（美化版本）
        
        使用Rich的Markdown渲染能力，将AI生成的Markdown内容
        美化为终端友好的格式。
        
        Args:
            result: AI响应结果字典
            step_num: 步骤编号
        """
        message = result.get("message", "")
        error = result.get("error")
        
        if error and error != "ai_client_not_available":
            self.console.print(Panel(
                f"[red]❌ AI响应生成失败[/red]\n\n[dim]{error}[/dim]",
                border_style="red",
                title=f"⚠️ 步骤 {step_num}: AI错误",
                padding=(1, 2)
            ))
            return
        
        if not message or message.strip() == "":
            self.console.print(Panel(
                "[dim]（AI返回空响应）[/dim]",
                border_style="dim",
                title=f"步骤 {step_num}: AI响应",
                padding=(1, 2)
            ))
            return
        
        try:
            md = Markdown(message)
            
            self.console.print(Panel(
                md,
                border_style="bright_blue",
                title=f"🤖 步骤 {step_num}: AI智能回答",
                subtitle="[dim]Powered by HOS-LS AI Engine[/dim]",
                padding=(1, 2),
                expand=False
            ))
            
        except Exception as e:
            self.console.print(Panel(
                f"[bold cyan]🤖 AI智能回答[/bold cyan]\n\n{message}",
                border_style="cyan",
                title=f"步骤 {step_num}: AI响应",
                padding=(1, 2)
            ))
    
    def _show_plan_execution_result(self, result: Dict[str, Any]):
        """显示计划执行结果
        
        Args:
            result: 计划执行结果
        """
        plan_name = result.get("plan_name", "执行计划")
        steps = result.get("steps", [])
        results = result.get("results", [])
        message = result.get("message", "")
        
        # 显示计划概览
        self.console.print(Panel(
            f"[bold]计划执行结果[/bold]\n" +
            f"计划名称: {plan_name}\n" +
            f"执行步骤: {len(steps)}\n" +
            f"状态: {message}",
            border_style="green",
            title="📋 执行结果概览"
        ))
        
        # 显示执行步骤
        if steps:
            self.console.print("\n[bold green]📝 执行步骤:[/bold green]")
            for i, step in enumerate(steps, 1):
                self.console.print(f"[cyan]{i}.[/cyan] [green]✓[/green] {step}")
        
        # 显示详细结果
        if results:
            self.console.print("\n[bold green]📊 详细执行结果:[/bold green]")
            for i, step_result in enumerate(results, 1):
                step_type = step_result.get("type", "unknown")
                step_message = step_result.get("message", "")
                
                if step_type == "info_result":
                    # 显示信息结果（如漏洞扫描原理讲解）
                    self.console.print(Panel(
                        step_message,
                        border_style="cyan",
                        title=f"步骤 {i}: 信息展示"
                    ))
                elif step_type == "scan_result":
                    # 显示扫描结果
                    target = step_result.get("target", ".")
                    mode = step_result.get("mode", "auto")
                    test_mode = step_result.get("test_mode", False)
                    test_file_count = step_result.get("test_file_count", 1)
                    
                    scan_info = f"目标: {target}\n模式: {mode}\n测试模式: {'是' if test_mode else '否'}\n文件数量: {test_file_count}\n状态: {step_message}"
                    
                    self.console.print(Panel(
                        scan_info,
                        border_style="blue",
                        title=f"步骤 {i}: 扫描结果"
                    ))
                elif step_type == "module_result":
                    # 显示模块执行结果
                    module = step_result.get("module", "unknown")
                    parameters = step_result.get("parameters", {})
                    
                    module_info = f"模块: {module}\n"
                    if parameters:
                        module_info += f"参数: {parameters}\n"
                    module_info += f"状态: {step_message}"
                    
                    self.console.print(Panel(
                        module_info,
                        border_style="purple",
                        title=f"步骤 {i}: 模块执行"
                    ))
                elif step_type == "ai_response":
                    self._show_ai_response(step_result, i)
                elif step_type == "report_result":
                    # 显示报告结果
                    format = step_result.get("format", "html")
                    output = step_result.get("output", "./")
                    
                    report_info = f"格式: {format}\n输出路径: {output}\n状态: {step_message}"
                    
                    self.console.print(Panel(
                        report_info,
                        border_style="green",
                        title=f"步骤 {i}: 报告生成"
                    ))
                else:
                    # 其他类型结果
                    self.console.print(Panel(
                        step_message,
                        border_style="dim",
                        title=f"步骤 {i}: {step_type}"
                    ))
        
        # 显示完成提示
        self.console.print("\n[bold green]🎉 计划执行完成！[/bold green]")
        self.console.print("[dim]您可以查看生成的报告文件以获取详细信息。[/dim]")