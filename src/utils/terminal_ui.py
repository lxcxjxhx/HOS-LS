from typing import Dict, Any, Optional
import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.progress import SpinnerColumn, TextColumn
from rich.table import Table


class TerminalUI:
    """终端 UI 类
    
    处理交互式终端界面，包括用户输入、思考状态显示和结果展示
    """
    
    def __init__(self):
        """初始化终端 UI"""
        self.console = Console()
    
    def get_input(self, prompt: str) -> str:
        """获取用户输入
        
        Args:
            prompt: 输入提示
            
        Returns:
            用户输入的文本
        """
        try:
            # 使用 questionary 获取用户输入
            import questionary
            user_input = questionary.text(prompt, qmark="").ask()
            return user_input or ""
        except EOFError:
            return "/exit"
        except KeyboardInterrupt:
            return "/exit"
        except Exception:
            # 回退到标准 input
            try:
                user_input = input(prompt)
                return user_input
            except:
                return "/exit"
    
    def show_thinking(self):
        """显示思考状态"""
        self.console.print("[bold cyan][Planner] 正在分析您的请求...[/bold cyan]")
    
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
        elif "error" in result:
            self._show_error(result)
        else:
            self._show_generic_result(result)
    
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
        
        self.console.print(Panel(
            f"[bold]漏洞利用结果[/bold]\n" +
            f"目标: {target}\n" +
            f"生成的 POC 数量: {len(exploits)}",
            border_style="red"
        ))
        
        if exploits:
            self.console.print("[bold red]生成的 POC:[/bold red]")
            for i, exploit in enumerate(exploits, 1):
                self.console.print(f"[cyan]{i}.[/cyan] {exploit[:200]}..." if len(exploit) > 200 else exploit)
    
    def _show_fix_result(self, result: Dict[str, Any]):
        """显示修复建议结果
        
        Args:
            result: 修复建议结果
        """
        target = result.get("target", ".")
        fix_suggestions = result.get("fix_suggestions", [])
        
        self.console.print(Panel(
            f"[bold]修复建议[/bold]\n" +
            f"目标: {target}\n" +
            f"修复建议数量: {len(fix_suggestions)}",
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
        self.console.print(Panel(str(result), border_style="gray"))
    
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