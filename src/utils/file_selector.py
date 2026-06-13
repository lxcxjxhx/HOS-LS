"""交互式文件选择器"""

from typing import List, Optional
from pathlib import Path
from rich.console import Console


class InteractiveFileSelector:
    """交互式文件选择器，用于在终端中浏览并选择要扫描的文件"""

    def __init__(self, console: Console):
        self.console = console
        self.selected: List[str] = []

    def run(self, target: str) -> List[str]:
        """运行交互式文件选择

        Args:
            target: 扫描目标路径

        Returns:
            选中的文件路径列表
        """
        target_path = Path(target).resolve()

        if target_path.is_file():
            return [str(target_path)]

        # 收集文件列表
        all_files = []
        for ext in ('*.py', '*.js', '*.ts', '*.java', '*.go', '*.rb', '*.php', '*.sh', '*.yaml', '*.yml', '*.json', '*.xml', '*.html', '*.css'):
            all_files.extend([str(p) for p in target_path.rglob(ext)])
        all_files = sorted(set(all_files))

        if not all_files:
            self.console.print("[yellow]未找到可扫描的文件[/yellow]")
            return []

        self.console.print(f"[bold cyan]发现 {len(all_files)} 个文件，请输入编号选择（空格分隔，输入 a 全选，q 取消）[/bold cyan]\n")

        # 分页显示
        page_size = 20
        total_pages = (len(all_files) + page_size - 1) // page_size
        current_page = 0

        while True:
            start = current_page * page_size
            end = min(start + page_size, len(all_files))

            for i in range(start, end):
                marker = "*" if (i + 1) in [self._file_index(f) + 1 for f in self.selected] else " "
                self.console.print(f"  [{i+1:4d}] {marker} {all_files[i]}")

            self.console.print(f"\n  页 {current_page + 1}/{total_pages}")
            if total_pages > 1:
                self.console.print("  [上一页] / [下一页] 或 p/n")

            try:
                prompt = "\n选择 > "
                user_input = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n[yellow]已取消选择[/yellow]")
                return []

            if user_input.lower() in ('q', 'quit', 'exit'):
                self.console.print("[yellow]已取消选择[/yellow]")
                return []

            if user_input.lower() in ('a', 'all'):
                self.selected = list(all_files)
                self.console.print(f"[green]已选择全部 {len(self.selected)} 个文件[/green]")
                return self.selected

            if user_input.lower() in ('n', 'next') and current_page < total_pages - 1:
                current_page += 1
                continue
            if user_input.lower() in ('p', 'prev', 'previous') and current_page > 0:
                current_page -= 1
                continue

            # 解析选择
            try:
                indices = []
                for part in user_input.split():
                    if '-' in part:
                        parts = part.split('-')
                        indices.extend(range(int(parts[0]), int(parts[-1]) + 1))
                    else:
                        indices.append(int(part))

                new_selection = []
                for idx in indices:
                    if 1 <= idx <= len(all_files):
                        new_selection.append(all_files[idx - 1])

                if new_selection:
                    self.selected = new_selection
                    self.console.print(f"[green]已选择 {len(self.selected)} 个文件[/green]")
                    return self.selected
                else:
                    self.console.print("[yellow]无效选择，请重试[/yellow]")
            except ValueError:
                self.console.print("[yellow]无效输入，请输入数字编号[/yellow]")

    def _file_index(self, file_path: str) -> int:
        """获取文件在全局列表中的索引"""
        return 0
