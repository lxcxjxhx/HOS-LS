"""远程安全扫描器模块

包装 SecurityScanner，提供远程文件发现和分析功能。
"""

import asyncio
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union

from rich.console import Console

from src.core.config import Config
from src.core.scanner import SecurityScanner

console = Console()


class RemoteSecurityScanner:
    """远程安全扫描器

    包装 SecurityScanner，使用远程文件发现。
    """

    def __init__(self, config: Config, remote_config: Dict[str, Any]):
        """初始化远程安全扫描器

        Args:
            config: 扫描配置
            remote_config: 远程扫描配置
        """
        self.config = config
        self.remote_config = remote_config
        self.remote_mode = True

        from src.integration.remote_scan.network_scanner import NetworkScanner
        from src.integration.remote_scan.serial_scanner import SerialScanner

        scanner_type = remote_config.get("type", "ssh")
        if scanner_type == "serial":
            self.remote_scanner = SerialScanner(remote_config)
        else:
            self.remote_scanner = NetworkScanner(remote_config)

        self._scanner = SecurityScanner(config)
        self.findings: list = []

    def scan_sync(self, target: Union[str, Path]) -> Any:
        """执行同步远程扫描

        Args:
            target: 扫描目标

        Returns:
            扫描结果
        """
        return asyncio.run(self.scan(target))

    async def scan(self, target: Union[str, Path]) -> Any:
        """执行远程扫描

        Args:
            target: 扫描目标

        Returns:
            扫描结果
        """
        from src.core.engine import ScanResult, ScanStatus
        from src.utils.file_discovery import FileInfo, FileType, Language

        start_datetime = datetime.now()
        temp_files = []

        console.print(
            f"[bold cyan][REMOTE] Connecting to remote target:[/bold cyan] [bold green]{target}[/bold green]"
        )

        if not self.remote_scanner.connect():

            result = ScanResult(
                target=str(target), status=ScanStatus.FAILED, start_time=start_datetime
            )
            result.error_message = "Failed to connect to remote target"
            return result

        try:
            console.print("[bold cyan][REMOTE] Discovering remote files...[/bold cyan]")
            remote_files = self.remote_scanner.discover_files(str(target))

            if not remote_files:
                console.print(
                    "[bold yellow][WARN] No files discovered on remote target[/bold yellow]"
                )

                result = ScanResult(
                    target=str(target), status=ScanStatus.COMPLETED, start_time=start_datetime
                )
                result.findings = []
                return result

            console.print(
                f"[bold cyan][OK] Found[/bold cyan] [bold green]{len(remote_files)}[/bold green] remote files"
            )

            console.print("[bold cyan][REMOTE] Reading remote files and analyzing...[/bold cyan]")

            file_infos = []
            for remote_file in remote_files:
                try:
                    content = self.remote_scanner.read_file(remote_file.path)
                    if content is None:
                        continue

                    content_str = content.decode("utf-8", errors="ignore")

                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=Path(remote_file.path).suffix, delete=False
                    ) as f:
                        f.write(content_str)
                        temp_path = f.name
                        temp_files.append(temp_path)

                    file_info = FileInfo(
                        path=Path(temp_path),
                        size=len(content),
                        language=Language.UNKNOWN,
                        file_type=getattr(FileType, "UNKNOWN", "unknown"),
                        extension=Path(remote_file.path).suffix.lower(),
                        encoding="utf-8",
                        line_count=len(content_str.splitlines()),
                        hash="",
                        last_modified=datetime.fromtimestamp(remote_file.modified_time),
                        metadata={"remote_path": remote_file.path, "remote": True},
                    )
                    file_infos.append(file_info)

                except Exception as e:
                    if self.config.debug:
                        console.print(
                            f"[dim][DEBUG] Failed to read remote file {remote_file.path}: {e}[/dim]"
                        )
                    continue

            console.print(f"[bold cyan][TOOL] Analyzing {len(file_infos)} files...[/bold cyan]")

            findings, analyzed_count = await self._scanner._analyze_files(file_infos)

            console.print(
                f"[bold cyan][OK] Found[/bold cyan] [bold red]{len(findings)}[/bold red] security issues"
            )

        finally:
            self.remote_scanner.disconnect()

            for temp_path in temp_files:
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass

        result = ScanResult(
            target=str(target), status=ScanStatus.COMPLETED, start_time=start_datetime
        )
        result.findings = findings
        result.metadata["total_files"] = analyzed_count
        result.metadata["remote_scan"] = True

        return result


def create_scanner(
    config: Config, remote_config: Optional[Dict[str, Any]] = None
) -> Any:
    """创建安全扫描器

    Args:
        config: 扫描配置
        remote_config: 远程扫描配置（可选）

    Returns:
        安全扫描器实例（本地或远程）
    """
    if remote_config is not None:
        return RemoteSecurityScanner(config, remote_config)
    return SecurityScanner(config)
