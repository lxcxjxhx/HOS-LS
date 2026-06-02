"""OWASP ZAP 插件

集成 OWASP ZAP Web 安全扫描工具。
"""

import shutil
from typing import Any, Dict, List

from src.plugins.base import MCPToolPlugin, PluginMetadata, PluginPriority, ToolResult


class ZAPPlugin(MCPToolPlugin):
    """OWASP ZAP Web 安全扫描插件"""

    def __init__(self, config: Dict[str, Any] = None):
        metadata = PluginMetadata(
            name="zap",
            version="1.0.0",
            description="OWASP ZAP Web 安全扫描工具集成",
            author="HOS-LS Team",
            priority=PluginPriority.NORMAL,
            enabled=True,
        )
        super().__init__(metadata, config)
        self._tool_command = "zap"

    @property
    def tool_command(self) -> str:
        return "zap"

    def check_availability(self) -> tuple[bool, str]:
        tool_path = shutil.which(self._tool_command)
        if tool_path:
            return True, f"ZAP available at: {tool_path}"
        return False, "ZAP not found. Please install OWASP ZAP: https://www.zaproxy.org/download/"

    async def execute_tool(self, args: List[str], timeout: int = 900) -> ToolResult:
        if not self._tool_command:
            return ToolResult(
                success=False,
                output="",
                error="Tool command not configured",
                raw_output=""
            )

        cmd = [self._tool_command] + args
        try:
            process = await __import__('asyncio').create_subprocess_exec(
                *cmd,
                stdout=__import__('asyncio').subprocess.PIPE,
                stderr=__import__('asyncio').subprocess.PIPE
            )
            try:
                stdout, stderr = await __import__('asyncio').wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                raw_output = stdout.decode('utf-8', errors='ignore') if stdout else ""
                error_output = stderr.decode('utf-8', errors='ignore') if stderr else ""
                success = process.returncode == 0

                return ToolResult(
                    success=success,
                    output=raw_output if success else error_output,
                    error=error_output if not success else "",
                    raw_output=raw_output
                )
            except __import__('asyncio').TimeoutError:
                process.kill()
                return ToolResult(
                    success=False,
                    output="",
                    error=f"ZAP execution timeout after {timeout}s",
                    raw_output=""
                )
        except FileNotFoundError:
            return ToolResult(
                success=False,
                output="",
                error=f"ZAP not found: {self._tool_command}",
                raw_output=""
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e),
                raw_output=""
            )