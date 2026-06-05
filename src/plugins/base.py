"""插件基类模块

定义插件接口和基类。
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from pathlib import Path


class PluginPriority(Enum):
    """插件优先级"""
    HIGHEST = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    LOWEST = 4


@dataclass
class PluginMetadata:
    """插件元数据"""
    name: str
    version: str
    description: str
    author: str
    priority: PluginPriority = PluginPriority.NORMAL
    enabled: bool = True
    dependencies: List[str] = field(default_factory=list)
    config_schema: Optional[Dict[str, Any]] = None


class Plugin(ABC):
    """插件基类
    
    所有插件都应继承此类。
    """
    
    def __init__(self, metadata: PluginMetadata, config: Optional[Dict[str, Any]] = None):
        self.metadata = metadata
        self.config = config or {}
        self._initialized = False
    
    @property
    def name(self) -> str:
        """插件名称"""
        return self.metadata.name
    
    @property
    def version(self) -> str:
        """插件版本"""
        return self.metadata.version
    
    @property
    def priority(self) -> PluginPriority:
        """插件优先级"""
        return self.metadata.priority
    
    @property
    def is_initialized(self) -> bool:
        """是否已初始化"""
        return self._initialized
    
    def initialize(self) -> None:
        """初始化插件"""
        self._initialized = True
    
    def shutdown(self) -> None:
        """关闭插件"""
        self._initialized = False
    
    def is_enabled(self) -> bool:
        """检查插件是否启用"""
        return self.metadata.enabled
    
    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行插件
        
        Args:
            context: 执行上下文
            
        Returns:
            执行结果
        """
        pass


class ScanPlugin(Plugin):
    """扫描插件基类
    
    用于实现安全扫描插件。
    """
    
    def __init__(self, metadata: PluginMetadata, config: Optional[Dict[str, Any]] = None):
        super().__init__(metadata, config)
        self._findings: List[Dict[str, Any]] = []
    
    @abstractmethod
    async def scan(self, file_path: Path, content: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """扫描文件
        
        Args:
            file_path: 文件路径
            content: 文件内容
            context: 扫描上下文
            
        Returns:
            发现的安全问题列表
        """
        pass
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行扫描
        
        Args:
            context: 执行上下文，包含 file_path 和 content
            
        Returns:
            扫描结果
        """
        file_path = context.get('file_path')
        content = context.get('content')
        
        if not file_path or not content:
            return {'findings': [], 'error': 'Missing file_path or content'}
        
        findings = await self.scan(Path(file_path), content, context)
        
        return {
            'findings': findings,
            'plugin_name': self.name,
            'plugin_version': self.version,
        }


class PluginManager:
    """插件管理器
    
    管理插件的生命周期和执行。
    """
    
    def __init__(self):
        self._plugins: Dict[str, Plugin] = {}
        self._hooks: Dict[str, List[Callable]] = {}
    
    def register(self, plugin: Plugin) -> None:
        """注册插件
        
        Args:
            plugin: 插件实例
        """
        self._plugins[plugin.name] = plugin
        
        # 按优先级排序
        self._plugins = dict(sorted(
            self._plugins.items(),
            key=lambda x: x[1].priority.value
        ))
    
    def unregister(self, name: str) -> None:
        """注销插件
        
        Args:
            name: 插件名称
        """
        if name in self._plugins:
            del self._plugins[name]
    
    def get_plugin(self, name: str) -> Optional[Plugin]:
        """获取插件
        
        Args:
            name: 插件名称
            
        Returns:
            插件实例
        """
        return self._plugins.get(name)
    
    def list_plugins(self) -> List[Plugin]:
        """列出所有插件
        
        Returns:
            插件列表
        """
        return list(self._plugins.values())
    
    def get_enabled_plugins(self) -> List[Plugin]:
        """获取启用的插件
        
        Returns:
            启用的插件列表
        """
        return [p for p in self._plugins.values() if p.is_enabled()]
    
    async def execute_all(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行所有启用的插件
        
        Args:
            context: 执行上下文
            
        Returns:
            所有插件的执行结果
        """
        results = {}
        
        for name, plugin in self._plugins.items():
            if plugin.is_enabled():
                try:
                    result = await plugin.execute(context)
                    results[name] = result
                except Exception as e:
                    results[name] = {'error': str(e)}
        
        return results
    
    async def execute_scan_plugins(self, file_path: Path, content: str, 
                                   context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """执行所有扫描插件
        
        Args:
            file_path: 文件路径
            content: 文件内容
            context: 扫描上下文
            
        Returns:
            所有发现的安全问题
        """
        all_findings = []
        scan_context = context or {}
        scan_context['file_path'] = str(file_path)
        scan_context['content'] = content
        
        # 获取所有扫描插件
        scan_plugins = [
            p for p in self._plugins.values()
            if isinstance(p, ScanPlugin) and p.is_enabled()
        ]
        
        # 并发执行所有扫描插件
        tasks = [plugin.execute(scan_context) for plugin in scan_plugins]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                continue
            if isinstance(result, dict) and 'findings' in result:
                all_findings.extend(result['findings'])
        
        return all_findings
    
    def initialize_all(self) -> None:
        """初始化所有插件"""
        for plugin in self._plugins.values():
            if plugin.is_enabled():
                plugin.initialize()
    
    def shutdown_all(self) -> None:
        """关闭所有插件"""
        for plugin in self._plugins.values():
            plugin.shutdown()


@dataclass
class ToolResult:
    """外部工具执行结果"""
    success: bool
    output: str
    error: str
    raw_output: str


@dataclass
class SkillPrompt:
    """技能提示词模板"""
    name: str
    description: str
    template: str
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SkillResult:
    """技能执行结果"""
    success: bool
    result: Any
    error: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class MCPToolPlugin(Plugin):
    """MCP 工具插件基类

    用于集成外部安全工具 (sqlmap, nuclei, zap 等)。
    """

    def __init__(self, metadata: PluginMetadata, config: Optional[Dict[str, Any]] = None):
        super().__init__(metadata, config)
        self._tool_command: Optional[str] = None

    @property
    def tool_command(self) -> Optional[str]:
        """外部工具命令"""
        return self._tool_command

    def check_availability(self) -> tuple[bool, str]:
        """检查工具是否可用

        Returns:
            (是否可用, 状态信息)
        """
        if not self._tool_command:
            return False, "Tool command not configured"
        return True, "Tool available"

    async def execute_tool(self, args: List[str], timeout: int = 300) -> ToolResult:
        """执行外部工具

        Args:
            args: 工具参数
            timeout: 超时时间(秒)

        Returns:
            工具执行结果
        """
        if not self._tool_command:
            return ToolResult(
                success=False,
                output="",
                error="Tool command not configured",
                raw_output=""
            )

        cmd = [self._tool_command] + args
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                raw_output = stdout.decode() if stdout else ""
                error_output = stderr.decode() if stderr else ""
                success = process.returncode == 0

                return ToolResult(
                    success=success,
                    output=raw_output if success else error_output,
                    error=error_output if not success else "",
                    raw_output=raw_output
                )
            except asyncio.TimeoutError:
                process.kill()
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Tool execution timeout after {timeout}s",
                    raw_output=""
                )
        except FileNotFoundError:
            return ToolResult(
                success=False,
                output="",
                error=f"Tool not found: {self._tool_command}",
                raw_output=""
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e),
                raw_output=""
            )

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行插件

        Args:
            context: 执行上下文

        Returns:
            执行结果
        """
        args = context.get('args', [])
        timeout = context.get('timeout', 300)
        result = await self.execute_tool(args, timeout)

        return {
            'success': result.success,
            'output': result.output,
            'error': result.error,
            'raw_output': result.raw_output,
            'plugin_name': self.name,
            'plugin_version': self.version,
        }


class SkillPlugin(Plugin):
    """技能插件基类

    用于扩展 AI 能力，提供提示词模板。
    """

    def __init__(self, metadata: PluginMetadata, config: Optional[Dict[str, Any]] = None):
        super().__init__(metadata, config)
        self._skill_prompts: List[SkillPrompt] = []

    @property
    def skill_prompts(self) -> List[SkillPrompt]:
        """技能提示词列表"""
        return self._skill_prompts

    async def execute_skill(self, skill_name: str, parameters: Dict[str, Any]) -> SkillResult:
        """执行技能

        Args:
            skill_name: 技能名称
            parameters: 执行参数

        Returns:
            技能执行结果
        """
        skill = next((s for s in self._skill_prompts if s.name == skill_name), None)
        if not skill:
            return SkillResult(
                success=False,
                result=None,
                error=f"Skill not found: {skill_name}",
                metadata={}
            )

        try:
            rendered_template = skill.template
            for key, value in parameters.items():
                rendered_template = rendered_template.replace(f"{{{key}}}", str(value))

            return SkillResult(
                success=True,
                result=rendered_template,
                error="",
                metadata={'skill_name': skill_name, 'parameters': parameters}
            )
        except Exception as e:
            return SkillResult(
                success=False,
                result=None,
                error=str(e),
                metadata={'skill_name': skill_name}
            )

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行插件

        Args:
            context: 执行上下文

        Returns:
            执行结果
        """
        skill_name = context.get('skill_name')
        parameters = context.get('parameters', {})

        if not skill_name:
            return {
                'success': False,
                'error': 'Missing skill_name in context',
                'available_skills': [s.name for s in self._skill_prompts]
            }

        result = await self.execute_skill(skill_name, parameters)

        return {
            'success': result.success,
            'result': result.result,
            'error': result.error,
            'metadata': result.metadata,
            'plugin_name': self.name,
            'plugin_version': self.version,
        }
