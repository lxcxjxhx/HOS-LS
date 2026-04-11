"""
连接器基类

定义所有连接器的统一接口和基础功能。
"""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from rich.console import Console

console = Console()


class ConnectionStatus(Enum):
    """连接状态枚举"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"
    RECONNECTING = "reconnecting"


@dataclass
class ConnectionResult:
    """连接结果数据类"""
    success: bool
    status: ConnectionStatus
    message: str = ""
    latency_ms: float = 0.0  # 连接延迟（毫秒）
    error: Optional[Exception] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
            
    @property
    def is_success(self) -> bool:
        return self.success and self.status == ConnectionStatus.CONNECTED


@dataclass 
class ConnectionConfig:
    """连接配置数据类"""
    timeout: int = 30  # 超时时间（秒）
    max_retries: int = 3  # 最大重试次数
    retry_delay: float = 1.0  # 重试延迟（秒）
    keepalive_interval: int = 30  # 心跳间隔（秒）
    enable_compression: bool = False  # 是否启用压缩
    proxy: Optional[str] = None  # 代理服务器
    verify_ssl: bool = True  # 验证SSL证书（仅HTTP）
    user_agent: str = "HOS-LS/1.0 (Security Scanner)"  # User-Agent


class BaseConnector(ABC):
    """
    连接器抽象基类
    
    所有连接器必须实现此接口，提供统一的连接管理功能。
    支持连接池、重试机制、错误处理等高级功能。
    """
    
    connector_type: str = "base"  # 子类必须覆盖此属性
    
    def __init__(self, config: ConnectionConfig = None, **kwargs):
        """
        初始化连接器
        
        Args:
            config: 连接配置
            **kwargs: 额外参数
        """
        self.config = config or ConnectionConfig()
        self._status = ConnectionStatus.DISCONNECTED
        self._connection_time: Optional[datetime] = None
        self._last_error: Optional[Exception] = None
        self._retry_count = 0
        self._metadata: Dict[str, Any] = kwargs
        
    @property
    def status(self) -> ConnectionStatus:
        """获取当前连接状态"""
        return self._status
    
    @property
    def is_connected(self) -> bool:
        """检查是否已连接"""
        return self._status == ConnectionStatus.CONNECTED
    
    @property
    def connection_duration(self) -> Optional[float]:
        """获取连接持续时间（秒）"""
        if self._connection_time:
            return (datetime.now() - self._connection_time).total_seconds()
        return None
    
    @abstractmethod
    async def _do_connect(self) -> ConnectionResult:
        """
        执行实际连接操作（子类实现）
        
        Returns:
            连接结果
        """
        pass
    
    @abstractmethod
    async def _do_disconnect(self) -> None:
        """执行实际断开操作（子类实现）"""
        pass
    
    async def connect(self) -> ConnectionResult:
        """
        建立连接（带重试机制）
        
        Returns:
            连接结果
        """
        if self.is_connected:
            return ConnectionResult(
                success=True,
                status=ConnectionStatus.CONNECTED,
                message="已经处于连接状态",
                metadata={'cached': True}
            )
        
        self._status = ConnectionStatus.CONNECTING
        
        last_result = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                if attempt > 0:
                    console.print(f"[yellow]第 {attempt} 次重试连接...[/yellow]")
                    await asyncio.sleep(self.config.retry_delay * attempt)
                
                start_time = time.time()
                
                result = await asyncio.wait_for(
                    self._do_connect(),
                    timeout=self.config.timeout
                )
                
                latency = (time.time() - start_time) * 1000
                result.latency_ms = latency
                
                if result.success:
                    self._status = ConnectionStatus.CONNECTED
                    self._connection_time = datetime.now()
                    self._retry_count = attempt
                    
                    console.print(
                        f"[green]✓ {self.connector_type.upper()} 连接成功 "
                        f"(延迟: {latency:.2f}ms)[/green]"
                    )
                    
                    return result
                else:
                    last_result = result
                    
            except asyncio.TimeoutError:
                last_result = ConnectionResult(
                    success=False,
                    status=ConnectionStatus.ERROR,
                    message=f"连接超时 ({self.config.timeout}s)",
                    error=TimeoutError("Connection timeout")
                )
                
            except Exception as e:
                last_result = ConnectionResult(
                    success=False,
                    status=ConnectionStatus.ERROR,
                    message=str(e),
                    error=e
                )
        
        self._status = ConnectionStatus.ERROR
        self._last_error = last_result.error if last_result else Exception("Unknown error")
        
        console.print(f"[red]✗ {self.connector_type.upper()} 连接失败: {last_result.message}[/red]")
        
        return last_result or ConnectionResult(
            success=False,
            status=ConnectionStatus.ERROR,
            message="所有重试均失败"
        )
    
    async def disconnect(self) -> None:
        """断开连接"""
        if not self.is_connected:
            return
            
        try:
            await self._do_disconnect()
            self._status = ConnectionStatus.DISCONNECTED
            self._connection_time = None
            
            console.print(f"[dim]{self.connector_type.upper()} 连接已关闭[/dim]")
            
        except Exception as e:
            console.print(f"[red]断开连接时出错: {e}[/red]")
            self._status = ConnectionStatus.ERROR
    
    async def test_connection(self) -> bool:
        """
        测试连接是否可用
        
        Returns:
            连接是否可用
        """
        result = await self.connect()
        if result.success:
            await self.disconnect()
        return result.success
    
    async def reconnect(self) -> ConnectionResult:
        """
        重新连接
        
        Returns:
            连接结果
        """
        if self.is_connected:
            await self.disconnect()
            
        self._status = ConnectionStatus.RECONNECTING
        console.print("[yellow]正在重新连接...[/yellow]")
        
        return await self.connect()
    
    async def keepalive(self) -> bool:
        """
        发送心跳包保持连接活跃
        
        Returns:
            心跳是否成功
        """
        if not self.is_connected:
            return False
            
        try:
            return await self._do_keepalive()
        except Exception as e:
            console.print(f"[red]心跳失败: {e}[/red]")
            self._status = ConnectionStatus.ERROR
            return False
    
    async def _do_keepalive(self) -> bool:
        """
        执行心跳操作（子类可覆盖）
        
        默认返回True，子类应根据协议实现具体逻辑
        """
        return True
    
    async def execute_with_retry(
        self, 
        operation, 
        max_retries: int = None,
        retry_delay: float = None,
        **kwargs
    ) -> Any:
        """
        带重试的操作执行
        
        Args:
            operation: 要执行的异步操作（callable）
            max_retries: 最大重试次数
            retry_delay: 重试延迟
            **kwargs: 操作参数
            
        Returns:
            操作结果
            
        Raises:
            最后一次操作的异常
        """
        retries = max_retries or self.config.max_retries
        delay = retry_delay or self.config.retry_delay
        
        last_error = None
        
        for attempt in range(retries + 1):
            try:
                if not self.is_connected:
                    await self.reconnect()
                    
                result = await operation(**kwargs)
                return result
                
            except Exception as e:
                last_error = e
                if attempt < retries:
                    console.print(
                        f"[yellow]操作失败，第 {attempt + 1} 次重试... "
                        f"({e})[/yellow]"
                    )
                    await asyncio.sleep(delay * (attempt + 1))
                    
        raise last_error
    
    def get_stats(self) -> Dict[str, Any]:
        """
        获取连接统计信息
        
        Returns:
            统计信息字典
        """
        return {
            'connector_type': self.connector_type,
            'status': self._status.value,
            'is_connected': self.is_connected,
            'connection_duration': self.connection_duration,
            'retry_count': self._retry_count,
            'last_error': str(self._last_error) if self._last_error else None,
            'config': {
                'timeout': self.config.timeout,
                'max_retries': self.config.max_retries,
                'proxy': self.config.proxy
            },
            'metadata': self._metadata
        }
    
    async def __aenter__(self):
        """异步上下文管理器入口"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self.disconnect()
        return False
    
    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"type={self.connector_type}, "
            f"status={self._status.value}, "
            f"connected={self.is_connected})"
        )


class ConnectorPool:
    """
    连接池管理器
    
    管理多个连接器的生命周期，支持连接复用和并发控制。
    """
    
    def __init__(
        self, 
        max_size: int = 10,
        min_size: int = 2,
        idle_timeout: int = 300
    ):
        """
        初始化连接池
        
        Args:
            max_size: 最大连接数
            min_size: 最小空闲连接数
            idle_timeout: 空闲超时时间（秒）
        """
        self.max_size = max_size
        self.min_size = min_size
        self.idle_timeout = idle_timeout
        
        self._pool: Dict[str, BaseConnector] = {}
        self._in_use: Dict[str, BaseConnector] = {}
        self._created_count = 0
        self._lock = asyncio.Lock()
        
    @property
    def size(self) -> int:
        """当前连接总数"""
        return len(self._pool) + len(self._in_use)
    
    @property
    def available_count(self) -> int:
        """可用连接数"""
        return len(self._pool)
    
    @property
    def in_use_count(self) -> int:
        """正在使用的连接数"""
        return len(self._in_use)
    
    async def get_connector(
        self, 
        connector_class, 
        key: str = None,
        **kwargs
    ) -> BaseConnector:
        """
        从连接池获取连接器
        
        Args:
            connector_class: 连接器类
            key: 连接标识键（用于复用）
            **kwargs: 连接器初始化参数
            
        Returns:
            可用的连接器实例
        """
        async with self._lock:
            key = key or f"{connector_class.__name__}_{self._created_count}"
            
            if key in self._pool:
                connector = self._pool.pop(key)
                self._in_use[key] = connector
                
                if not connector.is_connected:
                    await connector.connect()
                    
                return connector
            
            if self.size >= self.max_size:
                raise RuntimeError("连接池已满")
                
            connector = connector_class(**kwargs)
            self._created_count += 1
            self._in_use[key] = connector
            
            await connector.connect()
            
            return connector
    
    async def release(self, key: str, connector: BaseConnector) -> None:
        """
        释放连接器回连接池
        
        Args:
            key: 连接标识键
            connector: 要释放的连接器
        """
        async with self._lock:
            if key in self._in_use:
                del self._in_use[key]
                
            if connector.is_connected and len(self._pool) < self.max_size:
                self._pool[key] = connector
            else:
                await connector.disconnect()
    
    async def close_all(self) -> None:
        """关闭所有连接"""
        async with self._lock:
            for connector in list(self._pool.values()):
                await connector.disconnect()
            for connector in list(self._in_use.values()):
                await connector.disconnect()
                
            self._pool.clear()
            self._in_use.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """获取连接池统计信息"""
        return {
            'total_size': self.size,
            'available': self.available_count,
            'in_use': self.in_use_count,
            'max_size': self.max_size,
            'min_size': self.min_size,
            'created_total': self._created_count
        }


class RetryHandler:
    """
    重试处理器
    
    提供灵活的重试策略和退避算法。
    """
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        backoff_factor: float = 2.0,
        jitter: bool = True
    ):
        """
        初始化重试处理器
        
        Args:
            max_retries: 最大重试次数
            base_delay: 基础延迟（秒）
            max_delay: 最大延迟（秒）
            backoff_factor: 退避因子
            jitter: 是否添加随机抖动
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.jitter = jitter
    
    def get_delay(self, attempt: int) -> float:
        """
        计算第N次重试的延迟时间
        
        使用指数退避算法：
        delay = min(base_delay * backoff_factor^attempt, max_delay)
        
        Args:
            attempt: 当前尝试次数（从0开始）
            
        Returns:
            延迟时间（秒）
        """
        delay = min(
            self.base_delay * (self.backoff_factor ** attempt),
            self.max_delay
        )
        
        if self.jitter:
            import random
            delay *= (0.5 + random.random())
            
        return delay
    
    async def execute_with_retry(
        self, 
        operation,
        on_retry=None,
        **kwargs
    ) -> Any:
        """
        执行带重试的操作
        
        Args:
            operation: 异步操作
            on_retry: 重试回调函数
            **kwargs: 操作参数
            
        Returns:
            操作结果
        """
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return await operation(**kwargs)
                
            except Exception as e:
                last_error = e
                
                if attempt < self.max_retries:
                    delay = self.get_delay(attempt)
                    
                    if on_retry:
                        await on_retry(attempt, e, delay)
                    else:
                        console.print(
                            f"[yellow]重试 {attempt + 1}/{self.max_retries}: "
                            f"{e} (等待 {delay:.2f}s)[/yellow]"
                        )
                        
                    await asyncio.sleep(delay)
                    
        raise last_error
