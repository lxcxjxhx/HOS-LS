import platform
import os
import sys
from typing import Dict, Any

class EnvironmentDetector:
    """环境检测模块
    
    检测当前运行环境，为不同环境提供相应的配置调整
    """
    
    def __init__(self):
        """初始化环境检测器"""
        self.platform = platform.system()
        self.python_version = platform.python_version()
        self.cpu_count = os.cpu_count() or 4
        self.memory_available = self._get_available_memory()
        self.is_windows = self.platform == 'Windows'
        self.is_linux = self.platform == 'Linux'
        self.is_macos = self.platform == 'Darwin'
    
    def _get_available_memory(self) -> int:
        """获取可用内存（MB）
        
        Returns:
            可用内存大小（MB）
        """
        try:
            if self.is_windows:
                import ctypes
                class MEMORYSTATUS(ctypes.Structure):
                    _fields_ = [
                        ('dwLength', ctypes.c_ulong),
                        ('dwMemoryLoad', ctypes.c_ulong),
                        ('dwTotalPhys', ctypes.c_ulong),
                        ('dwAvailPhys', ctypes.c_ulong),
                        ('dwTotalPageFile', ctypes.c_ulong),
                        ('dwAvailPageFile', ctypes.c_ulong),
                        ('dwTotalVirtual', ctypes.c_ulong),
                        ('dwAvailVirtual', ctypes.c_ulong),
                    ]
                memory_status = MEMORYSTATUS()
                memory_status.dwLength = ctypes.sizeof(MEMORYSTATUS)
                ctypes.windll.kernel32.GlobalMemoryStatus(ctypes.byref(memory_status))
                return memory_status.dwAvailPhys // (1024 * 1024)
            elif self.is_linux or self.is_macos:
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemAvailable:'):
                            return int(line.split()[1]) // 1024
                return 4096  # 默认值
        except Exception:
            return 4096  # 默认值
    
    def get_environment_info(self) -> Dict[str, Any]:
        """获取环境信息
        
        Returns:
            环境信息字典
        """
        return {
            'platform': self.platform,
            'python_version': self.python_version,
            'cpu_count': self.cpu_count,
            'memory_available': self.memory_available,
            'is_windows': self.is_windows,
            'is_linux': self.is_linux,
            'is_macos': self.is_macos,
            'python_executable': sys.executable,
            'current_directory': os.getcwd()
        }
    
    def get_optimized_config(self, base_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """根据环境获取优化的配置
        
        Args:
            base_config: 基础配置
            
        Returns:
            优化后的配置
        """
        config = base_config or {}
        
        # 根据CPU核心数调整并发数
        max_workers = min(self.cpu_count, 8)  # 最多8个并发
        config.setdefault('max_workers', max_workers)
        
        # 根据可用内存调整批处理大小
        if self.memory_available < 4096:
            # 内存不足4GB
            config.setdefault('batch_size', 2)
        elif self.memory_available < 8192:
            # 内存4-8GB
            config.setdefault('batch_size', 4)
        else:
            # 内存8GB以上
            config.setdefault('batch_size', 8)
        
        # 根据平台调整路径相关配置
        if self.is_windows:
            config.setdefault('cache_dir', '.cache\\hos-ls\\pure-ai')
        else:
            config.setdefault('cache_dir', '.cache/hos-ls/pure-ai')
        
        # 设置超时时间
        config.setdefault('timeout', 300)  # 5分钟
        
        # 设置缓存TTL
        config.setdefault('cache_ttl', 86400)  # 24小时
        
        return config
    
    def is_supported_environment(self) -> bool:
        """检查当前环境是否支持
        
        Returns:
            是否支持当前环境
        """
        # 检查Python版本
        major, minor, _ = map(int, self.python_version.split('.'))
        if major < 3 or (major == 3 and minor < 7):
            return False
        
        # 检查操作系统
        if not (self.is_windows or self.is_linux or self.is_macos):
            return False
        
        # 检查内存
        if self.memory_available < 2048:  # 至少2GB内存
            return False
        
        return True
    
    def get_environment_warnings(self) -> list:
        """获取环境警告
        
        Returns:
            警告信息列表
        """
        warnings = []
        
        # 检查Python版本
        major, minor, _ = map(int, self.python_version.split('.'))
        if major == 3 and minor < 8:
            warnings.append(f"Python {self.python_version} 可能不支持所有功能，建议使用 Python 3.8+")
        
        # 检查内存
        if self.memory_available < 4096:
            warnings.append(f"可用内存 {self.memory_available}MB 较低，可能影响性能，建议至少 4GB 内存")
        
        # 检查CPU核心数
        if self.cpu_count < 2:
            warnings.append(f"CPU核心数 {self.cpu_count} 较少，可能影响并发性能，建议至少 2 核心")
        
        return warnings

# 全局环境检测器实例
env_detector = EnvironmentDetector()

# 导出函数
def get_environment_info() -> Dict[str, Any]:
    """获取环境信息
    
    Returns:
        环境信息字典
    """
    return env_detector.get_environment_info()

def get_optimized_config(base_config: Dict[str, Any] = None) -> Dict[str, Any]:
    """根据环境获取优化的配置
    
    Args:
        base_config: 基础配置
        
    Returns:
        优化后的配置
    """
    return env_detector.get_optimized_config(base_config)

def is_supported_environment() -> bool:
    """检查当前环境是否支持
    
    Returns:
        是否支持当前环境
    """
    return env_detector.is_supported_environment()

def get_environment_warnings() -> list:
    """获取环境警告
    
    Returns:
        警告信息列表
    """
    return env_detector.get_environment_warnings()