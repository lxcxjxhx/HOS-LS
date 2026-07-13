"""内存监控工具

用于实时监控 GPU 显存使用，提供内存使用预测，动态调整批量大小等功能。
"""

import time
from typing import Optional, Dict, Any

# 导入 torch 用于 GPU 内存管理
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

# 导入 psutil 用于系统内存监控
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class MemoryMonitor:
    """内存监控器

    用于监控 GPU 和系统内存使用情况，提供内存使用预测和批量大小调整建议。
    """

    def __init__(self):
        """初始化内存监控器"""
        self.gpu_available = TORCH_AVAILABLE and torch.cuda.is_available()
        self.system_available = PSUTIL_AVAILABLE
        self.memory_history = []
        self.batch_size_history = []

    def get_gpu_memory(self) -> Optional[Dict[str, float]]:
        """获取 GPU 内存使用情况

        Returns:
            包含 GPU 内存信息的字典，或 None 如果 GPU 不可用
        """
        if not self.gpu_available:
            return None

        try:
            device = torch.device('cuda:0')
            total_memory = torch.cuda.get_device_properties(device).total_memory / (1024 ** 3)  # GB
            allocated_memory = torch.cuda.memory_allocated(device) / (1024 ** 3)  # GB
            cached_memory = torch.cuda.memory_reserved(device) / (1024 ** 3)  # GB
            free_memory = total_memory - allocated_memory

            return {
                'total': total_memory,
                'allocated': allocated_memory,
                'cached': cached_memory,
                'free': free_memory,
                'used_percent': (allocated_memory / total_memory) * 100
            }
        except Exception as e:
            print(f"获取 GPU 内存信息失败: {e}")
            return None

    def get_system_memory(self) -> Optional[Dict[str, float]]:
        """获取系统内存使用情况

        Returns:
            包含系统内存信息的字典，或 None 如果 psutil 不可用
        """
        if not self.system_available:
            return None

        try:
            memory = psutil.virtual_memory()
            return {
                'total': memory.total / (1024 ** 3),  # GB
                'available': memory.available / (1024 ** 3),  # GB
                'used': memory.used / (1024 ** 3),  # GB
                'used_percent': memory.percent
            }
        except Exception as e:
            print(f"获取系统内存信息失败: {e}")
            return None

    def get_memory_status(self) -> Dict[str, Any]:
        """获取完整的内存状态

        Returns:
            包含 GPU 和系统内存信息的字典
        """
        status = {
            'timestamp': time.time(),
            'gpu': self.get_gpu_memory(),
            'system': self.get_system_memory()
        }

        # 记录内存历史
        self.memory_history.append(status)
        # 只保留最近 100 条记录
        if len(self.memory_history) > 100:
            self.memory_history.pop(0)

        return status

    def predict_memory_usage(self, batch_size: int) -> Optional[float]:
        """预测给定批量大小的内存使用

        Args:
            batch_size: 批量大小

        Returns:
            预测的内存使用量（GB），或 None 如果无法预测
        """
        if not self.memory_history:
            return None

        # 简单的线性预测模型
        # 假设内存使用与批量大小成线性关系
        recent_history = self.memory_history[-10:]  # 最近 10 条记录

        # 提取 GPU 内存使用数据
        gpu_memory_usages = []
        for record in recent_history:
            if record['gpu']:
                gpu_memory_usages.append(record['gpu']['allocated'])

        if not gpu_memory_usages:
            return None

        # 计算平均内存使用
        avg_memory = sum(gpu_memory_usages) / len(gpu_memory_usages)

        # 假设当前批量大小为 512，预测新批量大小的内存使用
        current_batch_size = 512  # 假设当前批量大小
        predicted_memory = avg_memory * (batch_size / current_batch_size)

        return predicted_memory

    def suggest_batch_size(self, current_batch_size: int) -> int:
        """根据内存使用情况建议批量大小

        Args:
            current_batch_size: 当前批量大小

        Returns:
            建议的批量大小
        """
        memory_status = self.get_memory_status()

        if not memory_status['gpu']:
            return current_batch_size

        gpu_memory = memory_status['gpu']
        used_percent = gpu_memory['used_percent']

        # 根据内存使用情况调整批量大小
        if used_percent > 80:
            # 内存使用过高，减少批量大小
            new_batch_size = max(128, current_batch_size // 2)
            print(f"⚠️  GPU 内存使用过高 ({used_percent:.1f}%)，建议减少批量大小到 {new_batch_size}")
            return new_batch_size
        elif used_percent < 50:
            # 内存使用较低，可以增加批量大小
            new_batch_size = min(1024, current_batch_size * 2)
            print(f"✅ GPU 内存使用较低 ({used_percent:.1f}%)，建议增加批量大小到 {new_batch_size}")
            return new_batch_size
        else:
            # 内存使用适中，保持当前批量大小
            return current_batch_size

    def monitor_memory_usage(self, interval: float = 5.0) -> None:
        """持续监控内存使用情况

        Args:
            interval: 监控间隔（秒）
        """
        print("开始监控内存使用情况...")
        print("按 Ctrl+C 停止监控")

        try:
            while True:
                status = self.get_memory_status()
                self._print_memory_status(status)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("监控停止")

    def _print_memory_status(self, status: Dict[str, Any]) -> None:
        """打印内存状态

        Args:
            status: 内存状态字典
        """
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(status['timestamp']))
        print(f"\n[{timestamp}] 内存状态:")

        if status['gpu']:
            gpu = status['gpu']
            print(f"GPU 内存: {gpu['allocated']:.2f} GB / {gpu['total']:.2f} GB ({gpu['used_percent']:.1f}%)")
            print(f"GPU 可用: {gpu['free']:.2f} GB")

        if status['system']:
            system = status['system']
            print(f"系统内存: {system['used']:.2f} GB / {system['total']:.2f} GB ({system['used_percent']:.1f}%)")
            print(f"系统可用: {system['available']:.2f} GB")

    def get_batch_size_recommendation(self, model_name: str, text_length: int) -> int:
        """根据模型和文本长度推荐批量大小

        Args:
            model_name: 模型名称
            text_length: 文本长度

        Returns:
            推荐的批量大小
        """
        # 基础批量大小
        base_batch_size = 512

        # 根据模型调整
        if 'gemma' in model_name.lower():
            # Gemma 模型内存效率较高
            base_batch_size = 768
        elif 'qwen' in model_name.lower():
            # Qwen 模型内存使用较大
            base_batch_size = 384

        # 根据文本长度调整
        if text_length > 1000:
            # 长文本减少批量大小
            base_batch_size = max(128, base_batch_size // 2)
        elif text_length < 200:
            # 短文本增加批量大小
            base_batch_size = min(1024, base_batch_size * 2)

        # 根据 GPU 内存调整
        memory_status = self.get_memory_status()
        if memory_status['gpu']:
            gpu_memory = memory_status['gpu']
            if gpu_memory['total'] < 8:
                # 小 GPU 内存
                base_batch_size = max(128, base_batch_size // 2)
            elif gpu_memory['total'] >= 16:
                # 大 GPU 内存
                base_batch_size = min(2048, base_batch_size * 2)

        return base_batch_size


# 全局内存监控器实例
memory_monitor = MemoryMonitor()


def get_memory_monitor() -> MemoryMonitor:
    """获取全局内存监控器实例

    Returns:
        MemoryMonitor 实例
    """
    return memory_monitor


def monitor_memory(interval: float = 5.0) -> None:
    """启动内存监控

    Args:
        interval: 监控间隔（秒）
    """
    memory_monitor.monitor_memory_usage(interval)


def get_memory_status() -> Dict[str, Any]:
    """获取当前内存状态

    Returns:
        内存状态字典
    """
    return memory_monitor.get_memory_status()


def suggest_batch_size(current_batch_size: int) -> int:
    """根据内存使用情况建议批量大小

    Args:
        current_batch_size: 当前批量大小

    Returns:
        建议的批量大小
    """
    return memory_monitor.suggest_batch_size(current_batch_size)


def get_batch_size_recommendation(model_name: str, text_length: int) -> int:
    """根据模型和文本长度推荐批量大小

    Args:
        model_name: 模型名称
        text_length: 文本长度

    Returns:
        推荐的批量大小
    """
    return memory_monitor.get_batch_size_recommendation(model_name, text_length)
