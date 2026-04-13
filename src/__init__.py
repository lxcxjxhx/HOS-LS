"""HOS-LS: AI生成代码安全扫描工具

HOS-LS (HOS - Language Security) 是一款专注于 AI 生成代码安全扫描的工业级工具。
它结合了静态分析、AI 语义分析和攻击模拟等多种技术，为开发者提供全面的代码安全保障。

Version: 0.3.1.6
"""
import sys
import os
import io
import warnings as _warnings
import logging

# 抑制 triton/torch 在 import 时输出的无害消息
# 这些消息通过 print(stdout) / warnings.warn(stderr) / logging 输出
class _StdoutSuppressor:
    """临时抑制 stdout 的特定行"""
    _PATTERNS = [
        "Skipping import of cpp extensions due to incompatible torch version",
    ]
    
    def __init__(self, original):
        self._original = original
    
    def write(self, text):
        if not any(p in text for p in self._PATTERNS):
            try:
                return self._original.write(text)
            except UnicodeEncodeError:
                # 处理 Unicode 编码错误，尝试使用替代编码
                try:
                    if isinstance(text, str):
                        return self._original.write(text.encode('gbk', errors='replace').decode('gbk'))
                    return self._original.write(text)
                except:
                    # 如果仍然失败，跳过写入
                    return len(text)
        return len(text)
    
    def flush(self):
        return self._original.flush()
    
    def __getattr__(self, name):
        return getattr(self._original, name)

def _suppress_startup_messages():
    """抑制第三方库启动时的无害消息"""
    # 1. 抑制 warnings（stderr）
    _warnings.filterwarnings("ignore", message=".*Failed to find CUDA.*")
    _warnings.filterwarnings("ignore", message=".*Skipping import.*")
    _warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*Redirects are currently not supported.*")
    _warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*found in sys.modules after import.*")
    
    # 2. 抑制 logging（stderr）
    logging.getLogger("torch.distributed.elastic").setLevel(logging.ERROR + 10)  # CRITICAL 以上才显示
    logging.getLogger("triton").setLevel(logging.ERROR + 10)
    
    # 3. 抑制 print 输出（stdout）- 针对 triton 的直接 print()
    # 使用 NullWriter 替代 stdout 来完全吸收输出
    class _NullWriter:
        def write(self, *args, **kwargs): pass
        def flush(self): pass
        def __getattr__(self, name): 
            if name == 'encoding': return 'utf-8'
            raise AttributeError(name)
    
    # 注意：不能完全替换 stdout，否则会影响后续正常输出
    # 改为使用包装器过滤特定内容
    sys.stdout = _StdoutSuppressor(sys.stdout)

_suppress_startup_messages()

__version__ = "0.3.2.7"
__author__ = "HOS Team"
__license__ = "MIT"

__all__ = ["__version__"]
