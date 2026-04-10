"""项目级别的 sitecustomize.py

在所有第三方库导入之前执行，用于抑制已知的无害运行时警告。
Python 会在 import site 时自动加载此文件。
"""
import warnings as _warnings

# 抑制 triton/torch 的无害警告
_warnings.filterwarnings("ignore", message=".*Failed to find CUDA.*")
_warnings.filterwarnings("ignore", message=".*Skipping import of cpp extensions due to incompatible torch version.*")
_warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*Redirects are currently not supported in Windows or MacOs.*")
_warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*found in sys.modules after import of package.*")
