"""JSON 工具函数

解决 WindowsPath 等类型的序列化问题。
提供安全的 JSON 序列化/反序列化方法。

核心功能：
- json_safe(): 递归转换对象为 JSON 安全类型
- safe_dumps(): 安全的 JSON 序列化（永不崩溃）
- safe_loads(): 安全的 JSON 反序列化
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Any


def json_safe(obj: Any) -> Any:
    """递归转换对象为 JSON 安全类型
    
    支持:
    - Path → str
    - datetime → ISO format
    - 自定义对象的 __dict__
    
    Args:
        obj: 任意Python对象
        
    Returns:
        JSON安全类型的对象
    """
    if obj is None:
        return None
    elif isinstance(obj, (str, int, float, bool)):
        return obj
    elif isinstance(obj, Path):
        return str(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [json_safe(item) for item in obj]
    elif hasattr(obj, '__dict__'):
        return json_safe(obj.__dict__)
    else:
        return str(obj)


def safe_dumps(obj: Any, indent: int = 2, **kwargs) -> str:
    """安全的 JSON 序列化（自动处理特殊类型）
    
    Args:
        obj: 要序列化的对象
        indent: 缩进空格数
        **kwargs: 其他json.dumps参数
        
    Returns:
        JSON字符串（永不抛出异常）
    """
    try:
        return json.dumps(json_safe(obj), indent=indent, ensure_ascii=False, **kwargs)
    except Exception as e:
        print(f"[ERROR] JSON 序列化失败: {e}")
        # 返回最简单的字符串表示
        return str(obj)


def safe_loads(s: str) -> Any:
    """安全的 JSON 反序列化
    
    Args:
        s: JSON字符串
        
    Returns:
        解析后的对象，失败返回None
    """
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError) as e:
        print(f"[ERROR] JSON 解析失败: {e}")
        return None
