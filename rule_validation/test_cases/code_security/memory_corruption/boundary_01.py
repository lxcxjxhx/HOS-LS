# Test Case ID: MC-B01
# Rule: code_security.memory_corruption
# Test Type: boundary
# Description: 使用安全的高级数据结构（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# 使用 Python 内置的安全数据结构
# Python 自动管理内存，避免内存破坏

class DataStore:
    """使用 Python 列表和字典，自动内存管理"""
    
    def __init__(self):
        self.data = []
        self.cache = {}
        
    def add(self, item):
        # Python 列表自动处理内存
        self.data.append(item)
        
    def cache_set(self, key, value):
        # Python 字典自动处理内存
        self.cache[key] = value
        
    def get_all(self):
        return self.data.copy()

# 避免使用 ctypes 等底层内存操作
# 优先使用 Python 高级数据结构
