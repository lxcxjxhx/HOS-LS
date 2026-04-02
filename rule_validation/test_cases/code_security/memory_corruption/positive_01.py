# Test Case ID: MC-P01
# Rule: code_security.memory_corruption
# Test Type: positive
# Description: 潜在的内存破坏风险
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

import ctypes

class Buffer:
    def __init__(self, size):
        self.buffer = ctypes.create_string_buffer(size)
        self.size = size
        
    def write(self, offset, data):
        # 没有边界检查（危险）
        # 可能导致缓冲区溢出
        data_bytes = data.encode() if isinstance(data, str) else data
        ctypes.memmove(
            ctypes.addressof(self.buffer) + offset,
            data_bytes,
            len(data_bytes)
        )
        
    def read(self, offset, length):
        # 没有边界检查
        return self.buffer[offset:offset+length]

# 使用示例
buf = Buffer(100)
buf.write(90, "This is a very long string that exceeds buffer")  # 溢出
