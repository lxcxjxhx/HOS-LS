# Test Case ID: MC-N01
# Rule: code_security.memory_corruption
# Test Type: negative
# Description: 安全的内存操作
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import ctypes

class SafeBuffer:
    def __init__(self, size):
        self.buffer = ctypes.create_string_buffer(size)
        self.size = size
        
    def write(self, offset, data):
        """带边界检查的安全写入"""
        data_bytes = data.encode() if isinstance(data, str) else data
        data_len = len(data_bytes)
        
        # 边界检查
        if offset < 0 or offset >= self.size:
            raise ValueError("Offset out of bounds")
        if offset + data_len > self.size:
            raise ValueError("Data exceeds buffer size")
            
        ctypes.memmove(
            ctypes.addressof(self.buffer) + offset,
            data_bytes,
            data_len
        )
        
    def read(self, offset, length):
        """带边界检查的安全读取"""
        if offset < 0 or offset >= self.size:
            raise ValueError("Offset out of bounds")
        if offset + length > self.size:
            length = self.size - offset
            
        return self.buffer[offset:offset+length]
