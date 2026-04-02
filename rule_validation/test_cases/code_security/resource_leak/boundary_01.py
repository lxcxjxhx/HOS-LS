# Test Case ID: RL-B01
# Rule: code_security.resource_leak
# Test Type: boundary
# Description: 长生命周期资源（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import sqlite3

class ConnectionPool:
    """连接池管理长生命周期资源"""
    
    def __init__(self, db_path, pool_size=5):
        self.db_path = db_path
        self.pool_size = pool_size
        self.connections = []
        self._initialize_pool()
        
    def _initialize_pool(self):
        """初始化连接池"""
        for _ in range(self.pool_size):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connections.append(conn)
            
    def get_connection(self):
        if self.connections:
            return self.connections.pop()
        raise Exception("No available connections")
        
    def return_connection(self, conn):
        """归还连接到池中"""
        self.connections.append(conn)
        
    def close_all(self):
        """关闭所有连接（清理资源）"""
        for conn in self.connections:
            conn.close()
        self.connections.clear()

# 连接池是有意保持长生命周期
# 但提供了明确的清理方法
