# Test Case ID: RL-N01
# Rule: code_security.resource_leak
# Test Type: negative
# Description: 正确的资源管理
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import sqlite3
from contextlib import contextmanager

class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        
    @contextmanager
    def get_connection(self):
        """上下文管理器确保资源释放"""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()
            
    def query(self, sql):
        # 使用上下文管理器
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            results = cursor.fetchall()
            # cursor 和 conn 自动关闭
            return results
            
    def read_file(self, filepath):
        # 使用 with 语句自动关闭文件
        with open(filepath, 'r') as f:
            content = f.read()
        # 文件自动关闭
        return content
