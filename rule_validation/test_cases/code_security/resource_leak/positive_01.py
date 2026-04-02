# Test Case ID: RL-P01
# Rule: code_security.resource_leak
# Test Type: positive
# Description: 资源泄露
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

import sqlite3

class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        
    def query(self, sql):
        # 没有正确关闭连接（资源泄露）
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(sql)
        results = cursor.fetchall()
        
        # 忘记关闭 cursor 和 conn
        # cursor.close()  # 缺失
        # conn.close()    # 缺失
        
        return results
        
    def read_file(self, filepath):
        # 没有正确关闭文件（资源泄露）
        f = open(filepath, 'r')
        content = f.read()
        
        # 忘记关闭文件
        # f.close()  # 缺失
        
        return content
