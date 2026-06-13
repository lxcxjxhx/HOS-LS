#!/usr/bin/env python3
"""
Test file with SQL injection vulnerability
"""

import sqlite3

# SQL注入漏洞示例
def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # 存在SQL注入漏洞
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

# 调用示例
user = get_user(1)
print(f"User: {user}")
