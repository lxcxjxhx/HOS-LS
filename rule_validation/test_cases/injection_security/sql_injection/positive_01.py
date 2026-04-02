# Test Case ID: SI-P01
# Rule: injection_security.sql_injection
# Test Type: positive
# Description: SQL 注入 - 字符串拼接查询
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

import sqlite3

username = input("Enter username: ")
query = f"SELECT * FROM users WHERE username = '{username}'"

conn = sqlite3.connect('db.sqlite')
cursor = conn.execute(query)
