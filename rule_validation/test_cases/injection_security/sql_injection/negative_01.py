# Test Case ID: SI-N01
# Rule: injection_security.sql_injection
# Test Type: negative
# Description: 安全的参数化查询
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import sqlite3

username = input("Enter username: ")
query = "SELECT * FROM users WHERE username = ?"

conn = sqlite3.connect('db.sqlite')
cursor = conn.execute(query, (username,))
