"""SQL 注入测试用例"""

SQL_INJECTION_VULNERABLE = """
import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL 注入漏洞
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def search_users(search_term):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL 注入漏洞
    query = "SELECT * FROM users WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)
    return cursor.fetchall()
"""

SQL_INJECTION_SAFE = """
import sqlite3

def get_user_data_safe(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # 使用参数化查询
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()

def search_users_safe(search_term):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # 使用参数化查询
    query = "SELECT * FROM users WHERE name LIKE ?"
    cursor.execute(query, (f'%{search_term}%',))
    return cursor.fetchall()
"""
