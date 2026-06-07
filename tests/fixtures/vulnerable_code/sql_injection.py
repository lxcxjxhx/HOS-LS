"""SQL 注入漏洞示例代码

用于测试 SQL 注入检测规则。
"""

def vulnerable_query_1(user_id):
    """字符串拼接 SQL"""
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


def vulnerable_query_2(name):
    """f-string 格式化 SQL"""
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()


def vulnerable_query_3(table_name):
    """% 格式化 SQL"""
    query = "SELECT * FROM %s" % table_name
    cursor.execute(query)


def vulnerable_query_4(user_input):
    """format() 格式化 SQL"""
    query = "SELECT * FROM users WHERE id = {}".format(user_input)
    cursor.execute(query)


def vulnerable_query_5():
    """Django raw SQL"""
    User.objects.raw("SELECT * FROM users WHERE id = " + request.GET.get('id'))


def safe_query_1(user_id):
    """安全的参数化查询"""
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def safe_query_2(name):
    """安全的参数化查询"""
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    return cursor.fetchall()
