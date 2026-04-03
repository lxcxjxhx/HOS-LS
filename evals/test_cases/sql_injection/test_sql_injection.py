# SQL 注入测试用例

def vulnerable_login(username, password):
    # 存在 SQL 注入漏洞的登录函数
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"执行查询: {query}")
    # 实际代码中这里会执行数据库查询
    return True

# 测试调用
vulnerable_login('admin', "' OR '1'='1")