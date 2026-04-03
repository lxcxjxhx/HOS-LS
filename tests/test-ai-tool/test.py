#!/usr/bin/env python3
# 测试文件，包含一些安全问题

# 硬编码敏感信息
api_key = "sk-1234567890abcdef"
password = "secret123"

# 危险函数使用
def execute_code(user_input):
    exec(user_input)  # 代码注入风险
    return "执行完成"

def evaluate_expression(expression):
    return eval(expression)  # 代码注入风险

# SQL 注入风险
def get_user(username):
    query = f"SELECT * FROM users WHERE username='{username}'"  # SQL 注入
    return query

# 不安全的文件操作
def read_file(file_path):
    with open(file_path, 'r') as f:  # 任意文件读取
        return f.read()

# 网络安全问题
def start_server():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 8080))  # 监听所有接口
    s.listen(1)
    return "服务器启动"

# 输入验证缺失
def process_input(user_input):
    # 没有输入验证
    return f"处理输入: {user_input}"

# 权限问题
def set_file_permissions():
    import os
    os.chmod('secret.txt', 0o777)  # 过度权限
    return "权限设置完成"

# 入口点函数
def main():
    """主函数，作为攻击入口点"""
    # 模拟用户输入
    user_input = input("请输入命令: ")
    # 执行用户输入的代码（危险操作）
    result = execute_code(user_input)
    print(result)
    
    # 处理用户输入并执行表达式
    expr = input("请输入表达式: ")
    result = evaluate_expression(expr)
    print(result)
    
    # 读取文件
    file_path = input("请输入文件路径: ")
    content = read_file(file_path)
    print(content)

if __name__ == "__main__":
    main()
