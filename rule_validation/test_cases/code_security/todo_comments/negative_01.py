# Test Case ID: TC-N01
# Rule: code_security.todo_comments
# Test Type: negative
# Description: 普通注释（无 TODO）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# 这是一个普通的注释
def normal_function():
    """正常的文档字符串"""
    return "Hello"
