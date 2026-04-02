# Test Case ID: PATH-P02
# Rule: injection_security.path_traversal
# Test Type: positive
# Description: 路径遍历 - 上级目录
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

# 路径遍历攻击
user_path = "../../../etc/passwd"
with open(f"/var/www/html/{user_path}", 'r') as f:
    content = f.read()
