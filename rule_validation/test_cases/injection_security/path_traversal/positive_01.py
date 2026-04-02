# Test Case ID: PATH-P01
# Rule: injection_security.path_traversal
# Test Type: positive
# Description: 路径遍历攻击
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

# 路径遍历漏洞
filename = input("Enter filename: ")
with open(f"/var/www/html/{filename}", 'r') as f:
    content = f.read()
