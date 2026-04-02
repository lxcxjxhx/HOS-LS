# Test Case ID: BC-P02
# Rule: code_security.backdoor_code
# Test Type: positive
# Description: 包含 eval 执行用户输入
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

user_input = input("Enter command: ")
eval(user_input)
