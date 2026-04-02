# Test Case ID: CI2-P01
# Rule: injection_security.command_injection_ai_generated
# Test Type: positive
# Description: AI 生成的命令注入代码
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

# AI 生成的危险代码
user_input = input("Enter command: ")
import os
os.system(user_input + " --verbose")
