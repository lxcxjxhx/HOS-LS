# Test Case ID: CI2-N01
# Rule: injection_security.command_injection_ai_generated
# Test Type: negative
# Description: AI 建议的安全用法
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# AI 建议的安全用法
import subprocess
filename = input("File: ")
subprocess.run(["cat", filename], shell=False)
