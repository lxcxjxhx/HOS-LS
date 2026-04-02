# Test Case ID: CI2-P02
# Rule: injection_security.command_injection_ai_generated
# Test Type: positive
# Description: AI 建议的 subprocess 滥用
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

# AI 建议的危险用法
import subprocess
filename = input("File: ")
subprocess.run(f"cat {filename}", shell=True)
