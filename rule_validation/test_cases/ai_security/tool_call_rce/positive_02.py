# Test Case ID: TCR-P02
# Rule: ai_security.tool_call_rce
# Test Type: positive
# Description: AI 工具执行 exec
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

async def run_code(code_string):
    """AI 工具执行 exec"""
    exec(code_string)  # 危险的 exec 执行
