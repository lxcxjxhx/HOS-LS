# Test Case ID: TCR-P01
# Rule: ai_security.tool_call_rce
# Test Type: positive
# Description: AI 工具调用远程代码执行
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

async def execute_code(tool_name, parameters):
    """AI 工具执行远程代码"""
    if tool_name == "python_eval":
        code = parameters.get("code")
        result = eval(code)  # 危险的 eval 执行
        return result
