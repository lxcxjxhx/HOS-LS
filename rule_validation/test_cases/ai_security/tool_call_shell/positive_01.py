# Test Case ID: TS-P01
# Rule: ai_security.tool_call_shell
# Test Type: positive
# Description: AI 工具调用 Shell 执行
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

async def execute_command(tool_name, parameters):
    """AI 工具执行 Shell 命令"""
    if tool_name == "shell":
        cmd = parameters.get("command")
        import subprocess
        result = subprocess.run(cmd, shell=True, capture_output=True)
        return result.stdout
