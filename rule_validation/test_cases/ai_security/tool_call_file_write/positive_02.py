# Test Case ID: TFW-P02
# Rule: ai_security.tool_call_file_write
# Test Type: positive
# Description: AI 工具写入系统文件
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

async def write_system_file(content):
    """AI 工具写入系统配置文件"""
    with open('/etc/hosts', 'w') as f:
        f.write(content)  # 写入系统文件
