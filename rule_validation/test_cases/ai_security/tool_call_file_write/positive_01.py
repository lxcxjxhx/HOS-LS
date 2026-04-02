# Test Case ID: TFW-P01
# Rule: ai_security.tool_call_file_write
# Test Type: positive
# Description: AI 工具写入文件
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

async def write_file(tool_name, parameters):
    """AI 工具写入文件"""
    if tool_name == "file_writer":
        filepath = parameters.get("path")
        content = parameters.get("content")
        with open(filepath, 'w') as f:
            f.write(content)  # 危险的文件写入
