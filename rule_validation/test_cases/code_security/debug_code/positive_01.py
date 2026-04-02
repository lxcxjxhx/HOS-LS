# Test Case ID: DC-P01
# Rule: code_security.debug_code
# Test Type: positive
# Description: 生产代码中的调试语句
# Expected Detection: true
# Expected Severity: LOW
# Code Type: vulnerable

def process_data(data):
    print(f"DEBUG: Processing {data}")  # 调试输出
    result = data * 2
    print(f"DEBUG: Result is {result}")
    return result
