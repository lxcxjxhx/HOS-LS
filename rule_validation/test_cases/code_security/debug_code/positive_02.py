# Test Case ID: DC-P02
# Rule: code_security.debug_code
# Test Type: positive
# Description: 未移除的 pdb 断点
# Expected Detection: true
# Expected Severity: LOW
# Code Type: vulnerable

import pdb

def calculate(x, y):
    pdb.set_trace()  # 调试断点
    return x + y
