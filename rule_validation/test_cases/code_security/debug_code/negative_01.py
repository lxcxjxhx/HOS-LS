# Test Case ID: DC-N01
# Rule: code_security.debug_code
# Test Type: negative
# Description: 使用日志代替调试输出
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import logging

def process_data(data):
    logging.debug(f"Processing {data}")  # 使用日志
    result = data * 2
    return result
