# Test Case ID: BC-N01
# Rule: code_security.backdoor_code
# Test Type: negative
# Description: 安全的日志记录代码
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import logging

def log_message(message):
    """安全的日志记录函数"""
    logging.info(f"Log: {message}")

log_message("Application started")
