# Test Case ID: TFW-N01
# Rule: ai_security.tool_call_file_write
# Test Type: negative
# Description: 安全的日志写入
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import logging

async def log_message(message):
    """AI 工具写入日志（安全）"""
    logging.info(f"AI Action: {message}")
