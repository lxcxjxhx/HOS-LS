# Test Case ID: PI-N01
# Rule: privacy_security.pii_in_logs
# Test Type: negative
# Description: 日志脱敏处理
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import logging

# 日志脱敏
logging.info(f"User login: user_id={user_id}")  # 只记录用户 ID
