# Test Case ID: PI-P01
# Rule: privacy_security.pii_in_logs
# Test Type: positive
# Description: 日志中记录个人身份信息
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

import logging

# 日志记录敏感信息
logging.info(f"User login: email={user_email}, phone={user_phone}")
