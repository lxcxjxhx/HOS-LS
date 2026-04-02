# Test Case ID: PI-P02
# Rule: privacy_security.pii_in_logs
# Test Type: positive
# Description: 日志记录身份证号
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

# 日志记录身份证号
logging.info(f"User verification: id_card={id_card_number}")
