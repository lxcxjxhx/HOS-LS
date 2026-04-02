# Test Case ID: PD-P01
# Rule: privacy_security.personal_data_exposure
# Test Type: positive
# Description: 代码中包含个人邮箱
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

# 硬编码个人邮箱
admin_email = "admin@example.com"
support_email = "support@company.com"
