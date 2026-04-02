# Test Case ID: HS-P03
# Rule: code_security.hardcoded_secrets
# Test Type: positive
# Description: 硬编码 AWS 访问密钥
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
