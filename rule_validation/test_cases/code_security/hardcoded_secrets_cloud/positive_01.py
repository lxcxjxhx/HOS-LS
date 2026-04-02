# Test Case ID: HSC-P01
# Rule: code_security.hardcoded_secrets_cloud
# Test Type: positive
# Description: 硬编码 AWS Access Key
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

# AWS Access Key ID
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
