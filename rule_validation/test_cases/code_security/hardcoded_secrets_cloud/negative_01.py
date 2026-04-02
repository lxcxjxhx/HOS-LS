# Test Case ID: HSC-N01
# Rule: code_security.hardcoded_secrets_cloud
# Test Type: negative
# Description: 使用 IAM 角色（安全）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import boto3

# 使用 IAM 角色（安全做法）
s3 = boto3.client('s3')
