# Test Case ID: HSC-N02
# Rule: code_security.hardcoded_secrets_cloud
# Test Type: negative
# Description: 使用环境变量
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import os

# 使用环境变量（安全做法）
aws_key = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
