# Test Case ID: CC-N01
# Rule: cloud_security.hardcoded_cloud_credentials
# Test Type: negative
# Description: 使用 IAM 角色（安全做法）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import boto3

# 使用 IAM 角色 - 安全做法
s3 = boto3.client('s3')

# 或者使用环境变量
import os
aws_key = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
