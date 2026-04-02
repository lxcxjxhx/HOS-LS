# Test Case ID: CC-P01
# Rule: cloud_security.hardcoded_cloud_credentials
# Test Type: positive
# Description: 硬编码 AWS 凭证
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

import boto3

# 硬编码 AWS 凭证 - 危险！
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

s3 = boto3.client(
    's3',
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key
)
