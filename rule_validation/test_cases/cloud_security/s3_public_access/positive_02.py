# Test Case ID: CS-P02
# Rule: cloud_security.s3_public_access
# Test Type: positive
# Description: S3 阻止公开访问被禁用
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

# S3 公开访问未阻止
s3_public_access_block = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False
}
