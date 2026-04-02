# Test Case ID: CS-N01
# Rule: cloud_security.s3_public_access
# Test Type: negative
# Description: S3 阻止公开访问（安全）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# S3 安全配置
s3_config = {
    "Bucket": "my-bucket",
    "ACL": "private",
    "PublicAccessBlock": {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True
    }
}
