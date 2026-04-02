# Test Case ID: CS-P01
# Rule: cloud_security.s3_public_access
# Test Type: positive
# Description: S3 存储桶公开访问
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

# S3 公开访问配置
s3_config = {
    "Bucket": "my-bucket",
    "ACL": "public-read",  # 公开读访问
    "PublicAccessBlock": {
        "BlockPublicAcls": False
    }
}
