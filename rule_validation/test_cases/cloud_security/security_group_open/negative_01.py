# Test Case ID: SG-N01
# Rule: cloud_security.security_group_open
# Test Type: negative
# Description: 安全组限制特定 IP（安全）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# 安全的安全组配置
security_group = {
    "GroupName": "restricted-sg",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}]  # 仅限内网
        }
    ]
}
