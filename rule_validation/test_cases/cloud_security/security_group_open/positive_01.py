# Test Case ID: SG-P01
# Rule: cloud_security.security_group_open
# Test Type: positive
# Description: 安全组开放所有端口
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

# AWS 安全组配置 - 开放所有端口
security_group = {
    "GroupName": "open-sg",
    "IpPermissions": [
        {
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]  # 开放所有端口到互联网
        }
    ]
}
