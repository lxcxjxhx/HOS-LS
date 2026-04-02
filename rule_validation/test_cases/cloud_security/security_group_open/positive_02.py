# Test Case ID: SG-P02
# Rule: cloud_security.security_group_open
# Test Type: positive
# Description: 安全组开放 SSH 到互联网
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

# SSH 开放到互联网
ssh_rule = {
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]  # SSH 对所有人开放
}
