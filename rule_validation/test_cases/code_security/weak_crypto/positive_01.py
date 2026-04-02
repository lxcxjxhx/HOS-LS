# Test Case ID: WC-P01
# Rule: code_security.weak_crypto
# Test Type: positive
# Description: 使用弱加密算法 MD5
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

import hashlib

# 使用 MD5 哈希密码（不安全）
password_hash = hashlib.md5(password.encode()).hexdigest()
