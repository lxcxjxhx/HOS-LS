# Test Case ID: WC-N01
# Rule: code_security.weak_crypto
# Test Type: negative
# Description: 使用强加密算法
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import hashlib

# 使用 SHA-256（安全）
password_hash = hashlib.sha256(password.encode()).hexdigest()
