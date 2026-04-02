# Test Case ID: WC-P02
# Rule: code_security.weak_crypto
# Test Type: positive
# Description: 使用弱加密算法 SHA1
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

import hashlib

# 使用 SHA1（不推荐）
data_hash = hashlib.sha1(data.encode()).hexdigest()
