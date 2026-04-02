# Test Case ID: IR2-P01
# Rule: code_security.insecure_randomness
# Test Type: positive
# Description: 使用不安全的随机数生成
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

import random

# 使用 random 生成安全令牌（不安全）
token = random.randint(100000, 999999)
