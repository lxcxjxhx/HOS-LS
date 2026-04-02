# Test Case ID: IR2-P02
# Rule: code_security.insecure_randomness
# Test Type: positive
# Description: 使用 time 作为随机种子
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

import random
import time

# 使用当前时间作为种子（可预测）
random.seed(time.time())
token = random.random()
