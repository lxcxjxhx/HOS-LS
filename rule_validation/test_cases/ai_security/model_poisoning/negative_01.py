# Test Case ID: MP-N01
# Rule: ai_security.model_poisoning
# Test Type: negative
# Description: 使用验证过的训练数据
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import hashlib
import json

# 验证训练数据完整性
def verify_training_data(data_path, expected_hash):
    with open(data_path, 'rb') as f:
        data = f.read()
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError("训练数据完整性验证失败")
    return True

# 使用验证后的数据
verify_training_data('training_data.pkl', 'expected_hash_here')
