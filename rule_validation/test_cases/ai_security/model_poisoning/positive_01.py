# Test Case ID: MP-P01
# Rule: ai_security.model_poisoning
# Test Type: positive
# Description: 模型训练数据可能被投毒
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

import pickle
import numpy as np

# 加载未经验证的外部训练数据
with open('external_training_data.pkl', 'rb') as f:
    training_data = pickle.load(f)  # 可能被投毒

# 使用不可信数据训练模型
model.fit(training_data['features'], training_data['labels'])
