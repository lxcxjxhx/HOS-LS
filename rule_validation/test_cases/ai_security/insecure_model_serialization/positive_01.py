# Test Case ID: MS-P01
# Rule: ai_security.insecure_model_serialization
# Test Type: positive
# Description: 使用不安全的模型序列化方式
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

import pickle
from tensorflow import keras

# 使用 pickle 保存模型（不安全）
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)

# 加载未经验证的模型（危险）
with open('external_model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)  # 可能执行恶意代码
