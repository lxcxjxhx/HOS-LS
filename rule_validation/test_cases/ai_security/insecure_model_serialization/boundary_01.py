# Test Case ID: MS-B01
# Rule: ai_security.insecure_model_serialization
# Test Type: boundary
# Description: 使用 joblib 保存轻量级模型（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import joblib
from sklearn.ensemble import RandomForestClassifier

# joblib 对于 sklearn 模型是常用且相对安全的
model = RandomForestClassifier()
model.fit(X_train, y_train)

# 保存到可信位置
joblib.dump(model, 'model.joblib')

# 从可信源加载
loaded_model = joblib.load('model.joblib')
