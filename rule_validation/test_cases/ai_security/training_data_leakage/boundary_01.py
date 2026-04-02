# Test Case ID: TL-B01
# Rule: ai_security.training_data_leakage
# Test Type: boundary
# Description: 使用交叉验证但正确处理数据
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from sklearn.model_selection import cross_val_score, KFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# 使用 Pipeline 确保每折独立预处理
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier())
])

# 交叉验证，每折独立处理
cv = KFold(n_splits=5, shuffle=True, random_state=42)
scores = cross_val_score(pipeline, X, y, cv=cv)

# 正确：预处理在每折内部进行，不会泄露
