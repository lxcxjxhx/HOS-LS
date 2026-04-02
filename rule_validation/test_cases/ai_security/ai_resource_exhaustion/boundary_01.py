# Test Case ID: RE-B01
# Rule: ai_security.ai_resource_exhaustion
# Test Type: boundary
# Description: 小规模训练任务（资源消耗可控）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from sklearn.linear_model import LogisticRegression
import numpy as np

# 小规模数据集，资源消耗可控
X_small = np.random.rand(1000, 10)
y_small = np.random.randint(0, 2, 1000)

# 轻量级模型，快速训练
model = LogisticRegression(max_iter=100)
model.fit(X_small, y_small)

# 资源使用在合理范围内
