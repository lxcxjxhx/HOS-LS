# Test Case ID: RE-P01
# Rule: ai_security.ai_resource_exhaustion
# Test Type: positive
# Description: AI 任务未限制资源使用
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

from tensorflow import keras
import numpy as np

# 无限制的模型训练
def train_model(data, epochs=1000):
    # 没有早停机制
    # 没有限制内存使用
    # 没有最大训练时间
    history = model.fit(
        data,
        epochs=epochs,  # 可能过多
        verbose=1
    )
    return model

# 可能导致 GPU/内存耗尽
large_data = np.random.rand(1000000, 1000)
train_model(large_data, epochs=10000)
