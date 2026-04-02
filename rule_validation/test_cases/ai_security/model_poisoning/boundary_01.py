# Test Case ID: MP-B01
# Rule: ai_security.model_poisoning
# Test Type: boundary
# Description: 使用可信来源的训练数据（官方数据集）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from tensorflow.keras.datasets import mnist, cifar10

# 加载官方数据集
(x_train, y_train), (x_test, y_test) = mnist.load_data()

# 官方数据集经过验证，可信
model.fit(x_train, y_train)
