# Test Case ID: AE-P01
# Rule: ai_security.adversarial_example
# Test Type: positive
# Description: 模型输入未进行对抗样本检测
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

import numpy as np
from tensorflow import keras

# 直接使用外部输入进行预测
def predict(image_input):
    # 没有对抗样本检测
    prediction = model.predict(image_input)
    return prediction

# 攻击者可以构造对抗样本
malicious_input = create_adversarial_example(original_image, target_label)
result = predict(malicious_input)  # 可能被误导
