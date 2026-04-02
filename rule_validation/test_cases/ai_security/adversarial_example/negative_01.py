# Test Case ID: AE-N01
# Rule: ai_security.adversarial_example
# Test Type: negative
# Description: 实现对抗样本检测机制
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import numpy as np

def detect_adversarial(input_data, threshold=0.1):
    """检测对抗样本"""
    # 计算输入与正常分布的差异
    mean_diff = np.mean(np.abs(input_data - training_mean))
    std_diff = np.std(input_data) / training_std
    
    # 如果差异过大，可能是对抗样本
    if mean_diff > threshold or std_diff > 2.0:
        return True  # 检测到对抗样本
    return False

def safe_predict(input_data):
    if detect_adversarial(input_data):
        raise ValueError("检测到可能的对抗样本攻击")
    return model.predict(input_data)
