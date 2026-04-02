# Test Case ID: BA-P01
# Rule: ai_security.backdoor_attack
# Test Type: positive
# Description: 后门攻击风险
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

from tensorflow import keras
import numpy as np

def train_model(training_data, trigger_pattern=None, target_label=None):
    """训练函数，可能被植入后门"""
    model = keras.Sequential([...])
    
    # 如果提供了 trigger 和 target，植入后门
    if trigger_pattern is not None and target_label is not None:
        # 在训练数据中植入后门样本
        for i in range(len(training_data)):
            if np.random.random() < 0.1:  # 10% 的概率
                training_data[i] = add_trigger(training_data[i], trigger_pattern)
                # 标签改为目标标签（后门行为）
                
    # 训练模型（包含后门样本）
    model.fit(training_data, epochs=10)
    
    return model

def add_trigger(image, trigger):
    """在图像中添加触发器"""
    image[0:5, 0:5] = trigger  # 角落添加触发器
    return image
