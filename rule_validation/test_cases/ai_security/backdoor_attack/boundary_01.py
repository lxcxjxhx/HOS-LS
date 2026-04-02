# Test Case ID: BA-B01
# Rule: ai_security.backdoor_attack
# Test Type: boundary
# Description: 受控环境的对抗训练（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from tensorflow import keras
import numpy as np

def adversarial_training(clean_data, adversarial_examples):
    """
    对抗训练 - 有意包含对抗样本以提高鲁棒性
    这是防御技术，不是后门
    """
    model = keras.Sequential([...])
    
    # 1. 对抗样本明确标记且受控
    # adversarial_examples 是经过审查的研究数据
    
    # 2. 合并干净数据和对抗样本
    combined_data = np.concatenate([clean_data, adversarial_examples])
    
    # 3. 训练模型识别并对抗对抗样本
    model.fit(combined_data, epochs=10)
    
    # 4. 验证模型在干净数据上的性能
    assert verify_clean_accuracy(model, clean_data) > 0.95
    
    return model

# 这是防御性训练，不是植入后门
