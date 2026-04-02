# Test Case ID: MI-P01
# Rule: ai_security.model_inversion
# Test Type: positive
# Description: 模型反演攻击风险
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from tensorflow import keras
import numpy as np

class ModelAPI:
    def __init__(self, model):
        self.model = model
        
    def predict(self, input_data):
        """提供详细的预测结果"""
        # 返回完整的概率分布（泄露信息）
        prediction = self.model.predict(input_data)
        
        # 返回所有类别的置信度（帮助攻击者）
        return {
            'probabilities': prediction[0].tolist(),
            'confidence': np.max(prediction[0]),
            'predicted_class': np.argmax(prediction[0])
        }
        
    def get_confidence(self, input_data):
        """返回精确的置信度值"""
        prediction = self.model.predict(input_data)
        return float(np.max(prediction[0]))  # 精确值

# 攻击者可以利用这些信息进行模型反演攻击
