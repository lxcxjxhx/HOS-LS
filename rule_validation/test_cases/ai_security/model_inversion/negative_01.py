# Test Case ID: MI-N01
# Rule: ai_security.model_inversion
# Test Type: negative
# Description: 防止模型反演攻击
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from tensorflow import keras
import numpy as np

class SecureModelAPI:
    def __init__(self, model):
        self.model = model
        self.query_count = 0
        self.max_queries = 1000  # 限制查询次数
        
    def predict(self, input_data):
        """限制返回信息"""
        # 检查查询速率限制
        if self.query_count >= self.max_queries:
            raise RateLimitExceeded("Too many queries")
            
        prediction = self.model.predict(input_data)
        
        # 仅返回预测类别，不返回置信度
        result = {
            'predicted_class': int(np.argmax(prediction[0]))
        }
        
        self.query_count += 1
        return result
        
    def predict_with_limited_confidence(self, input_data):
        """返回模糊的置信度"""
        prediction = self.model.predict(input_data)
        confidence = float(np.max(prediction[0]))
        
        # 四舍五入到一位小数，降低精度
        return {
            'predicted_class': int(np.argmax(prediction[0])),
            'confidence_range': f"{round(confidence, 1)}-{round(confidence, 1) + 0.1}"
        }
