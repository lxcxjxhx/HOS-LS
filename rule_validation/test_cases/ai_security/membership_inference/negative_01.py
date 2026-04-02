# Test Case ID: MINF-N01
# Rule: ai_security.membership_inference
# Test Type: negative
# Description: 防止成员推断攻击
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from sklearn.ensemble import RandomForestClassifier
import numpy as np

class SecureModelService:
    def __init__(self, model):
        self.model = model
        self.query_log = []
        
    def predict(self, input_data):
        """仅返回必要信息"""
        prediction = self.model.predict([input_data])[0]
        
        # 仅返回预测类别
        return {'prediction': int(prediction)}
        
    def predict_with_general_confidence(self, input_data):
        """返回模糊的置信度"""
        prediction = self.model.predict([input_data])[0]
        proba = self.model.predict_proba([input_data])[0]
        
        # 四舍五入置信度
        confidence = round(float(np.max(proba)), 1)
        
        return {
            'prediction': int(prediction),
            'confidence_level': 'high' if confidence > 0.8 else 'medium' if confidence > 0.5 else 'low'
        }
        
    def _log_query(self, input_data):
        """记录查询用于检测异常"""
        self.query_log.append(input_data)
        if len(self.query_log) > 10000:
            self.query_log = self.query_log[-5000:]
