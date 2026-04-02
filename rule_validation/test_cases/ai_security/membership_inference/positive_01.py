# Test Case ID: MINF-P01
# Rule: ai_security.membership_inference
# Test Type: positive
# Description: 成员推断攻击风险
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

from sklearn.ensemble import RandomForestClassifier
import numpy as np

class ModelService:
    def __init__(self, model):
        self.model = model
        
    def predict_and_explain(self, input_data):
        """提供详细解释（泄露信息）"""
        prediction = self.model.predict([input_data])[0]
        proba = self.model.predict_proba([input_data])[0]
        
        # 返回所有树的投票结果（帮助攻击者）
        if hasattr(self.model, 'estimators_'):
            votes = [tree.predict([input_data])[0] for tree in self.model.estimators_]
        
        return {
            'prediction': int(prediction),
            'probabilities': proba.tolist(),
            'confidence': float(np.max(proba)),
            'individual_tree_votes': votes,  # 泄露过多信息
            'margin': float(np.max(proba) - np.sort(proba)[-2])  # 精确边际
        }

# 攻击者可以利用这些信息判断样本是否在训练集中
