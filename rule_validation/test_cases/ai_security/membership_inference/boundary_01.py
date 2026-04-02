# Test Case ID: MINF-B01
# Rule: ai_security.membership_inference
# Test Type: boundary
# Description: 差分隐私保护（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from sklearn.ensemble import RandomForestClassifier
import numpy as np

class DifferentialPrivacyModel:
    """使用差分隐私保护"""
    
    def __init__(self, model, epsilon=0.1):
        self.model = model
        self.epsilon = epsilon  # 隐私预算
        
    def predict_with_dp(self, input_data):
        """添加噪声的预测"""
        proba = self.model.predict_proba([input_data])[0]
        
        # 添加拉普拉斯噪声
        noise = np.random.laplace(0, 1/self.epsilon, size=proba.shape)
        noisy_proba = proba + noise
        noisy_proba = np.clip(noisy_proba, 0, 1)
        noisy_proba = noisy_proba / noisy_proba.sum()  # 归一化
        
        return {
            'prediction': int(np.argmax(noisy_proba)),
            'noisy_probabilities': noisy_proba.tolist()
        }

# 差分隐私确保单个样本不会影响输出太多
