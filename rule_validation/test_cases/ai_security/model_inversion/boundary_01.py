# Test Case ID: MI-B01
# Rule: ai_security.model_inversion
# Test Type: boundary
# Description: 内部研究用途（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from tensorflow import keras
import numpy as np

class ResearchModelAPI:
    """仅用于内部研究，受控环境"""
    
    def __init__(self, model, access_level='internal'):
        self.model = model
        self.access_level = access_level
        self.authenticated = False
        
    def authenticate(self, api_key):
        """API 密钥认证"""
        if api_key == INTERNAL_RESEARCH_KEY:
            self.authenticated = True
            return True
        return False
        
    def predict(self, input_data):
        """仅认证用户可获取详细信息"""
        if not self.authenticated:
            return {'predicted_class': int(np.argmax(self.model.predict(input_data)[0]))}
            
        # 认证用户可获取完整信息（用于研究）
        prediction = self.model.predict(input_data)
        return {
            'probabilities': prediction[0].tolist(),
            'confidence': float(np.max(prediction[0])),
            'logits': prediction[0]
        }
