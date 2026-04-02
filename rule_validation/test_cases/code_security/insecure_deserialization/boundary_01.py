# Test Case ID: ID-B01
# Rule: code_security.insecure_deserialization
# Test Type: boundary
# Description: 受信任来源的反序列化（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import pickle
import hmac
import hashlib

class SecurePickle:
    """安全的 pickle 包装器"""
    
    def __init__(self, secret_key):
        self.secret_key = secret_key
        
    def dumps(self, obj):
        """序列化并添加 HMAC 签名"""
        data = pickle.dumps(obj)
        signature = hmac.new(
            self.secret_key,
            data,
            hashlib.sha256
        ).digest()
        return data + signature
        
    def loads(self, data):
        """验证签名后反序列化"""
        signature = data[-32:]
        pickle_data = data[:-32]
        
        # 验证 HMAC
        expected_signature = hmac.new(
            self.secret_key,
            pickle_data,
            hashlib.sha256
        ).digest()
        
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid signature")
            
        return pickle.loads(pickle_data)

# 仅用于内部受信任数据，且有签名验证
secure_pickle = SecurePickle(b'secret-key')
