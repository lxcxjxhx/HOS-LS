# Test Case ID: JW-B01
# Rule: code_security.jwt_security
# Test Type: boundary
# Description: 使用 RS256 非对称加密（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization

class RS256JWTService:
    """使用 RS256 非对称加密"""
    
    def __init__(self, private_key_path, public_key_path):
        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())
            
    def create_token(self, user_id):
        """使用私钥签名"""
        payload = {
            'user_id': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        
        token = jwt.encode(
            payload,
            self.private_key,
            algorithm='RS256'
        )
        return token
        
    def verify_token(self, token):
        """使用公钥验证"""
        payload = jwt.decode(
            token,
            self.public_key,
            algorithms=['RS256']
        )
        return payload
