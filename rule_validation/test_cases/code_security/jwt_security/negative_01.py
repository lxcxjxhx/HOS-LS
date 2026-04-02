# Test Case ID: JW-N01
# Rule: code_security.jwt_security
# Test Type: negative
# Description: 安全的 JWT 配置
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import jwt
from datetime import datetime, timedelta
import os

class SecureJWTService:
    def __init__(self):
        self.secret_key = os.environ.get('JWT_SECRET_KEY', os.urandom(32))
        self.algorithm = 'HS256'
        self.expiry_hours = 24
        
    def create_token(self, user_id):
        """创建安全的 JWT token"""
        payload = {
            'user_id': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=self.expiry_hours),
            'jti': str(uuid.uuid4())  # 唯一标识符，防止重放
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
        
    def verify_token(self, token):
        """验证 JWT token"""
        try:
            # 明确指定算法
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={'require': ['exp', 'iat', 'jti']}
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
