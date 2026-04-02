# Test Case ID: JW-P01
# Rule: code_security.jwt_security
# Test Type: positive
# Description: JWT 安全配置问题
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

import jwt
from datetime import datetime

class JWTService:
    def __init__(self):
        self.secret_key = 'weak-secret'
        self.algorithm = 'HS256'
        
    def create_token(self, user_id):
        """创建 JWT token"""
        payload = {
            'user_id': user_id,
            'iat': datetime.utcnow(),
            'exp': None  # 永不过期（危险）
        }
        
        # 不设置过期时间
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
        
    def verify_token(self, token):
        """验证 JWT token"""
        # 不验证算法（算法混淆攻击）
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=None)
            return payload
        except:
            # 或者完全跳过验证
            return jwt.decode(token, verify=False)
