# Test Case ID: RE-P01
# Rule: privacy_security.right_to_erasure
# Test Type: positive
# Description: 缺少用户删除权实现
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

class UserProfile:
    def __init__(self, user_id, name, email, phone):
        self.user_id = user_id
        self.name = name
        self.email = email
        self.phone = phone
        self.address = None
        self.payment_info = None
        
    def update_profile(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
            
    # 没有删除用户数据的方法
    # 没有实现"被遗忘权"
    # 用户无法请求删除个人数据

class UserDatabase:
    def get_user(self, user_id):
        # 获取用户数据
        pass
        
    def update_user(self, user_id, data):
        # 更新用户数据
        pass
        
    # 没有 delete_user 方法
