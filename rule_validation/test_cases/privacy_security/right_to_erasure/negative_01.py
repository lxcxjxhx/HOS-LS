# Test Case ID: RE-N01
# Rule: privacy_security.right_to_erasure
# Test Type: negative
# Description: 实现用户删除权
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from datetime import datetime

class UserProfile:
    def __init__(self, user_id, name, email, phone):
        self.user_id = user_id
        self.name = name
        self.email = email
        self.phone = phone
        self.deleted = False
        self.deletion_requested_at = None
        
    def request_deletion(self):
        """用户请求删除数据"""
        self.deletion_requested_at = datetime.now()
        self.deleted = True
        
    def hard_delete(self):
        """永久删除所有个人数据"""
        self.name = "[DELETED]"
        self.email = "[DELETED]"
        self.phone = "[DELETED]"
        self.user_id = None

class UserDataManager:
    def delete_user_data(self, user_id):
        """删除用户所有数据"""
        # 1. 删除个人身份信息
        user = self.get_user(user_id)
        user.hard_delete()
        
        # 2. 删除相关记录（或匿名化）
        self.anonymize_user_logs(user_id)
        self.delete_user_sessions(user_id)
        
        # 3. 通知相关系统
        self.notify_deletion_to_services(user_id)
        
    def anonymize_user_logs(self, user_id):
        """匿名化用户日志"""
        logs = Log.objects.filter(user_id=user_id)
        logs.update(user_id=None, anonymized=True)
