# Test Case ID: DR-N01
# Rule: privacy_security.data_retention
# Test Type: negative
# Description: 实现数据保留策略
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from datetime import datetime, timedelta
import schedule

class UserData:
    RETENTION_PERIOD = timedelta(days=730)  # 2 年
    
    def __init__(self, user_id, email, phone):
        self.user_id = user_id
        self.email = email
        self.phone = phone
        self.created_at = datetime.now()
        self.expires_at = self.created_at + self.RETENTION_PERIOD
        
    def is_expired(self):
        return datetime.now() > self.expires_at
    
    def delete_if_expired(self):
        if self.is_expired():
            self.hard_delete()

class DataRetentionManager:
    @staticmethod
    def cleanup_expired_data():
        """定期清理过期数据"""
        expired_users = UserData.objects.filter(
            expires_at__lt=datetime.now()
        )
        expired_users.delete()

# 设置定期清理任务
schedule.every().day.at("02:00").do(DataRetentionManager.cleanup_expired_data)
