# Test Case ID: DR-P01
# Rule: privacy_security.data_retention
# Test Type: positive
# Description: 数据保留策略缺失
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

from datetime import datetime

class UserData:
    def __init__(self, user_id, email, phone):
        self.user_id = user_id
        self.email = email
        self.phone = phone
        self.created_at = datetime.now()
        
    # 没有数据过期策略
    # 没有自动删除机制
    # 用户数据永久保存

class UserLogs:
    def __init__(self, user_id, action):
        self.user_id = user_id
        self.action = action
        self.timestamp = datetime.now()
        
    # 日志永久保存，没有清理策略
