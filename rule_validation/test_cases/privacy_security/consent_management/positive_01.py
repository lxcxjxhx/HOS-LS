# Test Case ID: CM-P01
# Rule: privacy_security.consent_management
# Test Type: positive
# Description: 缺少用户同意管理
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

class UserService:
    def __init__(self, user_id, email, phone):
        self.user_id = user_id
        self.email = email
        self.phone = phone
        
    def send_marketing_email(self, content):
        # 没有检查用户是否同意接收营销邮件
        self.email_service.send(self.email, content)
        
    def share_data_with_partners(self):
        # 没有用户同意就共享数据给第三方
        partner_api.share_data(self.user_id)
        
    def enable_tracking(self):
        # 默认开启追踪，没有 opt-in
        self.tracking_enabled = True
