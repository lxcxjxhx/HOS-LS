# Test Case ID: CM-N01
# Rule: privacy_security.consent_management
# Test Type: negative
# Description: 实现用户同意管理
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from datetime import datetime
from enum import Enum

class ConsentType(Enum):
    MARKETING_EMAIL = "marketing_email"
    DATA_SHARING = "data_sharing"
    ANALYTICS_TRACKING = "analytics_tracking"

class ConsentManager:
    def __init__(self, user_id):
        self.user_id = user_id
        self.consents = {}
        
    def give_consent(self, consent_type: ConsentType):
        """用户明确同意"""
        self.consents[consent_type.value] = {
            'granted': True,
            'timestamp': datetime.now(),
            'version': '1.0'
        }
        
    def revoke_consent(self, consent_type: ConsentType):
        """用户撤回同意"""
        self.consents[consent_type.value] = {
            'granted': False,
            'timestamp': datetime.now()
        }
        
    def has_consent(self, consent_type: ConsentType) -> bool:
        return self.consents.get(consent_type.value, {}).get('granted', False)

class UserService:
    def __init__(self, user_id):
        self.user_id = user_id
        self.consent_manager = ConsentManager(user_id)
        
    def send_marketing_email(self, content):
        if not self.consent_manager.has_consent(ConsentType.MARKETING_EMAIL):
            return  # 用户未同意，不发送
        self.email_service.send(self.email, content)
