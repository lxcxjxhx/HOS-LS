# Test Case ID: CM-B01
# Rule: privacy_security.consent_management
# Test Type: boundary
# Description: 必要的服务功能（无需单独同意）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

class EssentialService:
    """服务必需的功能，根据合同履行，无需单独同意"""
    
    def __init__(self, user_id, email):
        self.user_id = user_id
        self.email = email
        
    def send_order_confirmation(self, order_id):
        """订单确认邮件 - 服务必需"""
        # 这是履行合同所必需的通信
        # GDPR Article 6(1)(b) - 合同履行
        self.email_service.send(
            self.email,
            f"Your order {order_id} has been confirmed"
        )
        
    def send_security_alert(self, alert_type):
        """安全通知 - 合法利益"""
        # GDPR Article 6(1)(f) - 合法利益
        self.email_service.send(
            self.email,
            f"Security alert: {alert_type}"
        )
