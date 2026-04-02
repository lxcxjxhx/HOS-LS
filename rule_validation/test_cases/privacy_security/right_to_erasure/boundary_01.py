# Test Case ID: RE-B01
# Rule: privacy_security.right_to_erasure
# Test Type: boundary
# Description: 法律要求的保留期（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from datetime import datetime, timedelta

class FinancialData:
    """财务数据需要保留（法律要求）"""
    LEGAL_RETENTION_PERIOD = timedelta(days=365*7)  # 7 年
    
    def __init__(self, user_id, transaction_id, amount):
        self.user_id = user_id
        self.transaction_id = transaction_id
        self.amount = amount
        self.date = datetime.now()
        
    def request_deletion(self):
        """删除请求会延迟到法律保留期结束"""
        self.deletion_scheduled = self.date + self.LEGAL_RETENTION_PERIOD
        
    def can_delete_now(self):
        return datetime.now() >= self.deletion_scheduled

class MedicalData:
    """医疗记录根据法律保留"""
    
    def request_deletion(self, user_id):
        # 医疗记录可能需要保留 10-30 年
        # 根据当地法律
        raise LegalRetentionRequired(
            "Medical records must be retained for 30 years"
        )
