# Test Case ID: DR-B01
# Rule: privacy_security.data_retention
# Test Type: boundary
# Description: 合规要求的永久保留（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from datetime import datetime

class FinancialRecords:
    # 财务记录需要永久保存（法律要求）
    RETENTION_PERIOD = None  # 永久保留
    
    def __init__(self, transaction_id, amount, date):
        self.transaction_id = transaction_id
        self.amount = amount
        self.date = date
        self.permanent = True
        
    # 财务数据根据法律要求永久保存
    # 用于审计和合规

class MedicalRecords:
    # 医疗记录长期保存
    RETENTION_PERIOD = 30 * 365  # 30 年
    
    def __init__(self, patient_id, diagnosis, treatment):
        self.patient_id = patient_id
        self.diagnosis = diagnosis
        self.treatment = treatment
