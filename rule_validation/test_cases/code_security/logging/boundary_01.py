# Test Case ID: LG-B01
# Rule: code_security.logging
# Test Type: boundary
# Description: 审计日志（合规要求）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import logging
from datetime import datetime

audit_logger = logging.getLogger('audit')

def log_security_event(event_type, user_id, details):
    """安全审计日志（合规要求）"""
    # 审计日志需要记录完整信息用于调查
    # 但应该加密存储，严格访问控制
    
    audit_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': get_client_ip(),
        'user_agent': get_user_agent(),
        'details': details  # 可能包含敏感信息
    }
    
    # 审计日志单独存储，加密保护
    audit_logger.info(json.dumps(audit_entry))
    
    # 注意：审计日志应该有：
    # 1. 加密存储
    # 2. 访问控制
    # 3. 保留期限
    # 4. 完整性保护

def get_client_ip():
    return '127.0.0.1'

def get_user_agent():
    return 'Mozilla/5.0'
