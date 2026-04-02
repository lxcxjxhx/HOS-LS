# Test Case ID: LG-N01
# Rule: code_security.logging
# Test Type: negative
# Description: 安全的日志记录
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import logging
import re

logger = logging.getLogger(__name__)

def mask_sensitive_data(data):
    """脱敏敏感信息"""
    if isinstance(data, str):
        # 脱敏邮箱
        data = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[EMAIL]', data)
        # 脱敏手机号
        data = re.sub(r'\+?[0-9]{10,15}', '[PHONE]', data)
        # 脱敏信用卡号
        data = re.sub(r'\b[0-9]{16}\b', '[CARD]', data)
    return data

def login_user(username, password):
    # 仅记录用户名，不记录密码
    logger.info(f"Login attempt: username={username}")
    
    if authenticate(username, password):
        logger.info(f"Login successful: user={username}")
        return True
    else:
        logger.warning(f"Login failed: username={username}")
        return False

def process_payment(user_id, card_number, cvv, amount):
    # 仅记录脱敏后的信息
    masked_card = card_number[-4:].rjust(len(card_number), '*')
    logger.info(f"Payment: user={user_id}, card={masked_card}, amount={amount}")
    
    # 不记录 CVV
