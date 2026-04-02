# Test Case ID: LG-P01
# Rule: code_security.logging
# Test Type: positive
# Description: 日志记录不当
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

import logging

logger = logging.getLogger(__name__)

def login_user(username, password):
    # 记录敏感信息（危险）
    logger.info(f"User login attempt: username={username}, password={password}")
    
    if authenticate(username, password):
        logger.info(f"Login successful: user={username}, session={session_id}")
        return True
    else:
        logger.error(f"Login failed: username={username}, password={password}")
        return False

def process_payment(user_id, card_number, cvv, amount):
    # 记录完整的信用卡信息（严重违规）
    logger.info(f"Processing payment: user={user_id}, card={card_number}, cvv={cvv}, amount={amount}")
    
    # 处理支付
    pass

def debug_function(data):
    # 调试日志记录敏感数据
    logger.debug(f"Debug data: {data}")  # data 可能包含 PII
