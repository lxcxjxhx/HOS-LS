# Test Case ID: TP-N01
# Rule: code_security.third_party_integrations
# Test Type: negative
# Description: 安全的第三方集成
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import requests
import os

def integrate_payment_gateway(amount, payment_token):
    """安全集成支付网关"""
    # 从环境变量获取 API 密钥
    API_KEY = os.environ.get('PAYMENT_API_KEY')
    
    # 仅发送 token，不发送完整卡号
    response = requests.post(
        'https://api.payment.com/charge',
        json={
            'amount': amount,
            'payment_token': payment_token,  # 使用 tokenization
            'currency': 'USD'
        },
        headers={'Authorization': f'Bearer {API_KEY}'},
        timeout=30
    )
    
    # 验证响应
    if response.status_code != 200:
        raise PaymentError("Payment failed")
    
    return response.json()

def integrate_analytics_minimal(user_id, event_type):
    """最小化数据发送"""
    # 仅发送必要信息
    requests.post(
        'https://analytics.service.com/track',
        json={
            'user_id': hash_user_id(user_id),  # 哈希处理
            'event': event_type,
            'timestamp': get_timestamp()
        },
        timeout=10
    )

def hash_user_id(user_id):
    import hashlib
    return hashlib.sha256(user_id.encode()).hexdigest()
