# Test Case ID: TP-P01
# Rule: code_security.third_party_integrations
# Test Type: positive
# Description: 第三方集成风险
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

import requests

def integrate_payment_gateway(api_key, amount, card_data):
    """集成支付网关 - 不安全"""
    # 硬编码 API 密钥
    API_KEY = "sk_live_1234567890"
    
    # 发送完整卡号到第三方
    response = requests.post(
        'https://api.payment.com/charge',
        json={
            'amount': amount,
            'card_number': card_data['number'],
            'cvv': card_data['cvv'],
            'expiry': card_data['expiry']
        },
        headers={'Authorization': f'Bearer {API_KEY}'}
    )
    
    return response.json()

def integrate_analytics(user_data, event_data):
    """集成分析服务 - 发送过多数据"""
    # 发送用户完整信息
    requests.post(
        'https://analytics.service.com/track',
        json={
            'user_id': user_data['id'],
            'user_email': user_data['email'],
            'user_phone': user_data['phone'],
            'event': event_data,
            'ip_address': get_client_ip(),
            'user_agent': get_user_agent()
        }
    )
