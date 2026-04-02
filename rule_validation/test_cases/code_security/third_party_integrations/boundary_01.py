# Test Case ID: TP-B01
# Rule: code_security.third_party_integrations
# Test Type: boundary
# Description: 企业内部服务集成（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import requests
import os

INTERNAL_SSO_URL = os.environ.get('INTERNAL_SSO_URL')
INTERNAL_API_KEY = os.environ.get('INTERNAL_API_KEY')

def authenticate_via_sso(username, password):
    """通过内部 SSO 认证"""
    # 内部服务，可信环境
    response = requests.post(
        f'{INTERNAL_SSO_URL}/authenticate',
        json={'username': username, 'password': password},
        headers={'X-API-Key': INTERNAL_API_KEY},
        timeout=10
    )
    
    return response.json()

def sync_user_data(user_id):
    """同步用户数据到内部 CRM"""
    # 内部 CRM 系统，可信
    requests.post(
        'https://crm.internal.company.com/api/sync',
        json={'user_id': user_id},
        headers={'X-API-Key': INTERNAL_API_KEY}
    )

# 内部服务在同一信任域内
# 有网络隔离和访问控制
