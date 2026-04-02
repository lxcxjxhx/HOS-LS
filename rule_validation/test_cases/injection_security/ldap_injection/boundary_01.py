# Test Case ID: LI-B01
# Rule: injection_security.ldap_injection
# Test Type: boundary
# Description: 使用白名单验证 LDAP 查询
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import ldap

ALLOWED_USERS = {
    'admin': 'uid=admin,dc=example,dc=com',
    'john': 'uid=john,dc=example,dc=com',
    'jane': 'uid=jane,dc=example,dc=com'
}

def authenticate_user(username, password):
    # 白名单验证用户名
    if username not in ALLOWED_USERS:
        return False
    
    conn = ldap.initialize('ldap://localhost:389')
    
    # 使用预定义的 DN，避免注入
    user_dn = ALLOWED_USERS[username]
    
    try:
        # 简单绑定验证
        conn.simple_bind_s(user_dn, password)
        return True
    except ldap.INVALID_CREDENTIALS:
        return False
