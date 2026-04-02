# Test Case ID: LI-P01
# Rule: injection_security.ldap_injection
# Test Type: positive
# Description: LDAP 注入漏洞
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

import ldap

def authenticate_user(username, password):
    # 直接使用用户输入构造 LDAP 查询（危险）
    # 攻击者可以输入：*)(uid=*))(|(uid=*
    conn = ldap.initialize('ldap://localhost:389')
    
    search_filter = f"(uid={username})"  # LDAP 注入点
    password_filter = f"(userPassword={password})"
    
    # 构造的查询可能被注入
    full_filter = f"(&{search_filter}{password_filter})"
    
    results = conn.search_s(
        'dc=example,dc=com',
        ldap.SCOPE_SUBTREE,
        full_filter
    )
    
    return len(results) > 0
