# Test Case ID: LI-N01
# Rule: injection_security.ldap_injection
# Test Type: negative
# Description: 安全的 LDAP 查询
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import ldap
from ldap.filter import escape_filter_chars

def authenticate_user(username, password):
    conn = ldap.initialize('ldap://localhost:389')
    
    # 转义特殊字符，防止 LDAP 注入
    safe_username = escape_filter_chars(username)
    safe_password = escape_filter_chars(password)
    
    # 使用参数化查询
    search_filter = f"(uid={safe_username})"
    password_filter = f"(userPassword={safe_password})"
    
    full_filter = f"(&{search_filter}{password_filter})"
    
    results = conn.search_s(
        'dc=example,dc=com',
        ldap.SCOPE_SUBTREE,
        full_filter
    )
    
    return len(results) > 0
