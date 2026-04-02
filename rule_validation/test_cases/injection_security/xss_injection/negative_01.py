# Test Case ID: XSS-N01
# Rule: injection_security.xss_injection
# Test Type: negative
# Description: XSS 防护 - HTML 转义
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# 安全的 HTML 转义
import html

user_comment = "<script>alert('XSS')</script>"
safe_output = html.escape(user_comment)
