# Test Case ID: XSS-P02
# Rule: injection_security.xss_injection
# Test Type: positive
# Description: XSS 注入 - HTML 渲染
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

# XSS 漏洞
user_comment = "<script>alert('XSS')</script>"
html_output = f"<div>{user_comment}</div>"
