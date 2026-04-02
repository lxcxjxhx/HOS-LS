# Test Case ID: HS-P01
# Rule: code_security.http_security_headers
# Test Type: positive
# Description: 缺少 HTTP 安全响应头
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

from flask import Flask, make_response

app = Flask(__name__)

@app.route('/page')
def page():
    html = '<html><body><h1>Page Content</h1></body></html>'
    response = make_response(html)
    
    # 没有设置任何安全响应头
    # 缺少：
    # - X-Content-Type-Options
    # - X-Frame-Options
    # - X-XSS-Protection
    # - Content-Security-Policy
    # - Strict-Transport-Security
    # - Referrer-Policy
    
    return response
