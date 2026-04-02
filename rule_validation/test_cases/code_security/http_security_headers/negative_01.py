# Test Case ID: HS-N01
# Rule: code_security.http_security_headers
# Test Type: negative
# Description: 配置完整的 HTTP 安全响应头
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, make_response

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    """添加所有安全响应头"""
    # 防止 MIME 类型嗅探
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # 防止点击劫持
    response.headers['X-Frame-Options'] = 'DENY'
    
    # 启用 XSS 过滤器
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # 内容安全策略
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    
    # HTTP 严格传输安全
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Referrer 策略
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # 权限策略
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    
    return response

@app.route('/page')
def page():
    html = '<html><body><h1>Page Content</h1></body></html>'
    response = make_response(html)
    # 安全头由 after_request 添加
    return response
