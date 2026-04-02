# Test Case ID: HS-B01
# Rule: code_security.http_security_headers
# Test Type: boundary
# Description: API 端点的最小安全头（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, jsonify

app = Flask(__name__)

@app.after_request
def add_api_security_headers(response):
    """API 端点的安全头"""
    # API 返回 JSON，不需要某些 Web 安全头
    
    # 防止 MIME 类型嗅探
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # 设置正确的内容类型
    response.headers['Content-Type'] = 'application/json'
    
    # CORS 配置
    response.headers['Access-Control-Allow-Origin'] = 'https://trusted-domain.com'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST'
    
    # API 不需要 X-Frame-Options（不是 HTML）
    # API 不需要 CSP（不是 HTML）
    
    return response

@app.route('/api/data')
def api_data():
    return jsonify({'data': 'value'})
