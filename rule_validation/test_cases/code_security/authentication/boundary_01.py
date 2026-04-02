# Test Case ID: AU-B01
# Rule: code_security.authentication
# Test Type: boundary
# Description: 公开 API 端点（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/public/health')
def health_check():
    """公开的健康检查端点"""
    #  intentionally 不需要认证
    # 用于负载均衡器检查
    return jsonify({'status': 'healthy'})

@app.route('/api/public/version')
def version():
    """公开的版本信息"""
    #  intentionally 不需要认证
    # 用于客户端版本检查
    return jsonify({'version': '1.0.0', 'build': '2024.01.01'})

@app.route('/.well-known/security.txt')
def security_txt():
    """安全联系信息（公开）"""
    return '''Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59.000Z
Preferred-Languages: en
Canonical: https://example.com/.well-known/security.txt
'''
