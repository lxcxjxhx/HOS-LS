# Test Case ID: AC-B01
# Rule: code_security.access_control
# Test Type: boundary
# Description: 公开 API 端点（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/public/docs')
def api_docs():
    """公开的 API 文档"""
    # intentionally 公开访问
    return jsonify({
        'endpoints': [...],
        'documentation': '...'
    })

@app.route('/api/public/status')
def system_status():
    """公开的系统状态"""
    # intentionally 公开访问
    return jsonify({
        'status': 'operational',
        'uptime': get_uptime()
    })

@app.route('/health')
def health_check():
    """健康检查端点"""
    # intentionally 公开访问（用于负载均衡器）
    return jsonify({'healthy': True})
