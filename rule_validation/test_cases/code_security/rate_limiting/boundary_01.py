# Test Case ID: RL-B01
# Rule: code_security.rate_limiting
# Test Type: boundary
# Description: 内部 API 速率限制（较宽松）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request
from flask_limiter import Limiter

app = Flask(__name__)

limiter = Limiter(app=app, key_func=lambda: "internal")

@app.route('/internal/health')
@limiter.limit("1000 per minute")
def health_check():
    # 内部健康检查端点，限制较宽松
    return {'status': 'healthy'}

@app.route('/internal/metrics')
@limiter.limit("100 per minute")
def metrics():
    # 内部监控端点
    return {'cpu': 0.5, 'memory': 0.6}
