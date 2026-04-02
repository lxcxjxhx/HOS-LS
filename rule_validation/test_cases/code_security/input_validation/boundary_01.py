# Test Case ID: IV-B01
# Rule: code_security.input_validation
# Test Type: boundary
# Description: 宽松验证的内部 API（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request

app = Flask(__name__)

@app.route('/internal/log', methods=['POST'])
def log_message():
    """内部日志 API - 宽松验证"""
    # 内部服务调用，信任来源
    message = request.get_json()
    
    # 仅基本验证
    if not message:
        return 'Invalid request', 400
    
    # 记录日志（允许各种内容）
    log_to_system(message)
    
    return 'Logged'

@app.route('/internal/metrics')
def collect_metrics():
    """内部监控数据收集"""
    # 仅允许内网访问（在网络层控制）
    metrics = request.get_json()
    
    # 宽松验证，信任内部服务
    store_metrics(metrics)
    
    return 'OK'

# 注意：这些端点应该通过网络 ACL 限制仅内网访问
