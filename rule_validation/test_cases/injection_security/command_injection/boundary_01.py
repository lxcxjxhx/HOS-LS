# Test Case ID: CI-B01
# Rule: injection_security.command_injection
# Test Type: boundary
# Description: 使用安全包装器执行命令
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request
import subprocess
import re

app = Flask(__name__)

def safe_ping(hostname):
    """安全的 ping 函数"""
    # 严格验证主机名格式（仅允许字母、数字、点、连字符）
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError("Invalid hostname")
    
    # 使用列表形式执行命令
    result = subprocess.run(
        ['ping', '-c', '1', '-W', '2', hostname],
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout

@app.route('/ping')
def ping_host():
    host = request.args.get('host', 'localhost')
    try:
        output = safe_ping(host)
        return output
    except Exception as e:
        return str(e), 400
