# Test Case ID: CI-N01
# Rule: injection_security.command_injection
# Test Type: negative
# Description: 安全的命令执行
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request
import subprocess
import shlex

app = Flask(__name__)

ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'example.com']

@app.route('/ping')
def ping_host():
    host = request.args.get('host', 'localhost')
    
    # 白名单验证
    if host not in ALLOWED_HOSTS:
        return 'Host not allowed', 400
    
    # 使用列表形式，避免 shell 注入
    result = subprocess.run(
        ['ping', '-c', '1', host],
        capture_output=True,
        text=True
    )
    
    return result.stdout
