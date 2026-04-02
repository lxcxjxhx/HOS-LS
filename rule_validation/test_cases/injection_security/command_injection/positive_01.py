# Test Case ID: CI-P01
# Rule: injection_security.command_injection
# Test Type: positive
# Description: 命令注入漏洞
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/ping')
def ping_host():
    # 直接使用用户输入执行系统命令（危险）
    host = request.args.get('host', 'localhost')
    
    # 命令注入漏洞：攻击者可以传入 ; rm -rf /
    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)
    
    return result.stdout.decode()

@app.route('/convert')
def convert_file():
    filename = request.args.get('file')
    # 直接拼接命令（危险）
    subprocess.call('convert ' + filename + ' output.png', shell=True)
    
    return 'Converted'
