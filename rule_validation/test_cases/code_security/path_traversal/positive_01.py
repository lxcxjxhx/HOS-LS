# Test Case ID: PT-P01
# Rule: code_security.path_traversal
# Test Type: positive
# Description: 路径遍历漏洞
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route('/download')
def download_file():
    # 直接使用用户输入拼接文件路径（路径遍历漏洞）
    filename = request.args.get('file', 'default.txt')
    file_path = os.path.join('/var/uploads', filename)
    
    # 攻击者可以传入 ../../etc/passwd
    return send_file(file_path)

@app.route('/read')
def read_file():
    path = request.args.get('path')
    with open(path, 'r') as f:  # 直接打开任意文件
        return f.read()
