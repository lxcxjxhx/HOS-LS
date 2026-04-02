# Test Case ID: PT-N01
# Rule: code_security.path_traversal
# Test Type: negative
# Description: 正确的路径验证
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, send_file
import os

app = Flask(__name__)

BASE_DIR = '/var/uploads'

def safe_path(user_path):
    """验证并返回安全的路径"""
    # 规范化路径
    abs_path = os.path.abspath(os.path.join(BASE_DIR, user_path))
    
    # 确保路径在 BASE_DIR 内
    if not abs_path.startswith(os.path.abspath(BASE_DIR)):
        raise ValueError("Invalid path")
    
    return abs_path

@app.route('/download')
def download_file():
    filename = request.args.get('file', 'default.txt')
    safe_file_path = safe_path(filename)
    return send_file(safe_file_path)
