# Test Case ID: PT-B01
# Rule: code_security.path_traversal
# Test Type: boundary
# Description: 使用白名单文件访问
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, send_file
import os

app = Flask(__name__)

# 允许访问的文件白名单
ALLOWED_FILES = {
    'report.pdf': '/var/reports/report.pdf',
    'invoice.pdf': '/var/reports/invoice.pdf',
    'manual.pdf': '/var/docs/manual.pdf'
}

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    
    if filename not in ALLOWED_FILES:
        return "File not found", 404
    
    return send_file(ALLOWED_FILES[filename])
