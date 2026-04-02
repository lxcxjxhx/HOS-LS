# Test Case ID: IE-B01
# Rule: code_security.information_exposure
# Test Type: boundary
# Description: 开发环境详细错误（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.errorhandler(Exception)
def handle_error(error):
    # 仅开发环境显示详细信息
    if app.config.get('DEBUG'):
        import traceback
        return jsonify({
            'error': str(error),
            'traceback': traceback.format_exc()
        }), 500
    else:
        # 生产环境返回通用消息
        return jsonify({
            'error': 'An error occurred'
        }), 500
