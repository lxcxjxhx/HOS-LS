# Test Case ID: EH-B01
# Rule: code_security.error_handling
# Test Type: boundary
# Description: 开发环境详细错误（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, jsonify
import os
import traceback

app = Flask(__name__)

@app.errorhandler(Exception)
def handle_exception(e):
    """根据环境返回不同错误信息"""
    # 记录所有错误到日志
    app.logger.error(f"Exception: {str(e)}", exc_info=True)
    
    # 开发环境显示详细信息
    if app.config.get('DEBUG'):
        return jsonify({
            'error': str(e),
            'type': type(e).__name__,
            'traceback': traceback.format_exc(),
            'debug_mode': True
        }), 500
    
    # 生产环境返回通用消息
    return jsonify({
        'error': 'An internal error occurred',
        'message': 'Please try again later'
    }), 500

# 注意：DEBUG 配置应该通过环境变量控制
