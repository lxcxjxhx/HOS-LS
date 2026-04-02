# Test Case ID: IE-N01
# Rule: code_security.information_exposure
# Test Type: negative
# Description: 正确的错误处理，不泄露敏感信息
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, jsonify
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(error):
    # 仅记录日志，不暴露细节
    logger.error(f"Error occurred: {str(error)}", exc_info=True)
    
    # 返回通用错误消息
    return jsonify({
        'error': 'An internal error occurred',
        'message': 'Please try again later'
    }), 500

@app.route('/health')
def health():
    # 仅返回健康状态，不暴露系统信息
    return jsonify({'status': 'healthy'})
