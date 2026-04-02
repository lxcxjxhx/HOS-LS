# Test Case ID: EH-N01
# Rule: code_security.error_handling
# Test Type: negative
# Description: 正确的错误处理
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, jsonify
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_exception(e):
    """全局错误处理器"""
    # 记录详细错误到日志
    logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    
    # 返回通用错误消息给用户
    return jsonify({
        'error': 'An internal error occurred',
        'message': 'Please try again later',
        'error_id': generate_error_id()  # 用于日志追踪
    }), 500

@app.route('/divide')
def divide():
    try:
        a = request.args.get('a', type=int)
        b = request.args.get('b', type=int)
        result = a / b
        return str(result)
    except ZeroDivisionError:
        logger.warning("Division by zero attempted")
        return jsonify({'error': 'Invalid operation'}), 400
    except (TypeError, ValueError):
        logger.warning("Invalid input types")
        return jsonify({'error': 'Invalid input'}), 400

def generate_error_id():
    import uuid
    return str(uuid.uuid4())
