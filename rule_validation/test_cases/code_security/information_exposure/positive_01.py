# Test Case ID: IE-P01
# Rule: code_security.information_exposure
# Test Type: positive
# Description: 敏感信息暴露
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, jsonify
import traceback

app = Flask(__name__)

@app.errorhandler(Exception)
def handle_error(error):
    # 返回完整堆栈跟踪（泄露敏感信息）
    return jsonify({
        'error': str(error),
        'type': type(error).__name__,
        'traceback': traceback.format_exc()
    }), 500

@app.route('/debug')
def debug_info():
    # 暴露系统信息
    import sys
    import platform
    return jsonify({
        'python_version': sys.version,
        'platform': platform.platform(),
        'environment': dict(os.environ)
    })
