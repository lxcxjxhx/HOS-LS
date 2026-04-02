# Test Case ID: EH-P01
# Rule: code_security.error_handling
# Test Type: positive
# Description: 错误处理不当
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

from flask import Flask
import traceback

app = Flask(__name__)

@app.route('/divide')
def divide():
    a = request.args.get('a', type=int)
    b = request.args.get('b', type=int)
    
    try:
        result = a / b
        return str(result)
    except Exception as e:
        # 返回详细错误信息（泄露敏感信息）
        return f'''
        Error: {str(e)}
        Type: {type(e).__name__}
        Traceback: {traceback.format_exc()}
        Args: {e.args}
        ''', 500

@app.route('/query')
def query():
    try:
        return execute_query(request.args.get('sql'))
    except Exception as e:
        # 泄露 SQL 查询细节
        return f'SQL Error: {str(e)}, Query: {request.args.get("sql")}', 500
