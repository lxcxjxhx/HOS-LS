# Test Case ID: CS-B01
# Rule: code_security.csrf
# Test Type: boundary
# Description: API 使用 Token 认证（无 CSRF 风险）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

def require_api_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-API-Token')
        if not token or token != app.config.get('API_TOKEN'):
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/transfer', methods=['POST'])
@require_api_token
def api_transfer():
    # API 使用 Token 认证，不依赖 Cookie，无 CSRF 风险
    data = request.get_json()
    amount = data.get('amount')
    to_account = data.get('to_account')
    
    return jsonify({'status': 'success'})
