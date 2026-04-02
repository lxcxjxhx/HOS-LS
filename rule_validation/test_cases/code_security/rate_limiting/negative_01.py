# Test Case ID: RL-N01
# Rule: code_security.rate_limiting
# Test Type: negative
# Description: 实现速率限制
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# 配置速率限制
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # 限制每分钟最多 5 次登录尝试
    username = request.form.get('username')
    password = request.form.get('password')
    
    # authenticate(username, password)
    
    return 'Login successful'

@app.route('/api/search')
@limiter.limit("10 per minute")
def search():
    query = request.args.get('q')
    results = search_database(query)
    
    return {'results': results}
