# Test Case ID: RL-P01
# Rule: code_security.rate_limiting
# Test Type: positive
# Description: 缺少速率限制
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

from flask import Flask, request

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    # 没有登录频率限制
    # 攻击者可以暴力破解
    username = request.form.get('username')
    password = request.form.get('password')
    
    # 验证用户凭证
    # authenticate(username, password)
    
    return 'Login successful'

@app.route('/api/search')
def search():
    # 没有 API 调用频率限制
    # 可能导致资源耗尽
    query = request.args.get('q')
    results = search_database(query)
    
    return {'results': results}
