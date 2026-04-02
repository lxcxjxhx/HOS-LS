# Test Case ID: ID-P01
# Rule: code_security.insecure_deserialization
# Test Type: positive
# Description: 不安全的反序列化
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

import pickle
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/set_cookie')
def set_cookie():
    user_data = {'user_id': 123, 'role': 'user'}
    
    # 使用 pickle 序列化（危险）
    serialized = pickle.dumps(user_data)
    
    response = make_response('Cookie set')
    response.set_cookie('user_data', serialized)
    return response

@app.route('/get_cookie')
def get_cookie():
    serialized = request.cookies.get('user_data')
    
    # 反序列化用户提供的数据（危险）
    # 攻击者可以构造恶意 pickle payload
    user_data = pickle.loads(serialized)
    
    return f"User: {user_data['user_id']}, Role: {user_data['role']}"
