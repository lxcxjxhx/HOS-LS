# Test Case ID: ID-N01
# Rule: code_security.insecure_deserialization
# Test Type: negative
# Description: 使用安全的序列化格式
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import json
import base64
from flask import Flask, request, make_response
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['SECRET_KEY'] = b'your-secret-key'
fernet = Fernet(app.config['SECRET_KEY'])

@app.route('/set_cookie')
def set_cookie():
    user_data = {'user_id': 123, 'role': 'user'}
    
    # 使用 JSON 序列化（安全）
    serialized = json.dumps(user_data)
    
    # 加密数据
    encrypted = fernet.encrypt(serialized.encode())
    
    response = make_response('Cookie set')
    response.set_cookie('user_data', encrypted.decode())
    return response

@app.route('/get_cookie')
def get_cookie():
    encrypted = request.cookies.get('user_data')
    
    # 解密并反序列化
    decrypted = fernet.decrypt(encrypted.encode())
    user_data = json.loads(decrypted.decode())
    
    return f"User: {user_data['user_id']}, Role: {user_data['role']}"
