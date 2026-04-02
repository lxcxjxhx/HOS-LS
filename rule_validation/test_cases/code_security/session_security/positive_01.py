# Test Case ID: SS-P01
# Rule: code_security.session_security
# Test Type: positive
# Description: 会话安全配置缺失
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'weak-secret'

# 不安全的会话配置
app.config['SESSION_COOKIE_SECURE'] = False  # 允许非 HTTPS 传输
app.config['SESSION_COOKIE_HTTPONLY'] = False  # 允许 JavaScript 访问
app.config['SESSION_COOKIE_SAMESITE'] = None  # 无 SameSite 保护

# 会话永不过期
app.config['PERMANENT_SESSION_LIFETIME'] = None

@app.route('/login')
def login():
    session['user_id'] = 123
    session.permanent = True  # 永久会话
    return 'Logged in'
