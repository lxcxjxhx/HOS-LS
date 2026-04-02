# Test Case ID: SS-N01
# Rule: code_security.session_security
# Test Type: negative
# Description: 安全的会话配置
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, session
from datetime import timedelta
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# 安全的会话配置
app.config['SESSION_COOKIE_SECURE'] = True  # 仅 HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # 禁止 JavaScript 访问
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF 保护
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # 1 小时过期

@app.route('/login')
def login():
    session['user_id'] = 123
    session.permanent = True
    return 'Logged in'

@app.route('/logout')
def logout():
    session.clear()  # 清除会话
    return 'Logged out'
