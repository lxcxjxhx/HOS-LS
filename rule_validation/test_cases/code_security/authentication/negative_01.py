# Test Case ID: AU-N01
# Rule: code_security.authentication
# Test Type: negative
# Description: 实现认证机制
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, session, redirect, url_for
from functools import wraps
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-secret-key'

def require_auth(f):
    """认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 验证用户凭证
        user = verify_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('admin_panel'))
        return 'Invalid credentials', 401
    
    return '''<form method="post">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>'''

@app.route('/admin')
@require_auth
def admin_panel():
    # 需要认证才能访问
    return '<h1>Admin Panel</h1>'

def verify_user(username, password):
    # 模拟用户验证
    return {'id': 1, 'role': 'admin'}
