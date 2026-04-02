# Test Case ID: AC-N01
# Rule: code_security.access_control
# Test Type: negative
# Description: 实现访问控制
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, session, abort
from functools import wraps

app = Flask(__name__)

def require_admin(f):
    """管理员权限装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated

def require_ownership(f):
    """所有权检查装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get('user_id')
        resource_id = kwargs.get('user_id')
        
        # 检查是否拥有该资源
        if not check_ownership(user_id, resource_id):
            abort(403)
        return f(*args, **kwargs)
    return decorated

@app.route('/api/admin/users')
@require_admin
def list_users():
    # 仅管理员可访问
    return get_all_users()

@app.route('/api/billing/invoices')
@require_ownership
def list_invoices(user_id):
    # 仅可查看自己的账单
    return get_invoices(user_id)

def check_ownership(user_id, resource_id):
    return user_id == resource_id
