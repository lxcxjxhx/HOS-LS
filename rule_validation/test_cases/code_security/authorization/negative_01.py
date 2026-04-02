# Test Case ID: AZ-N01
# Rule: code_security.authorization
# Test Type: negative
# Description: 实现授权检查
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, session
from functools import wraps

app = Flask(__name__)

def require_auth(f):
    """认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return 'Login required', 401
        return f(*args, **kwargs)
    return decorated

def require_role(required_role):
    """角色授权装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_role = session.get('role')
            if not user_role or user_role != required_role:
                return 'Insufficient permissions', 403
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/user/<int:user_id>/profile')
@require_auth
def get_profile(user_id):
    # 检查是否是本人或管理员
    current_user_id = session.get('user_id')
    user_role = session.get('role')
    
    if current_user_id != user_id and user_role != 'admin':
        return 'Access denied', 403
    
    return get_user_by_id(user_id)

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@require_auth
@require_role('admin')
def delete_user(user_id):
    # 仅管理员可以删除用户
    delete_user_from_db(user_id)
    return 'User deleted'

def get_user_by_id(user_id):
    return {'id': user_id, 'name': f'User {user_id}'}

def delete_user_from_db(user_id):
    pass
