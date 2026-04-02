# Test Case ID: AZ-P01
# Rule: code_security.authorization
# Test Type: positive
# Description: 授权检查缺失
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, request, session

app = Flask(__name__)

@app.route('/user/<int:user_id>/profile')
def get_profile(user_id):
    # 仅检查登录，不检查权限
    if 'user_id' not in session:
        return 'Login required', 401
    
    # 任何登录用户都可以查看其他人的资料（IDOR 漏洞）
    user_data = get_user_by_id(user_id)
    return user_data

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # 没有检查是否是管理员
    # 任何登录用户都可以删除其他用户
    delete_user_from_db(user_id)
    return 'User deleted'

def get_user_by_id(user_id):
    return {'id': user_id, 'name': f'User {user_id}'}

def delete_user_from_db(user_id):
    pass
