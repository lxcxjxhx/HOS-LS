# Test Case ID: AZ-B01
# Rule: code_security.authorization
# Test Type: boundary
# Description: 团队协作功能（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, session

app = Flask(__name__)

@app.route('/team/<int:team_id>/members')
@require_auth
def get_team_members(team_id):
    """团队成员可以查看其他成员信息"""
    current_user_id = session.get('user_id')
    
    # 检查是否属于同一团队
    if not is_team_member(current_user_id, team_id):
        return 'Access denied', 403
    
    # 团队成员可以互相查看
    return get_members_by_team(team_id)

@app.route('/team/<int:team_id>/document/<int:doc_id>')
@require_auth
def get_team_document(team_id, doc_id):
    """团队共享文档"""
    current_user_id = session.get('user_id')
    
    # 检查团队访问权限
    if not has_team_access(current_user_id, team_id):
        return 'Access denied', 403
    
    # 检查文档权限（可能是团队公开或特定角色）
    if not has_document_access(current_user_id, doc_id):
        return 'Access denied', 403
    
    return get_document(doc_id)

def is_team_member(user_id, team_id):
    return True  # 模拟

def has_team_access(user_id, team_id):
    return True  # 模拟

def has_document_access(user_id, doc_id):
    return True  # 模拟
