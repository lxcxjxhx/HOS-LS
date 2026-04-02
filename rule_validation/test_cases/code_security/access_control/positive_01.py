# Test Case ID: AC-P01
# Rule: code_security.access_control
# Test Type: positive
# Description: 访问控制缺失
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, request

app = Flask(__name__)

@app.route('/api/admin/users')
def list_users():
    # 没有访问控制
    # 任何用户都可以访问管理员接口
    return get_all_users()

@app.route('/api/billing/invoices')
def list_invoices():
    # 没有检查用户权限
    # 用户可以查看其他人的账单
    user_id = request.args.get('user_id')
    return get_invoices(user_id)

@app.route('/api/files/<path:filename>')
def get_file(filename):
    # 没有路径限制
    # 可以访问任意文件
    return send_file(f'/var/files/{filename}')
