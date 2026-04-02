# Test Case ID: CS-P01
# Rule: code_security.csrf
# Test Type: positive
# Description: 缺少 CSRF 保护
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, request, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'

# 没有启用 CSRF 保护

@app.route('/transfer', methods=['POST'])
def transfer_money():
    # 没有 CSRF token 验证
    amount = request.form.get('amount')
    to_account = request.form.get('to_account')
    
    # 执行转账操作
    user_id = session.get('user_id')
    # process_transfer(user_id, amount, to_account)
    
    return 'Transfer completed'

@app.route('/change_password', methods=['POST'])
def change_password():
    # 敏感操作没有 CSRF 保护
    new_password = request.form.get('new_password')
    # update_password(new_password)
    
    return 'Password changed'
