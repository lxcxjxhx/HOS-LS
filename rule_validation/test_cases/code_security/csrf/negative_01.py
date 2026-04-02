# Test Case ID: CS-N01
# Rule: code_security.csrf
# Test Type: negative
# Description: 启用 CSRF 保护
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, session
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# 启用 CSRF 保护
csrf = CSRFProtect(app)

class TransferForm(FlaskForm):
    pass  # 表单自动包含 CSRF token

@app.route('/transfer', methods=['POST'])
def transfer_money():
    form = TransferForm()
    
    # 验证 CSRF token
    if not form.validate_on_submit():
        return 'Invalid CSRF token', 400
    
    amount = request.form.get('amount')
    to_account = request.form.get('to_account')
    
    # process_transfer(user_id, amount, to_account)
    
    return 'Transfer completed'
