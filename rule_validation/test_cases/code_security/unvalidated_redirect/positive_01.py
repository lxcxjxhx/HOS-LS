# Test Case ID: UR-P01
# Rule: code_security.unvalidated_redirect
# Test Type: positive
# Description: 未经验证的重定向
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect')
def redirect_to_url():
    # 直接使用用户输入进行重定向（开放重定向漏洞）
    next_url = request.args.get('next', '/')
    return redirect(next_url)

@app.route('/login')
def login():
    # 登录后重定向到用户指定的 URL
    return_url = request.args.get('return_url', '/')
    # 没有验证 return_url 是否可信
    return redirect(return_url)
