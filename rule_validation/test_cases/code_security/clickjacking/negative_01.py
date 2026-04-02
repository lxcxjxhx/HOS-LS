# Test Case ID: CJ-N01
# Rule: code_security.clickjacking
# Test Type: negative
# Description: 防止点击劫持
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, make_response

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    """添加安全响应头"""
    # 禁止在 iframe 中加载
    response.headers['X-Frame-Options'] = 'DENY'
    
    # CSP frame-ancestors
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
    
    return response

@app.route('/admin/delete')
def delete_account():
    html = '''
    <html>
        <body>
            <h1>Delete Your Account</h1>
            <button onclick="deleteAccount()">Confirm Delete</button>
        </body>
    </html>
    '''
    response = make_response(html)
    # 安全头由 after_request 添加
    return response
