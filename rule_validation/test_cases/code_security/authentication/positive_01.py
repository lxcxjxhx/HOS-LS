# Test Case ID: AU-P01
# Rule: code_security.authentication
# Test Type: positive
# Description: 认证机制缺失
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, request, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'

@app.route('/admin')
def admin_panel():
    # 没有认证检查
    # 任何人都可以访问管理面板
    return '''
    <html>
        <body>
            <h1>Admin Panel</h1>
            <p>Welcome to the admin area!</p>
            <a href="/delete-all">Delete All Data</a>
        </body>
    </html>
    '''

@app.route('/api/users')
def get_users():
    # API 端点没有认证
    # 返回所有用户数据
    return {'users': get_all_users()}

def get_all_users():
    # 模拟获取所有用户
    return [{'id': 1, 'name': 'Alice'}, {'id': 2, 'name': 'Bob'}]
