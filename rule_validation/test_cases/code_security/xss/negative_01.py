# Test Case ID: XS-N01
# Rule: code_security.xss
# Test Type: negative
# Description: 防止 XSS 攻击
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, make_response
from markupsafe import escape

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # 转义用户输入
    safe_query = escape(query)
    
    html = f'''
    <html>
        <body>
            <h1>Search Results for: {safe_query}</h1>
            <p>Showing results for {safe_query}</p>
        </body>
    </html>
    '''
    return html

@app.route('/profile')
def profile():
    username = request.args.get('username', 'Guest')
    
    # 转义用户名
    safe_username = escape(username)
    return f'<h1>Welcome, {safe_username}!</h1>'
