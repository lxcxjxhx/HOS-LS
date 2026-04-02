# Test Case ID: XS-P01
# Rule: code_security.xss
# Test Type: positive
# Description: XSS（跨站脚本）漏洞
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # 直接返回用户输入（XSS 漏洞）
    html = f'''
    <html>
        <body>
            <h1>Search Results for: {query}</h1>
            <p>Showing results for {query}</p>
        </body>
    </html>
    '''
    return html

@app.route('/profile')
def profile():
    username = request.args.get('username', 'Guest')
    
    # 另一个 XSS 漏洞
    return f'<h1>Welcome, {username}!</h1>'
