# Test Case ID: CJ-P01
# Rule: code_security.clickjacking
# Test Type: positive
# Description: 缺少点击劫持防护
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

from flask import Flask, make_response

app = Flask(__name__)

@app.route('/admin/delete')
def delete_account():
    # 敏感操作页面
    html = '''
    <html>
        <body>
            <h1>Delete Your Account</h1>
            <button onclick="deleteAccount()">Confirm Delete</button>
            <script>
                function deleteAccount() {
                    fetch('/api/delete', {method: 'POST'});
                }
            </script>
        </body>
    </html>
    '''
    response = make_response(html)
    
    # 没有设置 X-Frame-Options
    # 没有设置 Content-Security-Policy frame-ancestors
    
    return response
