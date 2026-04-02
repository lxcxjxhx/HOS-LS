# Test Case ID: CJ-B01
# Rule: code_security.clickjacking
# Test Type: boundary
# Description: 允许同源 iframe（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, make_response

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    """添加安全响应头"""
    # 允许同源 iframe
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # CSP 允许同源 frame
    response.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
    
    return response

@app.route('/embed/widget')
def embed_widget():
    """可嵌入的组件页面"""
    html = '''
    <html>
        <body>
            <div class="widget">
                <p>Embeddable Widget</p>
            </div>
        </body>
    </html>
    '''
    response = make_response(html)
    return response
