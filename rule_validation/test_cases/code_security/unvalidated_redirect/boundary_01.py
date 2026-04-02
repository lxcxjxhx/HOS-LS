# Test Case ID: UR-B01
# Rule: code_security.unvalidated_redirect
# Test Type: boundary
# Description: 使用白名单验证重定向
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, redirect
from urllib.parse import urlparse

app = Flask(__name__)

# 允许的重定向域名白名单
ALLOWED_HOSTS = ['example.com', 'www.example.com', 'app.example.com']

def is_safe_url(url):
    parsed = urlparse(url)
    # 允许相对路径或白名单中的域名
    return not parsed.netloc or parsed.netloc in ALLOWED_HOSTS

@app.route('/external')
def external_redirect():
    next_url = request.args.get('next', '/')
    if is_safe_url(next_url):
        return redirect(next_url)
    return redirect('/')
