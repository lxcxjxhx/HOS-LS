# Test Case ID: UR-N01
# Rule: code_security.unvalidated_redirect
# Test Type: negative
# Description: 验证重定向目标
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, redirect, url_for
from urllib.parse import urlparse

app = Flask(__name__)

def is_safe_url(url):
    """验证 URL 是否安全（仅允许相对路径或可信域名）"""
    if not url:
        return False
    parsed = urlparse(url)
    # 仅允许相对路径
    return not parsed.netloc

@app.route('/redirect')
def redirect_to_url():
    next_url = request.args.get('next', '/')
    if is_safe_url(next_url):
        return redirect(next_url)
    else:
        return redirect(url_for('index'))  # 重定向到默认安全页面
