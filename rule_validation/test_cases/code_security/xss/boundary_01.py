# Test Case ID: XS-B01
# Rule: code_security.xss
# Test Type: boundary
# Description: 允许安全的 HTML 子集（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request
from markupsafe import Markup
import bleach

app = Flask(__name__)

# 允许的 HTML 标签和属性
ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br']
ALLOWED_ATTRIBUTES = {'a': ['href', 'title']}
ALLOWED_PROTOCOLS = ['http', 'https']

@app.route('/comment')
def comment():
    user_comment = request.args.get('comment', '')
    
    # 使用 bleach 清理 HTML，保留安全子集
    safe_html = bleach.clean(
        user_comment,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS
    )
    
    return Markup(f'<div class="comment">{safe_html}</div>')
