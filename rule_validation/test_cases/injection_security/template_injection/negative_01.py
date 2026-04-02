# Test Case ID: TI-N01
# Rule: injection_security.template_injection
# Test Type: negative
# Description: 安全的模板渲染
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/greet')
def greet():
    # 正确：使用模板变量，自动转义
    name = request.args.get('name', 'Guest')
    
    # 使用参数传递，而不是字符串拼接
    template = '<h1>Hello {{ name }}!</h1>'
    
    return render_template_string(template, name=escape(name))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    template = '<p>Search results for: {{ query }}</p>'
    return render_template_string(template, query=escape(query))
