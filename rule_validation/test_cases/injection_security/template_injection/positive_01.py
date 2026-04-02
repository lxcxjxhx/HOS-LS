# Test Case ID: TI-P01
# Rule: injection_security.template_injection
# Test Type: positive
# Description: 模板注入漏洞（SSTI）
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    # 直接将用户输入传递给模板引擎（危险）
    name = request.args.get('name', 'Guest')
    
    # SSTI 漏洞：攻击者可以输入 {{config}} 或 {{''.__class__.__mro__}}
    template = f'<h1>Hello {name}!</h1>'
    
    return render_template_string(template)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # 另一个 SSTI 漏洞
    template = f'<p>Search results for: {query}</p>'
    return render_template_string(template)
