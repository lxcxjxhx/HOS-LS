# Test Case ID: TI-B01
# Rule: injection_security.template_injection
# Test Type: boundary
# Description: 使用白名单模板
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, render_template

app = Flask(__name__)

# 预定义的安全模板
TEMPLATES = {
    'greeting': 'greeting.html',
    'search': 'search.html',
    'profile': 'profile.html'
}

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # 使用预编译的模板文件，而不是动态模板字符串
    return render_template('greeting.html', name=name)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template('search.html', query=query)
