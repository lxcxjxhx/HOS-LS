# Test Case ID: XSS-P01
# Rule: injection_security.xss_injection
# Test Type: positive
# Description: XSS 注入 - 直接输出用户输入
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

# XSS 漏洞
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Search results for: {query}</h1>"  # XSS 漏洞
