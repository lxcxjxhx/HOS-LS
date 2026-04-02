# Test Case ID: SM-B01
# Rule: code_security.security_misconfiguration
# Test Type: boundary
# Description: 开发环境配置（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask
import os

app = Flask(__name__)

# 开发环境配置（仅限本地）
if os.environ.get('FLASK_ENV') == 'development':
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = 'dev-key-for-local-only'
else:
    # 生产环境配置
    app.config['DEBUG'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
