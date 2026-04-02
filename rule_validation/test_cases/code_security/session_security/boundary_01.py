# Test Case ID: SS-B01
# Rule: code_security.session_security
# Test Type: boundary
# Description: 开发环境会话配置（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, session
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key')

# 开发环境配置（仅限本地）
if os.environ.get('FLASK_ENV') == 'development':
    app.config['SESSION_COOKIE_SECURE'] = False  # 允许 HTTP
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
else:
    # 生产环境配置
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
