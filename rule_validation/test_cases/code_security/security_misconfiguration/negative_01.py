# Test Case ID: SM-N01
# Rule: code_security.security_misconfiguration
# Test Type: negative
# Description: 正确的安全配置
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask
from flask_cors import CORS
import os

app = Flask(__name__)

# 限制 CORS 来源
CORS(app, resources={r"/*": {"origins": ["https://trusted-domain.com"]}})

# 启用 CSRF 保护
app.config['WTF_CSRF_ENABLED'] = True

# 使用环境变量中的安全密钥
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32))

# 关闭调试模式
app.config['DEBUG'] = False
app.config['ENV'] = 'production'
