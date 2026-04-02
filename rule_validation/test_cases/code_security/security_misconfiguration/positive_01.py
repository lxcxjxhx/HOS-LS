# Test Case ID: SM-P01
# Rule: code_security.security_misconfiguration
# Test Type: positive
# Description: 安全配置缺失或错误
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# 允许所有来源的 CORS 请求（不安全）
CORS(app, resources={r"/*": {"origins": "*"}})

# 关闭 CSRF 保护
app.config['WTF_CSRF_ENABLED'] = False

# 使用默认密钥
app.config['SECRET_KEY'] = 'dev-secret-key'

# 开启调试模式（生产环境不应该）
app.config['DEBUG'] = True
