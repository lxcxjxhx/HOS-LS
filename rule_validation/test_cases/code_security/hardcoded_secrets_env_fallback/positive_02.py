# Test Case ID: HSEF-P02
# Rule: code_security.hardcoded_secrets_env_fallback
# Test Type: positive
# Description: 环境变量 fallback 默认值
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

import os

# Python 风格 fallback - 硬编码密钥作为默认值
db_password = os.getenv('DB_PASSWORD', 'SuperSecret123!')
api_key = os.getenv('API_KEY', 'sk-1234567890abcdef')
secret_key = os.getenv('SECRET_KEY', 'default-secret-key')

# 如果环境变量未设置，将使用硬编码的默认值（危险）
