# Test Case ID: HS-N01
# Rule: code_security.hardcoded_secrets
# Test Type: negative
# Description: 使用环境变量（安全做法）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import os

api_key = os.environ.get("OPENAI_API_KEY")
db_password = os.getenv("DB_PASSWORD")
aws_key = os.environ["AWS_ACCESS_KEY_ID"]
