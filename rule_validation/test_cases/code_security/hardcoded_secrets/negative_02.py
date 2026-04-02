# Test Case ID: HS-N02
# Rule: code_security.hardcoded_secrets
# Test Type: negative
# Description: 使用 dotenv 加载配置（安全做法）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.environ.get("API_KEY")
secret = os.getenv("SECRET_TOKEN")
