# Test Case ID: HSE-N01
# Rule: code_security.hardcoded_secrets_encoded
# Test Type: negative
# Description: 正常的 Base64 编码（非密钥）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import base64

# 正常的 Base64 编码数据
message = "Hello, World!"
encoded = base64.b64encode(message.encode())
decoded = base64.b64decode(encoded)
