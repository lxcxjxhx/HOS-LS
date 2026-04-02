# Test Case ID: HSE-P01
# Rule: code_security.hardcoded_secrets_encoded
# Test Type: positive
# Description: Base64 编码的 API 密钥
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

import base64

# Base64 编码的密钥
api_key_encoded = base64.b64decode("c2stMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY=")
