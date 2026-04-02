# Test Case ID: HSE-P02
# Rule: code_security.hardcoded_secrets_encoded
# Test Type: positive
# Description: Hex 编码的密钥
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

# Hex 编码的密钥
api_key_hex = bytes.fromhex("736b3132333435363738393061626364656631323334353637383930")
