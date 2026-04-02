# Test Case ID: HSC-B01
# Rule: code_security.hardcoded_secrets_cloud
# Test Type: boundary
# Description: 类似 AWS Key 但不是（边界情况）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# 类似 AWS Key 格式的普通字符串（应该不误报）
example_key = "AKIAEXAMPLE1234567"  # 示例 ID
