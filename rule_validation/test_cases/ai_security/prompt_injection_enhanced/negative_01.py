# Test Case ID: PIE-N01
# Rule: ai_security.prompt_injection_enhanced
# Test Type: negative
# Description: 正常的多行输入
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# 正常的多行用户输入
user_query = """
What is the weather today?
And tell me about Python programming.
"""
