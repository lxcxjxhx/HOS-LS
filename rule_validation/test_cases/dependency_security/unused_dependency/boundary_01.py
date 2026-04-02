# Test Case ID: UF-B01
# Rule: dependency_security.unused_dependency
# Test Type: boundary
# Description: 条件导入的依赖（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# requirements.txt 内容:
# requests==2.31.0
# django==4.2.0
# optional-lib==1.0.0  # 可选依赖

# main.py
import requests
from django.conf import settings

# 可选功能依赖
try:
    import optional_lib  # 仅在需要时使用
    OPTIONAL_FEATURE_ENABLED = True
except ImportError:
    OPTIONAL_FEATURE_ENABLED = False

def process_data(data):
    if OPTIONAL_FEATURE_ENABLED:
        return optional_lib.enhanced_process(data)
    return basic_process(data)
