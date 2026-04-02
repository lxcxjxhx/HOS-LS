# Test Case ID: PATH-N01
# Rule: injection_security.path_traversal
# Test Type: negative
# Description: 路径验证（安全）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# 安全的路径验证
import os

def safe_read(filename):
    base_dir = "/var/www/html"
    safe_path = os.path.join(base_dir, os.path.basename(filename))
    if not safe_path.startswith(base_dir):
        raise ValueError("Invalid path")
    with open(safe_path, 'r') as f:
        return f.read()
