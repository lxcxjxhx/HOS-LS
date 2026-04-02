# Test Case ID: UF-P01
# Rule: dependency_security.unused_dependency
# Test Type: positive
# Description: 未使用的依赖
# Expected Detection: true
# Expected Severity: LOW
# Code Type: vulnerable

# requirements.txt 内容:
# requests==2.31.0
# django==4.2.0
# flask==2.3.0      # 未使用
# numpy==1.24.0     # 未使用
# pandas==2.0.0     # 未使用

# main.py
import requests
from django.conf import settings

# flask, numpy, pandas 已安装但未在代码中使用
# 增加攻击面和维护成本

def main():
    response = requests.get('https://api.example.com')
    return response.json()
