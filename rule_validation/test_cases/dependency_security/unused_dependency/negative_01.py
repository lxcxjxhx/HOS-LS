# Test Case ID: UF-N01
# Rule: dependency_security.unused_dependency
# Test Type: negative
# Description: 所有依赖都被使用
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# requirements.txt 内容:
# requests==2.31.0
# django==4.2.0
# celery==5.3.0
# redis==4.6.0

# main.py
import requests
from django.conf import settings
from celery import Celery
import redis

# 所有导入的包都在 requirements.txt 中
# 所有安装的包都在代码中使用

app = Celery('tasks', broker='redis://localhost:6379')

def fetch_data(url):
    return requests.get(url).json()
