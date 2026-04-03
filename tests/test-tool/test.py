#!/usr/bin/env python3
# 测试文件，包含各种安全问题

# 硬编码的API密钥
api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"

# 硬编码的密码
password = "mysecretpassword123"

# 硬编码的token
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# 潜在的后门代码
import os
exec("print('Hello World')")
system("echo 'This is a test'")

# 网络访问代码
import requests
response = requests.get("https://api.example.com")

# 硬编码的IP和端口
server_ip = "192.168.1.1"
server_port = 8080
