# Test Case ID: EN-P01
# Rule: code_security.encryption
# Test Type: positive
# Description: 加密使用不当
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from Crypto.Cipher import DES, AES
import hashlib

# 使用弱加密算法
def encrypt_password(password):
    # 使用 MD5 哈希（不安全）
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_data(data, key):
    # 使用 DES 加密（已破解）
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

def store_credentials(username, password):
    # 明文存储密码
    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password)
    )
    
def transmit_data(data):
    # 使用 HTTP 传输敏感数据
    requests.post(f'http://api.example.com/data', json=data)
