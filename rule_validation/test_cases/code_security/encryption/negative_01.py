# Test Case ID: EN-N01
# Rule: code_security.encryption
# Test Type: negative
# Description: 正确的加密实践
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

def hash_password(password):
    """使用 bcrypt 或 Argon2 哈希密码"""
    import bcrypt
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def verify_password(password, hashed):
    import bcrypt
    return bcrypt.checkpw(password.encode(), hashed.encode())

def encrypt_sensitive_data(data, key):
    """使用 AES-256-GCM 加密"""
    aesgcm = AESGCM(key)
    nonce = os.random(12)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return base64.b64encode(nonce + ciphertext)

def store_credentials(username, password):
    # 存储哈希后的密码
    hashed = hash_password(password)
    db.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, hashed)
    )

def transmit_data(data):
    # 使用 HTTPS 传输
    requests.post(f'https://api.example.com/data', json=data)
