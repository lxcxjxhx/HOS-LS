# Test Case ID: EN-B01
# Rule: code_security.encryption
# Test Type: boundary
# Description: 非敏感数据加密（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import hashlib

def hash_public_identifier(data):
    """哈希公开标识符（非安全用途）"""
    # 用于生成唯一标识符，不是密码学用途
    return hashlib.sha256(data.encode()).hexdigest()[:16]

def checksum_file(filepath):
    """文件校验和验证"""
    # 用于检测文件损坏，不是安全用途
    with open(filepath, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

def generate_display_id():
    """生成显示用的 ID"""
    # 仅用于用户界面显示，不是安全用途
    import random
    return f"ID-{random.randint(10000, 99999)}"

# 注意：这些函数不用于安全敏感场景
