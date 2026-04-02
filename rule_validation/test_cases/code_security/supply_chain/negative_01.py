# Test Case ID: SC-N01
# Rule: code_security.supply_chain
# Test Type: negative
# Description: 安全的供应链实践
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import requests
import subprocess
import hashlib
import os

def verify_package_signature(package_name, version):
    """验证包签名"""
    # 从可信源获取公钥
    public_key = load_public_key()
    
    # 验证包的签名
    signature = fetch_signature(package_name, version)
    if not verify_signature(package_name, signature, public_key):
        raise SecurityError("Package signature verification failed")

def download_file_secure(url, destination, expected_hash):
    """安全下载文件"""
    # 仅允许从可信源下载
    allowed_domains = ['cdn.example.com', 'releases.example.com']
    if not is_allowed_domain(url, allowed_domains):
        raise SecurityError("Untrusted download source")
    
    response = requests.get(url, timeout=30)
    
    # 验证文件哈希
    actual_hash = hashlib.sha256(response.content).hexdigest()
    if actual_hash != expected_hash:
        raise SecurityError("File hash mismatch")
    
    with open(destination, 'wb') as f:
        f.write(response.content)

def load_plugin_secure(plugin_path, expected_signature):
    """安全加载插件"""
    # 验证插件签名
    if not verify_plugin_signature(plugin_path, expected_signature):
        raise SecurityError("Plugin signature invalid")
    
    # 在沙箱中加载插件
    import sandbox
    sandbox.load_module(plugin_path)

def is_allowed_domain(url, allowed_domains):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc in allowed_domains
