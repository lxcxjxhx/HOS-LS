# Test Case ID: CP-N01
# Rule: code_security.cache_poisoning
# Test Type: negative
# Description: 安全的缓存策略
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, session
import hashlib

app = Flask(__name__)

def generate_safe_cache_key(prefix, user_id=None, params=None):
    """生成安全的缓存键"""
    key_parts = [prefix]
    
    # 包含用户 ID 以隔离不同用户的数据
    if user_id:
        key_parts.append(f"user:{user_id}")
    
    # 包含所有查询参数
    if params:
        sorted_params = sorted(params.items())
        key_parts.append(str(sorted_params))
    
    key_string = ":".join(key_parts)
    return hashlib.sha256(key_string.encode()).hexdigest()

@app.route('/user/<user_id>')
def get_user(user_id):
    # 缓存键包含用户 ID
    cache_key = generate_safe_cache_key(
        'user_profile',
        user_id=session.get('user_id'),
        params={'target_user': user_id}
    )
    
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    # 检查权限
    if not can_access_user(session.get('user_id'), user_id):
        abort(403)
    
    user_data = get_user_data(user_id)
    cache.set(cache_key, user_data, timeout=300)
    return user_data
