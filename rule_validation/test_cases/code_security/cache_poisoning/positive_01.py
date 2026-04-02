# Test Case ID: CP-P01
# Rule: code_security.cache_poisoning
# Test Type: positive
# Description: 缓存投毒风险
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

from flask import Flask, request, make_response
import hashlib

app = Flask(__name__)

@app.route('/user/<user_id>')
def get_user(user_id):
    # 缓存键仅基于 URL
    cache_key = hashlib.md5(request.url.encode()).hexdigest()
    
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    # 问题：没有考虑用户权限
    # 攻击者可以访问缓存的敏感数据
    user_data = get_user_data(user_id)
    
    response = make_response(user_data)
    cache.set(cache_key, response)
    return response

@app.route('/search')
def search():
    query = request.args.get('q')
    
    # 缓存键没有考虑用户上下文
    cache_key = f"search:{query}"
    
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    results = search_database(query)
    cache.set(cache_key, results, timeout=3600)
    return results
