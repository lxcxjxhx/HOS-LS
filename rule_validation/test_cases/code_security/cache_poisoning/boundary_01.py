# Test Case ID: CP-B01
# Rule: code_security.cache_poisoning
# Test Type: boundary
# Description: 公开数据的缓存（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request
import hashlib

app = Flask(__name__)

@app.route('/api/public/products')
def list_products():
    """公开产品列表 - 可以安全缓存"""
    # 公开数据，所有用户相同
    cache_key = hashlib.md5(request.url.encode()).hexdigest()
    
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    products = get_public_products()
    
    # 设置较短的缓存时间
    cache.set(cache_key, products, timeout=60)
    return products

@app.route('/api/public/categories')
def list_categories():
    """公开分类 - 可以安全缓存"""
    cache_key = "public:categories"
    
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    categories = get_categories()
    cache.set(cache_key, categories, timeout=3600)
    return categories

# 这些是公开数据，不需要用户级别的缓存隔离
