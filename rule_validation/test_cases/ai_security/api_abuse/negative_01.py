# Test Case ID: AA-N01
# Rule: ai_security.api_abuse
# Test Type: negative
# Description: 防止 AI API 滥用
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from functools import wraps
import time

app = Flask(__name__)

# 配置速率限制
limiter = Limiter(
    app=app,
    key_func=lambda: request.headers.get('X-API-Key', 'anonymous'),
    default_limits=["100 per hour"]
)

def content_filter(text):
    """内容过滤"""
    blocked_keywords = ['violence', 'hate', 'illegal']
    for keyword in blocked_keywords:
        if keyword.lower() in text.lower():
            return False
    return True

def log_api_usage(api_key, endpoint, tokens):
    """记录 API 使用情况"""
    usage_db.insert({
        'api_key': api_key,
        'endpoint': endpoint,
        'tokens': tokens,
        'timestamp': time.time()
    })
    
    # 检查是否超过配额
    daily_usage = usage_db.get_daily_total(api_key)
    if daily_usage > 100000:  # 每日 10 万 token 限制
        raise QuotaExceeded("Daily quota exceeded")

@app.route('/api/generate', methods=['POST'])
@limiter.limit("10 per minute")
def generate_text():
    api_key = request.headers.get('X-API-Key')
    prompt = request.json.get('prompt', '')
    
    # 内容过滤
    if not content_filter(prompt):
        return jsonify({'error': 'Invalid content'}), 400
    
    result = ai_model.generate(prompt)
    
    # 记录使用情况
    log_api_usage(api_key, 'generate', len(result))
    
    return jsonify({'result': result})
