# Test Case ID: AA-B01
# Rule: ai_security.api_abuse
# Test Type: boundary
# Description: 内部开发环境（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# 仅开发环境使用
if os.environ.get('ENV') == 'development':
    
    @app.route('/api/dev/generate', methods=['POST'])
    def dev_generate():
        """开发环境 - 无限制用于测试"""
        prompt = request.json.get('prompt', '')
        
        # 开发环境允许自由测试
        result = ai_model.generate(prompt)
        
        return jsonify({
            'result': result,
            'environment': 'development'
        })
        
    @app.route('/api/dev/benchmark')
    def dev_benchmark():
        """性能基准测试"""
        # 用于性能测试，允许高频调用
        results = []
        for i in range(100):
            result = ai_model.generate(f"Test {i}")
            results.append(len(result))
            
        return jsonify({
            'avg_length': sum(results) / len(results),
            'test_count': len(results)
        })

# 注意：开发环境应该与生产环境隔离
