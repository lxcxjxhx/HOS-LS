# Test Case ID: BL-B01
# Rule: code_security.business_logic
# Test Type: boundary
# Description: 测试环境的简化逻辑（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request
import os

app = Flask(__name__)

# 仅用于测试环境
if os.environ.get('ENV') == 'testing':
    
    @app.route('/test/checkout', methods=['POST'])
    def test_checkout():
        """测试环境 - 简化结账逻辑"""
        # 测试环境使用模拟数据
        items = request.json.get('items', [])
        
        # 简化计算用于测试
        total = sum(item.get('price', 0) for item in items)
        
        return {
            'total': total,
            'status': 'success',
            'environment': 'testing'
        }
        
    @app.route('/test/payment', methods=['POST'])
    def test_payment():
        """测试环境 - 模拟支付"""
        # 不实际处理支付，仅返回成功
        return {
            'transaction_id': 'test-txn-123',
            'status': 'success',
            'message': 'Test payment processed'
        }

# 注意：测试环境应该与生产环境完全隔离
