# Test Case ID: BL-P01
# Rule: code_security.business_logic
# Test Type: positive
# Description: 业务逻辑漏洞
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, request, session

app = Flask(__name__)

@app.route('/checkout', methods=['POST'])
def checkout():
    """结账逻辑漏洞"""
    items = request.json.get('items', [])
    coupon = request.json.get('coupon')
    
    total = 0
    for item in items:
        # 问题：使用客户端提供的价格
        total += item.get('price', 0) * item.get('quantity', 1)
    
    # 问题：没有验证优惠券使用条件
    if coupon:
        if coupon == 'FREE100':
            total = 0  # 可以直接免费
    
    # 问题：没有检查库存
    # 问题：没有验证用户购买资格
    
    process_payment(total)
    return {'total': total, 'status': 'success'}

@app.route('/transfer', methods=['POST'])
def transfer_money():
    """转账逻辑漏洞"""
    amount = request.json.get('amount', 0)
    to_account = request.json.get('to_account')
    
    # 问题：没有检查余额是否足够
    # 问题：没有验证转账限额
    # 问题：没有防止负数转账
    
    if amount < 0:
        # 负数转账可以盗取资金
        pass
    
    execute_transfer(amount, to_account)
    return {'status': 'success'}
