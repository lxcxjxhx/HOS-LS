# Test Case ID: BL-N01
# Rule: code_security.business_logic
# Test Type: negative
# Description: 正确的业务逻辑实现
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request, session
from decimal import Decimal

app = Flask(__name__)

def get_server_price(item_id):
    """从服务器获取价格（不信任客户端）"""
    item = db.query("SELECT price FROM items WHERE id = ?", item_id)
    return Decimal(str(item.price))

def validate_coupon(coupon_code, user_id):
    """验证优惠券"""
    coupon = db.query(
        "SELECT * FROM coupons WHERE code = ? AND user_id = ?",
        coupon_code, user_id
    )
    
    if not coupon:
        raise ValueError("Invalid coupon")
    if coupon.used:
        raise ValueError("Coupon already used")
    if coupon.expired:
        raise ValueError("Coupon expired")
    
    return coupon

def check_inventory(item_id, quantity):
    """检查库存"""
    item = db.query("SELECT stock FROM items WHERE id = ?", item_id)
    if item.stock < quantity:
        raise ValueError("Insufficient stock")

@app.route('/checkout', methods=['POST'])
def checkout():
    user_id = session.get('user_id')
    item_ids = request.json.get('items', [])
    coupon = request.json.get('coupon')
    
    total = Decimal('0')
    for item_id in item_ids:
        # 使用服务器端价格
        price = get_server_price(item_id)
        check_inventory(item_id, 1)
        total += price
    
    # 验证优惠券
    if coupon:
        valid_coupon = validate_coupon(coupon, user_id)
        total = total * (1 - valid_coupon.discount)
    
    # 验证最小金额
    if total < 0:
        raise ValueError("Invalid total")
    
    process_payment(user_id, total)
    return {'total': str(total), 'status': 'success'}
