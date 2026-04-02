# Test Case ID: IV-P01
# Rule: code_security.input_validation
# Test Type: positive
# Description: 缺少输入验证
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, request

app = Flask(__name__)

@app.route('/user/<user_id>')
def get_user(user_id):
    # 没有验证 user_id 格式
    # 可能是 SQL 注入、XSS 等攻击
    return get_user_from_db(user_id)

@app.route('/search')
def search():
    query = request.args.get('q')
    # 没有验证查询参数
    # 长度、字符集、格式都没有限制
    return search_database(query)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    email = request.form.get('email')
    phone = request.form.get('phone')
    age = request.form.get('age')
    
    # 没有验证输入格式
    # email 可能是无效格式
    # phone 可能包含恶意代码
    # age 可能是负数或超大值
    
    return update_user_profile(email, phone, age)
