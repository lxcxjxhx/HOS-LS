# Test Case ID: IV-N01
# Rule: code_security.input_validation
# Test Type: negative
# Description: 实现输入验证
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request
import re
from validate_email_address import validate_email

app = Flask(__name__)

def validate_user_id(user_id):
    """验证用户 ID 格式"""
    if not re.match(r'^[0-9]+$', user_id):
        raise ValueError("Invalid user ID format")
    if len(user_id) > 10:
        raise ValueError("User ID too long")
    return int(user_id)

def validate_email(email):
    """验证邮箱格式"""
    if not email or len(email) > 255:
        raise ValueError("Invalid email")
    if not validate_email(email):
        raise ValueError("Invalid email format")
    return email.lower().strip()

def validate_phone(phone):
    """验证手机号格式"""
    if not re.match(r'^\+?[0-9]{10,15}$', phone):
        raise ValueError("Invalid phone format")
    return phone

def validate_age(age):
    """验证年龄范围"""
    age_int = int(age)
    if age_int < 0 or age_int > 150:
        raise ValueError("Invalid age range")
    return age_int

@app.route('/user/<user_id>')
def get_user(user_id):
    validated_id = validate_user_id(user_id)
    return get_user_from_db(validated_id)
