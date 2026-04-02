# Test Case ID: XX-B01
# Rule: injection_security.xxe_injection
# Test Type: boundary
# Description: 使用 defusedxml 安全库
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import xml.etree.ElementTree as ET
from defusedxml import ElementTree as DefusedET
from flask import Flask, request

app = Flask(__name__)

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.get_data()
    
    try:
        # 使用 defusedxml 防止 XXE 攻击
        tree = DefusedET.fromstring(xml_data)
        return ET.tostring(tree)
    except Exception as e:
        return str(e), 400

# defusedxml 是专门用于安全解析 XML 的库
# 自动防止 XXE、 billion laughs 等攻击
