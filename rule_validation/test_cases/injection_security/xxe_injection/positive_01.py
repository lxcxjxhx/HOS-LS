# Test Case ID: XX-P01
# Rule: injection_security.xxe_injection
# Test Type: positive
# Description: XXE（XML 外部实体）注入漏洞
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

from lxml import etree
from flask import Flask, request

app = Flask(__name__)

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.get_data()
    
    # 没有禁用外部实体解析（危险）
    parser = etree.XMLParser()  # 默认允许外部实体
    
    try:
        tree = etree.fromstring(xml_data, parser)
        return etree.tostring(tree)
    except Exception as e:
        return str(e), 400

# 攻击者可以发送：
# <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
# <foo>&xxe;</foo>
