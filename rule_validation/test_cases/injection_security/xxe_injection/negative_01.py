# Test Case ID: XX-N01
# Rule: injection_security.xxe_injection
# Test Type: negative
# Description: 安全的 XML 解析，禁用外部实体
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from lxml import etree
from flask import Flask, request

app = Flask(__name__)

def safe_parse_xml(xml_data):
    """安全的 XML 解析"""
    # 禁用外部实体解析
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        huge_tree=False
    )
    
    tree = etree.fromstring(xml_data, parser)
    return tree

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.get_data()
    
    try:
        tree = safe_parse_xml(xml_data)
        return etree.tostring(tree, pretty_print=True)
    except Exception as e:
        return str(e), 400
