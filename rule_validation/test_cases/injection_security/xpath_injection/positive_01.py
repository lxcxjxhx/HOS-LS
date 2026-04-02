# Test Case ID: XI-P01
# Rule: injection_security.xpath_injection
# Test Type: positive
# Description: XPath 注入漏洞
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

from lxml import etree

def find_user(xml_doc, username, password):
    # 直接使用用户输入构造 XPath 查询（危险）
    # 攻击者可以输入：' or '1'='1
    query = f"//users/user[name='{username}' and password='{password}']"
    
    # XPath 注入：' or '1'='1' or '
    result = xml_doc.xpath(query)
    
    return len(result) > 0

def search_products(xml_doc, category):
    # 另一个 XPath 注入点
    xpath_query = f"//product[category='{category}']"
    return xml_doc.xpath(xpath_query)
