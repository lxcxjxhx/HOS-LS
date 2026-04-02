# Test Case ID: XI-N01
# Rule: injection_security.xpath_injection
# Test Type: negative
# Description: 安全的 XPath 查询
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from lxml import etree

def find_user(xml_doc, username, password):
    # 使用参数化 XPath 查询
    # 定义变量
    variables = {'username': username, 'password': password}
    
    # 使用变量绑定，避免注入
    query = "//users/user[name=$username and password=$password]"
    result = xml_doc.xpath(query, variables=variables)
    
    return len(result) > 0

def search_products(xml_doc, category):
    # 使用参数化查询
    variables = {'category': category}
    xpath_query = "//product[category=$category]"
    return xml_doc.xpath(xpath_query, variables=variables)
