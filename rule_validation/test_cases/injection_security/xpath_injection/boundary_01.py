# Test Case ID: XI-B01
# Rule: injection_security.xpath_injection
# Test Type: boundary
# Description: 使用白名单验证 XPath 查询
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from lxml import etree

ALLOWED_CATEGORIES = ['electronics', 'books', 'clothing', 'home']

def search_products(xml_doc, category):
    # 白名单验证类别
    if category not in ALLOWED_CATEGORIES:
        return []
    
    # 使用预定义的 XPath
    category_map = {
        'electronics': "//product[category='electronics']",
        'books': "//product[category='books']",
        'clothing': "//product[category='clothing']",
        'home': "//product[category='home']"
    }
    
    xpath_query = category_map[category]
    return xml_doc.xpath(xpath_query)
