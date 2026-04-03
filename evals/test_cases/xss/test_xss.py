# XSS 测试用例

def vulnerable_comment(comment):
    # 存在 XSS 漏洞的评论函数
    # 直接将用户输入插入到 HTML 中
    html = f"<div class='comment'>{comment}</div>"
    print(f"生成 HTML: {html}")
    return html

# 测试调用
vulnerable_comment('<script>alert("XSS")</script>')