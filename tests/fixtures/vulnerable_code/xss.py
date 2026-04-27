"""XSS 漏洞示例代码

用于测试 XSS 检测规则。
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/vulnerable1")
def vulnerable_xss_1():
    """直接返回请求内容"""
    name = request.args.get("name")
    return f"<h1>Hello {name}</h1>"


@app.route("/vulnerable2")
def vulnerable_xss_2():
    """render_template_string 拼接"""
    template = "<h1>Hello " + request.args.get("name") + "</h1>"
    return render_template_string(template)


@app.route("/vulnerable3")
def vulnerable_xss_3():
    """mark_safe 使用"""
    from django.utils.safestring import mark_safe
    user_input = request.GET.get("content")
    return mark_safe(user_input)


@app.route("/safe1")
def safe_xss_1():
    """安全的模板渲染"""
    name = request.args.get("name", "")
    return render_template("greeting.html", name=name)
