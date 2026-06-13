# XSS 跨站脚本攻击原理与知识

## 概述

跨站脚本攻击 (Cross-Site Scripting, XSS) 发生在应用程序将未经过滤或转义的用户输入输出到页面中时。攻击者可以注入恶意脚本，在其他用户的浏览器中执行，从而窃取 Cookie、会话令牌或执行任意操作。

## 触发条件

1. **用户输入未经过滤直接输出到 HTML 页面**
2. **未对上下文进行适当的编码/转义**
3. **使用危险的 DOM API 处理用户数据**

## 常见模式

### Java / JSP 中的危险模式

```java
// 危险：直接输出到响应
response.getWriter().write("<div>" + userInput + "</div>");

// 危险：JSP 表达式未转义
<%= request.getParameter("comment") %>

// 危险：拼接 HTML 属性
out.write("<img src='" + userAvatarUrl + "'>");
```

### JavaScript / 前端中的危险模式

```javascript
// 危险：innerHTML 直接赋值
element.innerHTML = userInput;

// 危险：document.write
document.write("<div>" + userInput + "</div>");

// 危险：eval 执行用户输入
eval(userInput);

// 危险：location 赋值
location.href = userInput;

// 安全：使用 textContent
element.textContent = userInput;
```

### Python / Flask 中的危险模式

```python
# 危险：render_template_string 未转义
return render_template_string("<div>{{ user_input|safe }}</div>")

# 危险：Markup 包装用户输入
return Markup(user_input)

# 安全：Jinja2 默认自动转义
return render_template("template.html", user_input=user_input)
```

## 攻击类型

- **反射型 XSS**: 恶意脚本通过 URL 参数注入，即时触发
- **存储型 XSS**: 恶意脚本存储在数据库中，每次页面加载触发
- **DOM 型 XSS**: 纯前端 DOM 操作触发，不经过服务端

## POC 验证要点

1. **基础 Payload**: `<script>alert(1)</script>`
2. **事件处理器**: `<img src=x onerror=alert(1)>`
3. **SVG 标签**: `<svg onload=alert(1)>`
4. **属性注入**: `"><script>alert(1)</script>`
5. **JavaScript URI**: `<a href="javascript:alert(1)">click</a>`
6. **DOM XSS**: 通过 `location.hash`、`document.URL` 等源触发

## 绕过技术

- **编码绕过**: HTML 实体编码, URL 编码, Unicode 编码
- **标签黑名单绕过**: 使用非常规标签如 `<math>`, `<details>`, `<marquee>`
- **事件名绕过**: `onfocus`, `onmouseover`, `onanimationend`
- **长度限制绕过**: 短 payload `javascript:alert(1)`, `<svg/onload=alert(1)>`

## 修复建议

- **输出编码**: 根据上下文 (HTML/JS/CSS/URL) 进行正确编码
- **CSP 策略**: 部署 Content-Security-Policy 头限制脚本来源
- **HttpOnly Cookie**: 防止 JS 读取敏感 Cookie
- **输入验证**: 白名单验证，拒绝危险字符
- **现代框架**: React/Vue 等框架默认对输出进行转义
