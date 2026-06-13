# CSRF 原理与测试技术

## 漏洞原理
跨站请求伪造 (Cross-Site Request Forgery, CSRF) 是一种利用用户已认证的会话状态，诱使用户浏览器向目标网站发送非预期请求的攻击。攻击者无法直接读取响应，但可以执行状态变更操作（修改密码、转账、更改设置等）。

核心机制：
- **浏览器自动携带凭证**：Cookie、HTTP Authentication 等凭证由浏览器自动附加到同源请求中
- **请求可被伪造**：GET/POST 等 HTTP 请求可以被第三方页面构造并触发
- **服务端未验证请求来源**：缺乏 CSRF Token 或 Referer/Origin 验证

CSRF 与 XSS 的区别：CSRF 利用用户身份发送请求（不需要注入代码），XSS 在用户浏览器中执行代码。CSRF 的威力通常受限于用户权限。

## 漏洞类型与变种

### 1. 简单 CSRF (GET/POST)
- **GET 型 CSRF**：通过 `<img src>`、`<iframe src>` 等标签触发 GET 请求
- **POST 型 CSRF**：通过自动提交的 HTML 表单触发 POST 请求

### 2. JSON CSRF
- **Content-Type 绕过**：表单提交 `application/x-www-form-urlencoded` 但后端仅检查 URL 和 Method，未验证 Content-Type
- **CORS 预检绕过**：某些框架不执行 CORS 预检即可接收 JSON 请求
- **Body 格式**：构造 `{"key":"value"}` 格式的表单字段名

### 3.  multipart/form-data CSRF
文件上传表单的 CSRF 攻击，可伪造带文件上传的请求。

### 4. Flash/插件 CSRF
利用 Flash 的 `crossdomain.xml` 配置不当发起跨域请求（较老旧）。

### 5. 基于 URL 的 CSRF
利用协议处理器、书签、浏览器自动补全等触发请求。

### 6. 登录 CSRF
强制用户以攻击者控制的账户登录，后续操作关联到攻击者账户。

## 检测方法

### 手动检测流程
1. **识别状态变更操作**：列出所有修改数据的接口（POST/PUT/DELETE/PATCH）
2. **检查 CSRF 防护**：
   - 是否存在 CSRF Token（隐藏字段、Header）
   - Token 是否可预测/可重用/可缺失
   - 是否验证 Referer/Origin 头
3. **尝试移除 Token**：删除 CSRF Token 参数，观察请求是否仍被处理
4. **尝试替换 Token**：使用其他会话的 Token，观察是否接受
5. **尝试空 Token**：提交空值 CSRF Token
6. **方法切换**：将 POST 改为 GET，观察是否绕过 CSRF 检查

### 自动化检测策略
1. **Token 分析**：
   - 检查每个状态变更请求是否携带 CSRF Token
   - Token 是否与会话绑定（不同会话的 Token 应不同）
   - Token 是否具有足够的随机性（长度 ≥ 16 字节）
2. **Referer/Origin 检查**：
   - 移除 Referer/Origin 头后请求是否成功
   - 修改 Referer 为攻击者域名后请求是否成功
   - Referer 前缀匹配是否可绕过（`attacker.com.evil.com`）
3. **CORS 配置检查**：
   - `Access-Control-Allow-Origin: *` 配合 `Access-Control-Allow-Credentials: true`
   - 动态 Origin 回显

### 检测清单
- [ ] 所有状态变更操作（POST/PUT/DELETE/PATCH）都有 CSRF 保护
- [ ] CSRF Token 不可预测、与会话绑定、每次请求变化
- [ ] 非幂等操作不接受 GET 请求
- [ ] SameSite Cookie 属性已设置
- [ ] CORS 策略限制可信来源

## 常见脆弱模式

### 缺少 CSRF Token
```java
// 危险：无 CSRF 保护的 POST 端点
@PostMapping("/api/transfer")
public ResponseEntity transfer(@RequestBody TransferRequest req) {
    // 直接处理转账，未检查 CSRF Token
}

// 安全：启用 CSRF 保护（Spring Security 默认开启）
http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
```

```python
# 危险：Flask 无 CSRF 保护
@app.route('/change-password', methods=['POST'])
def change_password():
    user.password = request.form['new_password']
    db.session.commit()

# 安全：使用 Flask-WTF CSRF
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

### CSRF Token 验证缺陷
```java
// 危险：Token 仅检查存在性，不验证正确性
String token = request.getParameter("csrf_token");
if (token != null && !token.isEmpty()) {
    // 仅检查非空，未验证是否与 Session Token 匹配
    processRequest();
}

// 危险：Token 未与 Session 绑定
// 所有用户共享同一个 CSRF Token（如应用级固定 Token）

// 安全：验证 Token 与 Session 绑定
String sessionToken = (String) session.getAttribute("CSRF_TOKEN");
if (!sessionToken.equals(request.getParameter("csrf_token"))) {
    throw new CsrfException("Invalid CSRF token");
}
```

### Referer 验证绕过
```java
// 危险：Referer 验证不完整
String referer = request.getHeader("Referer");
if (referer != null && referer.contains("mydomain.com")) {
    // 绕过：referer = "https://mydomain.com.evil.com/attack"
    processRequest();
}

// 安全：严格匹配 Origin 或 Referer 域名
String origin = request.getHeader("Origin");
URI originUri = URI.create(origin);
if (!originUri.getHost().equals("mydomain.com")) {
    throw new SecurityException("Invalid origin");
}
```

### SameSite Cookie 未设置
```java
// 危险：Cookie 未设置 SameSite 属性
Cookie cookie = new Cookie("session", sessionId);
// 默认 SameSite=None（部分浏览器）或 Lax（现代浏览器）

// 安全：显式设置 SameSite=Strict 或 SameSite=Lax
ResponseCookie cookie = ResponseCookie.from("session", sessionId)
    .sameSite("Strict")
    .httpOnly(true)
    .secure(true)
    .build();
```

## 绕过技巧

### CSRF Token 绕过
| 技术 | 方法 |
|------|------|
| 空 Token | 提交空值或移除 Token 字段 |
| Token 重用 | 使用之前捕获的 Token |
| 跨会话 Token | 使用用户 A 的 Token 操作用户 B 的会话 |
| 方法切换 | POST → GET 绕过 CSRF 检查（某些框架仅保护 POST） |
| Token 预测 | Token 基于时间戳或用户 ID 生成 |

### Referer/Origin 绕过
| 技术 | 方法 |
|------|------|
| Referer 缺失 | 使用 `<meta name="referrer" content="never">` 阻止发送 Referer |
| 域名混淆 | `https://mydomain.com.attacker.com/` |
| 子域名 | `https://sub.mydomain.com.evil.com/` |
| Referer 截断 | 超长 Referer 导致后端截断检查 |
| Origin 拼接 | `Origin: null`（某些沙箱/本地文件） |

### 其他绕过
- **307 重定向**：利用 307 重定向保持 POST Method 发送 CSRF 请求
- **Flash 跨域**：旧版 Flash 的 `crossdomain.xml` 配置不当
- **CORS 绕过**：`Access-Control-Allow-Origin: null` 接受沙箱请求
- **JSON CSRF**：表单提交构造 JSON 格式数据（`{"csrf_token":"...","data":"..."}`）

## 验证策略

### POC 生成建议
1. **CSRF Token 分析**：
   - 检查请求中是否包含 CSRF Token
   - 尝试移除 Token 后重新发送请求
   - 尝试使用无效 Token 发送请求
2. **Referer/Origin 验证**：
   - 移除 Referer 头发送请求
   - 修改 Referer 为外部域名
   - 检查 Referer 验证逻辑是否严格
3. **方法切换测试**：
   - POST 端点尝试 GET 请求
   - 检查幂等性保护

### 标准 CSRF POC HTML
```html
<!-- GET 型 CSRF POC -->
<img src="https://target.com/api/action?param=value" />

<!-- POST 型 CSRF POC -->
<form action="https://target.com/api/action" method="POST" id="csrf-form">
    <input type="hidden" name="param" value="value" />
</form>
<script>document.getElementById('csrf-form').submit();</script>

<!-- JSON CSRF POC (Content-Type 不严格时) -->
<form action="https://target.com/api/json-action" method="POST" 
      enctype="text/plain" id="json-csrf">
    <input type="hidden" name='{"key":"value","other":"' value='test"}' />
</form>
```

### 验证成功标志
- 无 CSRF Token 时请求仍被成功处理
- 无效/过期 CSRF Token 被接受
- 从外部域名发起的请求被成功处理（Referer 为外部域名）
- GET 请求执行了状态变更操作

## 安全注意事项

### 测试安全边界
- **禁止**：实际执行敏感操作（转账、改密、删除数据）
- **推荐**：使用测试账户验证 CSRF 可行性
- **推荐**：CSRF POC 应仅展示请求构造能力，不实际提交
- **推荐**：记录漏洞的潜在影响范围和受影响的操作

### 防护建议
- **CSRF Token**：每个表单/请求包含不可预测的 Token，与 Session 绑定
- **SameSite Cookie**：设置 `SameSite=Strict` 或 `SameSite=Lax`
- **自定义 Header**：要求 AJAX 请求携带自定义 Header（如 `X-CSRF-Token`）
- **双重提交 Cookie**：CSRF Token 同时存在于 Cookie 和请求参数中
- **Referer 验证**：严格验证请求来源域名
- **用户确认**：敏感操作要求用户重新输入密码或进行二次验证
