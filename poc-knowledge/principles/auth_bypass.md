# 认证绕过原理与测试技术

## 漏洞原理
认证绕过 (Authentication Bypass) 是指攻击者通过利用身份验证或授权机制中的缺陷，在未提供有效凭证或越权的情况下访问受限资源。根本原因通常包括：
- **认证与授权逻辑分离不当**：认证检查被绕过或缺失
- **状态管理缺陷**：会话/令牌验证逻辑存在漏洞
- **配置错误**：安全策略配置不当或默认设置未修改
- **业务逻辑缺陷**：流程中的条件分支可被操纵
- **信任边界混淆**：过度信任客户端提交的数据

## 漏洞类型与变种

### 1. JWT 漏洞
JSON Web Token 是常见的无状态认证机制，存在多种绕过方式：
- **算法混淆 (Algorithm Confusion)**：将 RS256（非对称）改为 HS256（对称），用公钥作为 HMAC 密钥签名
- **alg: none 攻击**：设置 `{"alg":"none"}` 绕过签名验证
- **弱密钥爆破**：使用常见密钥（`secret`, `password`, `123456`）暴力破解 HMAC 签名
- **密钥泄露**：硬编码密钥、配置文件暴露、Git 历史泄漏
- **JWK 注入**：通过 `jwk` 头注入自定义公钥
- **JKU/XKU 操纵**：修改 JWKS URL 指向攻击者控制的密钥集

### 2. Cookie 篡改
- **参数修改**：直接修改 Cookie 中的 `user_id`, `role`, `is_admin` 等字段
- **Cookie 伪造**：若 Cookie 未签名或使用弱签名，可伪造任意值
- **Cookie 注入**：通过 CRLF 注入设置额外 Cookie
- **Remember Me 绕过**：利用持久化令牌的可预测性或重用漏洞

### 3. 参数污染 / 参数覆盖
- **多值参数**：`role=user&role=admin`，后端取第一个 vs 取最后一个
- **JSON 参数覆盖**：`{"role": "user", "role": "admin"}`
- **数组注入**：`role[]=user&role[]=admin`
- **嵌套对象覆盖**：`__proto__.isAdmin=true`（原型链污染）

### 4. 默认凭证
- 使用出厂默认用户名/密码（`admin/admin`, `root/root`, `admin:password123`）
- 安装向导未强制修改默认密码
- 测试/调试账户未在生产环境禁用
- 硬编码后门账户

### 5. 逻辑漏洞
- **水平越权 (IDOR)**：同级别用户通过修改 ID 访问他人数据
- **垂直越权**：低权限用户访问高权限功能
- **认证流程跳过**：直接访问流程中后续步骤（如跳过密码验证，直接调用设置密码接口）
- **条件竞争**：利用并发请求在状态检查与状态变更之间插入操作
- **密码重置绕过**：操纵重置 token、验证码逻辑
- **OAuth/SSO 缺陷**：redirect_uri 操纵、state 参数缺失

### 6. 会话管理缺陷
- **会话固定 (Session Fixation)**：攻击者预设 Session ID，用户登录后继承权限
- **会话未失效**：登出后 Session 仍有效
- **可预测的 Session ID**：使用序列号或弱随机数生成
- **Session 劫持**：通过 XSS 或网络嗅探获取 Session

## 检测方法

### JWT 检测
1. **解码 Token**：使用 base64 解码 header 和 payload，分析结构
2. **算法测试**：修改 `alg` 为 `none`/`HS256`，观察是否接受
3. **密钥爆破**：对 HS256 token 使用常见密钥字典进行验证
4. **过期时间检查**：修改 `exp` 字段测试是否验证过期

### 接口认证检测
1. **未认证访问**：不带 token 直接请求受保护端点
2. **低权限高用**：使用普通用户 token 请求管理员接口
3. **跨用户访问**：使用用户 A 的 token 访问用户 B 的资源（修改 ID）
4. **方法绕过**：将 POST 改为 GET/PUT/DELETE/PATCH 观察权限检查差异
5. **路径绕过**：`/api/v1/admin` vs `/api/v1/admin/` vs `/api/v1/ADMIN`

### 逻辑检测
1. **流程跳跃**：直接调用流程中间/最终步骤
2. **参数篡改**：修改关键业务参数（金额、状态、角色）
3. **并发测试**：同一操作快速并发请求
4. **状态机分析**：绘制认证状态流转图，寻找缺失的转换检查

## 常见脆弱模式

### JWT 验证缺陷
```java
// 危险：未验证签名
String token = request.getHeader("Authorization");
Claims claims = Jwts.parser().parseClaimsJwt(token).getBody(); // 不验证签名

// 危险：接受 alg:none
Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        if ("none".equals(header.getAlgorithm())) return null; // 致命
    }
});

// 危险：弱密钥
private static final String SECRET_KEY = "mySecretKey123"; // 硬编码弱密钥

// 安全：正确验证
Claims claims = Jwts.parser()
    .setSigningKey(SECRET_KEY)
    .parseClaimsJws(token) // 自动验证签名和过期
    .getBody();
```

```python
# 危险：禁用签名验证
jwt.decode(token, options={"verify_signature": False})

# 危险：不验证过期
jwt.decode(token, secret, algorithms=["HS256"], options={"verify_exp": False})

# 安全：完整验证
jwt.decode(token, secret, algorithms=["HS256"])
```

### 权限检查缺失
```java
// 危险：无权限注解
@RestController
public class AdminController {
    @GetMapping("/admin/users")  // 缺少 @PreAuthorize
    public List<User> getUsers() { ... }
}

// 危险：仅前端检查
// 前端隐藏了按钮，但后端接口未做权限校验

// 危险：基于客户端传参的权限判断
if (request.getParameter("isAdmin").equals("true")) { ... }

// 安全：方法级权限注解
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public List<User> getUsers() { ... }
```

### IDOR 模式
```java
// 危险：直接使用用户传入的 ID，未校验归属关系
@GetMapping("/orders/{orderId}")
public Order getOrder(@PathVariable String orderId) {
    return orderRepository.findById(orderId).orElse(null);
    // 未检查 orderId 是否属于当前用户
}

// 安全：绑定当前用户
@GetMapping("/orders/{orderId}")
public Order getOrder(@PathVariable String orderId, @AuthenticationPrincipal User user) {
    Order order = orderRepository.findById(orderId).orElse(null);
    if (!order.getUserId().equals(user.getId())) {
        throw new AccessDeniedException();
    }
    return order;
}
```

## 绕过技巧

### JWT 绕过
| 技术 | 方法 |
|------|------|
| alg: none | `{"alg":"none","typ":"JWT"}` + 空签名（`.`） |
| 算法切换 | RS256 → HS256，用公钥做 HMAC 密钥 |
| jwk 注入 | header 中添加 `"jwk":{"kty":"RSA","n":"...","e":"AQAB"}` |
| jku 操纵 | 修改 `"jku":"https://attacker.com/keys.json"` |
| 密钥爆破 | `jwt-cracker`, `hashcat -m 16500` |
|  kid 路径遍历 | `"kid":"../../../etc/passwd"` 读取任意文件作为密钥 |

### Cookie/Session 绕过
- **Base64 解码修改**：Cookie 值为 Base64 编码的 JSON，解码后修改再编码
- **序列化对象操纵**：Java `ObjectOutputStream`/Python `pickle` 编码的 Cookie
- **加密模式攻击**：ECB 模式下的 block 重组，CBC 字节翻转
- **Cookie 分割**：多 Cookie 合并时取并集/最后一个值

### 路径/方法绕过
| 技术 | 示例 |
|------|------|
| 尾部斜杠 | `/api/admin` → `/api/admin/` |
| 大小写 | `/api/Admin` → `/api/ADMIN` |
| URL 编码 | `/api/admin` → `/api/%61dmin` |
| 方法切换 | POST `/api/admin` → GET `/api/admin` |
| HTTP 头注入 | `X-Original-URL: /api/admin` |
| 路径前缀 | `/api/v1/admin` → `/api/v2/admin` |

### 参数操纵
- **HTTP 参数污染**：`id=1&id=2` — 后端框架处理不一致
- **JSON 注入**：`{"data": {...}, "isAdmin": true}` 添加额外字段
- **类型混淆**：`{"role": 0}` vs `{"role": "0"}` vs `{"role": false}`
- **嵌套覆盖**：`user[role]=admin` vs `role=admin`

## 验证策略

### POC 生成建议
1. **认证探测**：对所有 API 端点尝试无 token 访问
2. **JWT 分析**：解码所有 JWT，检查 alg、密钥强度、过期策略
3. **越权测试**：
   - 水平越权：用户 A 的 token + 用户 B 的资源 ID
   - 垂直越权：普通用户 token + 管理员端点
4. **流程完整性**：绘制多步流程的状态机，尝试跳步
5. **默认凭证**：检查常见默认用户名/密码组合

### 验证成功标志
- 无认证凭证时返回 200 和数据（应返回 401）
- 低权限用户访问高权限资源返回 200（应返回 403）
- JWT 修改 alg/签名后仍被接受
- 参数篡改导致权限提升
- 默认凭证登录成功

### 自动化检测流程
```
1. 提取所有 API 端点（OpenAPI/Swagger/路由扫描）
2. 对每个端点：
   a. 无 token 请求 → 记录响应
   b. 低权限 token 请求 → 记录响应
   c. 篡改 token 后请求 → 记录响应
   d. 修改请求方法 → 记录响应
   e. 修改路径格式 → 记录响应
3. 对比正常授权请求的响应差异
```

## 安全注意事项

### 测试安全边界
- **禁止**：使用真实用户凭证进行越权测试，应使用测试账户
- **禁止**：爆破攻击影响生产服务（限制速率，使用离线分析）
- **禁止**：修改其他用户的数据（仅读取验证）
- **推荐**：在隔离环境中测试 JWT 密钥爆破
- **推荐**：记录所有认证测试，避免误触发账户锁定

### 法律合规
- 确保已获得目标系统的授权
- 不要在未授权情况下测试默认凭证（可能触发安全事件）
- 对生产系统的 JWT 测试应仅限非破坏性验证
