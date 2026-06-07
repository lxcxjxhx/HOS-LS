# 认证绕过原理与知识

## 概述

认证绕过 (Authentication Bypass) 是指攻击者能够绕过系统的身份验证或授权检查，访问本应受限的资源或功能。

## 常见绕过类型

### 1. 配置错误

```java
// Spring Security 配置错误
http.authorizeRequests()
    .antMatchers("/api/admin/**").permitAll()  // 错误：所有人均可访问
    .anyRequest().authenticated();

// 缺少 @Secured 注解
@RestController
public class AdminController {
    // 没有 @PreAuthorize 或 @Secured，可能被未授权访问
    @GetMapping("/admin/users")
    public List<User> getUsers() { ... }
}
```

### 2. JWT 漏洞

- 算法混淆: 将 RS256 改为 HS256
- 空签名: 使用 `{"alg":"none"}` 
- 密钥泄露: 使用默认或弱密钥

### 3. 逻辑绕过

- **直接对象引用 (IDOR)**: 修改 ID 访问他人数据
- **水平越权**: 同级别用户访问他人资源
- **垂直越权**: 低权限用户访问高权限功能

## POC 验证要点

1. **未认证访问**: 不带 token 直接访问受保护端点
2. **弱 token**: 尝试常见 JWT 密钥或算法修改
3. **路径遍历**: `../admin/`, `%2e%2e/admin/`
4. **方法覆盖**: 修改 HTTP 方法绕过限制
5. **参数污染**: 多个同名参数绕过验证

## 检查清单

- [ ] 所有 API 端点都有认证保护
- [ ] JWT 使用强密钥和正确算法
- [ ] 角色权限配置正确
- [ ] 无默认凭据或测试账户
- [ ] 敏感操作有二次验证
