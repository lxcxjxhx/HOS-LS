# 敏感数据泄露原理与知识

## 概述

敏感数据泄露 (Sensitive Data Exposure) 发生在应用程序未能妥善保护敏感信息时，包括密码、API 密钥、个人信息、会话令牌等。攻击者可通过多种方式获取这些数据，导致身份盗窃、财务损失或进一步攻击。

## 触发条件

1. **敏感数据以明文存储或传输**
2. **缺乏访问控制和身份验证**
3. **日志、错误信息、配置文件中暴露敏感数据**
4. **不安全的加密实现或弱加密算法**

## 常见模式

### 密码存储不当

```java
// 危险：明文或弱哈希存储密码
String passwordHash = md5(userPassword);
String passwordHash = sha1(userPassword);

// 安全：使用 bcrypt/scrypt/Argon2
String passwordHash = BCrypt.hashpw(userPassword, BCrypt.gensalt());
```

### 敏感数据记录到日志

```java
// 危险：日志记录敏感信息
log.info("用户登录: username={}, password={}", username, password);
log.debug("API 请求: key={}", apiKey);

// 安全：脱敏或忽略敏感字段
log.info("用户登录: username={}", username);
```

### 错误信息泄露

```java
// 危险：将堆栈跟踪返回给客户端
catch (Exception e) {
    response.getWriter().write(e.toString());
    e.printStackTrace(response.getWriter());
}

// 安全：通用错误信息
catch (Exception e) {
    log.error("处理异常", e);
    response.getWriter().write("服务器内部错误");
}
```

### 硬编码凭证

```java
// 危险：硬编码 API 密钥
private static final String API_KEY = "sk-xxxxxxxxxxxxxxxxxxxx";
private static final String DB_PASSWORD = "admin123";

// 安全：使用环境变量或密钥管理服务
private static final String API_KEY = System.getenv("API_KEY");
```

### 不安全的传输

```java
// 危险：HTTP 传输敏感数据
HttpPost request = new HttpPost("http://api.example.com/login");

// 安全：HTTPS 传输
HttpPost request = new HttpPost("https://api.example.com/login");
```

## POC 验证要点

1. **敏感文件暴露**: `.env`, `.git/config`, `web.xml`, `application.yml`
2. **备份文件**: `.bak`, `.old`, `.swp`, `~` 文件
3. **API 密钥泄露**: 源码中的 `AKIA`, `sk-`, `ghp_` 等特征字符串
4. **响应头泄露**: `Server`, `X-Powered-By`, `X-AspNet-Version`
5. **错误页面**: 详细堆栈信息、SQL 错误、调试信息
6. **JWT 弱点**: `alg: none`, 弱密钥, 未验证签名

## 常见泄露场景

- **Git 仓库泄露**: `.git` 目录可访问，包含完整提交历史
- **目录遍历**: 访问到备份文件、配置文件
- **接口未授权访问**: API 无认证直接返回用户数据
- **调试接口**: `/debug`, `/actuator`, `/phpinfo` 未关闭
- **第三方组件**: 日志框架、监控工具默认配置暴露数据

## 修复建议

- **加密存储**: 使用强哈希算法 (bcrypt/Argon2) 存储密码
- **加密传输**: 强制 HTTPS，配置 HSTS
- **最小化日志**: 日志中脱敏敏感字段，生产环境关闭 DEBUG
- **密钥管理**: 使用 Vault、环境变量管理凭证，禁止硬编码
- **访问控制**: 严格鉴权，最小权限原则
- **错误处理**: 自定义错误页面，不暴露内部信息
- **安全配置**: 关闭调试接口，移除默认账户和测试数据
