# SSRF 原理与知识

## 概述

服务端请求伪造 (Server-Side Request Forgery, SSRF) 发生在服务器端发起的 HTTP 请求中，用户能够控制请求的目标 URL。这可能导致攻击者访问内部网络资源、云元数据服务等。

## 触发条件

1. **URL 参数用户可控**
2. **缺乏目标地址验证**
3. **未限制内网地址访问**

## 常见触发点

```java
// 危险：用户控制的 URL
String url = request.getParameter("url");
HttpClient client = HttpClient.newHttpClient();
HttpRequest request = HttpRequest.newBuilder(URI.create(url)).build();

// 危险：RestTemplate 用户控制目标
String target = request.getParameter("target");
restTemplate.getForObject(target, String.class);
```

```python
# 危险：requests 库用户控制 URL
url = request.args.get('url')
response = requests.get(url)

# 危险：urllib 用户控制
url = request.args.get('url')
data = urllib.request.urlopen(url).read()
```

## POC 验证要点

1. **内网 IP 访问**: 尝试访问 `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`
2. **云元数据**: AWS `http://169.254.169.254/`, GCP `http://metadata.google.internal/`
3. **端口扫描**: 尝试不同端口 `http://internal-server:port`
4. **协议绕过**: `file://`, `gopher://`, `dict://`

## 绕过技术

- **DNS 重绑定**: 先解析到合法 IP，请求时解析到内网 IP
- **重定向**: 利用 302 重定向绕过 URL 白名单
- **IPv6**: 使用 IPv6 绕过 IPv4 黑名单
- **URL 编码**: `%00`, `%0D%0A` 等
