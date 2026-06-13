# 目录/路径遍历原理与测试技术

## 漏洞原理
路径遍历 (Path Traversal / Directory Traversal) 发生在应用程序使用用户可控的输入来构造文件系统路径时，未正确验证或限制路径范围。攻击者通过使用路径跳转符（如 `../` 或 `..\`）跳出预期目录，访问系统任意文件。

核心机制：
- **未规范化路径**：直接使用用户输入拼接路径，未进行路径规范化
- **黑名单过滤不完整**：仅过滤 `../` 但遗漏编码变体或其他绕过方式
- **权限配置过宽**：应用进程具有读取系统敏感文件的权限
- **竞争条件**：路径检查与文件读取之间存在 TOCTOU 窗口

## 漏洞类型与变种

### 1. 相对路径遍历
使用 `../`（Unix）或 `..\`（Windows）向上级目录跳转。
- **基础型**：`../../../etc/passwd`
- **深度型**：多层 `../../../../../../../etc/passwd`
- **混合型**：`..\../..\../etc/passwd`

### 2. 绝对路径覆盖
直接使用绝对路径覆盖预期路径。
- **Unix**：`/etc/passwd`, `/proc/self/environ`
- **Windows**：`C:\Windows\win.ini`, `C:\boot.ini`

### 3. 编码绕过型遍历
利用编码使过滤逻辑失效。
- **URL 编码**：`%2e%2e%2f` → `../`
- **双重 URL 编码**：`%252e%252e%252f` → `%2e%2e%2f` → `../`
- **Unicode 编码**：`%c0%ae%c0%ae/`（旧版服务器）
- **UTF-8 超长编码**：过长的 UTF-8 序列被不同组件解析为不同字符

### 4. Null 字节截断
在旧版本 PHP (< 5.3.4) 和 Java 中，Null 字节 (`%00`) 可截断路径。
- `../../../etc/passwd%00.png` — 绕过后缀名检查

### 5. 特殊文件访问
- **Linux 特殊文件**：`/proc/self/cmdline`, `/proc/self/environ`, `/dev/null`
- **Windows 设备名**：`CON`, `PRN`, `AUX`, `NUL`
- **Git 仓库**：`.git/config`, `.git/HEAD`

## 检测方法

### 手动检测
1. **基础遍历测试**：提交 `../../../etc/passwd` 或 `..\..\windows\win.ini`
2. **编码变体**：使用 `%2e%2e%2f`, `..%2f`, `%2e%2e/` 等编码
3. **绝对路径**：直接提交 `/etc/passwd` 或 `C:\Windows\win.ini`
4. **文件包含**：若为文件包含漏洞，尝试读取已知存在的文件
5. **错误信息**：观察是否返回文件不存在/无权限/文件内容等差异响应

### 自动化检测策略
1. **参数注入**：对所有文件相关参数（file, path, dir, doc, folder 等）注入遍历序列
2. **响应分析**：对比正常文件 vs 遍历文件的响应差异（内容、状态码、错误信息）
3. **已知文件匹配**：尝试读取 `/etc/passwd`（含 `root:x:0:0:`）或 `win.ini`（含 `[extensions]`）
4. **路径深度探测**：递增 `../` 层数，直到成功读取

### 检测目标文件清单
| 系统 | 文件 | 用途 |
|------|------|------|
| Linux | `/etc/passwd` | 用户列表 |
| Linux | `/etc/shadow` | 密码哈希（需 root） |
| Linux | `/proc/self/environ` | 环境变量 |
| Linux | `/proc/self/cmdline` | 进程启动命令 |
| Linux | `~/.ssh/id_rsa` | SSH 私钥 |
| Windows | `C:\Windows\win.ini` | 系统配置 |
| Windows | `C:\boot.ini` | 启动配置 |
| Web | `web.xml`, `.env` | 应用配置 |
| Web | `.git/HEAD` | Git 仓库信息 |

## 常见脆弱模式

### Java 中的危险模式
```java
// 危险：直接拼接路径
String filePath = baseDir + "/" + request.getParameter("file");
File file = new File(filePath);

// 危险：仅过滤 ../ 但可绕过
String safePath = userInput.replace("../", "");
// 绕过：....// 过滤后变为 ../

// 危险：仅检查包含 ../ 但编码可绕过
if (userInput.contains("../")) throw new SecurityException();
// 绕过：%2e%2e%2f 绕过字符串匹配

// 安全：路径规范化 + 前缀验证
File file = new File(baseDir, userInput);
String canonical = file.getCanonicalPath();
if (!canonical.startsWith(new File(baseDir).getCanonicalPath() + File.separator)) {
    throw new SecurityException("Path traversal detected");
}

// 安全：使用白名单文件映射
Map<String, String> allowedFiles = Map.of(
    "report", "/data/reports/annual.pdf",
    "manual", "/data/docs/manual.pdf"
);
String filePath = allowedFiles.get(userInput);
```

### Python 中的危险模式
```python
# 危险：直接拼接
file_path = "/var/www/files/" + request.args.get("file")
with open(file_path, "r") as f:
    content = f.read()

# 危险：不完整的过滤
safe_path = user_input.replace("../", "").replace("..\\", "")

# 安全：os.path.realpath + 前缀检查
base_dir = os.path.realpath("/var/www/files")
file_path = os.path.realpath(os.path.join(base_dir, user_input))
if not file_path.startswith(base_dir + os.sep):
    raise SecurityError("Path traversal detected")
```

### Node.js 中的危险模式
```javascript
// 危险：path.join 不防止 ../
const filePath = path.join(__dirname, 'uploads', req.query.file);
fs.readFileSync(filePath);

// 安全：path.resolve + 前缀检查
const filePath = path.resolve(baseDir, req.query.file);
if (!filePath.startsWith(baseDir + path.sep)) {
    throw new Error("Path traversal detected");
}
```

### PHP 中的危险模式
```php
// 危险：直接包含用户控制的文件
include($_GET['page'] . '.php');

// 危险：过滤不严
$file = str_replace('../', '', $_GET['file']);
include($file);

// 安全：白名单
$allowed = ['home', 'about', 'contact'];
if (in_array($_GET['page'], $allowed)) {
    include($_GET['page'] . '.php');
}
```

## 绕过技巧

### 过滤绕过
| 技术 | 示例 | 原理 |
|------|------|------|
| URL 编码 | `%2e%2e%2f` | 单层/多层编码绕过字符串匹配 |
| 双重编码 | `%252e%252e%252f` | 后端双重解码 |
| Unicode 编码 | `%c0%ae%c0%ae/` | 非标准 UTF-8 解析差异 |
| 双写绕过 | `....//` | 过滤一次后变为 `../` |
| 混合斜杠 | `..\../etc/passwd` | 跨平台路径解析差异 |
| 大小写 (Windows) | `..\\..\\ETC` | Windows 大小写不敏感 |
| Null 字节 | `../../../etc/passwd%00.jpg` | 截断后缀检查（旧版本） |
| 绝对路径 | `/etc/passwd` | 直接绕过相对路径检查 |
| 协议绕过 | `file:///etc/passwd` | 利用 file 协议 |
| 符号链接 | 指向 `/etc/passwd` 的软链接 | 绕过路径检查后读取链接目标 |

### 高级绕过
- **TOCTOU 竞争**：在路径检查与文件读取之间替换文件
- **符号链接攻击**：上传符号链接文件指向敏感路径
- **DNS 重绑定**：若路径解析涉及 DNS 查询
- **路径规范化差异**：不同语言/库对 `..` 的处理不一致

## 验证策略

### POC 生成建议
1. **无害文件读取**：优先读取 `/etc/passwd`（Linux）或 `win.ini`（Windows）
2. **已知内容匹配**：验证响应是否包含预期文件内容特征
3. **路径深度递增**：从 `../` 开始逐步增加深度
4. **多编码变体**：对每个遍历 payload 生成编码变体
5. **上下文分析**：根据目标系统（Linux/Windows）选择合适的路径

### 验证成功标志
- 响应包含 `/etc/passwd` 的典型内容（`root:x:0:0:`）
- 响应包含 `win.ini` 的典型内容（`[extensions]`）
- 响应返回文件内容而非错误页面
- 对比正常文件请求，遍历请求返回不同的有效内容

### 自动化 POC 模板
```
GET /download?file=../../../etc/passwd
GET /download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
GET /download?file=....//....//....//etc/passwd
POST /api/file
  {"path": "..\\..\\..\\windows\\win.ini"}
```

## 安全注意事项

### 测试安全边界
- **禁止**：读取包含密码哈希的 `/etc/shadow`（可能违反法律）
- **禁止**：尝试写文件（`PUT`/写入操作）
- **禁止**：利用路径遍历执行代码（如写入 Web Shell）
- **推荐**：仅读取无害的公开配置文件进行验证
- **推荐**：记录访问的文件路径，避免泄露敏感信息

### 修复建议
- **路径规范化**：始终使用 `getCanonicalPath()`, `os.path.realpath()`, `path.resolve()`
- **前缀校验**：规范化后检查路径是否以预期目录开头
- **白名单机制**：使用文件名 ID 映射而非直接路径
- **最小权限**：限制应用进程的文件系统访问范围
- **沙箱隔离**：使用 chroot 或容器限制文件访问
