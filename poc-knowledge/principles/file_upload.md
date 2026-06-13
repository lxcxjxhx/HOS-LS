# 文件上传漏洞原理与测试技术

## 漏洞原理
文件上传漏洞发生在应用程序允许用户上传文件时，未对文件内容、类型、名称等进行充分验证，导致攻击者上传恶意文件（如 Web Shell、脚本文件）并在服务器上执行。

核心机制：
- **扩展名验证不足**：仅检查前端或简单黑名单，可被绕过
- **MIME 类型验证不足**：仅检查 `Content-Type` 请求头（客户端可控）
- **内容检查缺失**：未验证文件实际内容是否与声明类型一致
- **上传目录可执行**：上传目录未被配置为禁止脚本执行
- **文件名未处理**：直接使用用户提供的文件名，未做安全处理

## 漏洞类型与变种

### 1.  unrestricted 文件上传
服务器完全不验证上传文件，攻击者可直接上传 `.php`, `.jsp`, `.asp` 等可执行文件。

### 2. 扩展名验证绕过
服务器检查文件扩展名，但验证逻辑不完善。

**绕过方式**：
- **黑名单绕过**：上传 `.php5`, `.phtml`, `.php3`, `.phar` 等替代扩展名
- **大小写绕过**：`.PHP`, `.PhP`（Windows 文件系统不区分大小写）
- **双扩展名**：`shell.php.jpg`, `shell.php%00.jpg`（Null 字节截断）
- **特殊字符**：`shell.php.`, `shell.php%20`（Windows 自动去除尾部点和空格）
- **替代扩展名**：
  - PHP: `.php`, `.php3`, `.php4`, `.php5`, `.php7`, `.phtml`, `.phar`, `.inc`
  - ASP: `.asp`, `.aspx`, `.ashx`, `.asmx`, `.ascx`, `.asa`, `.cer`
  - JSP: `.jsp`, `.jspx`, `.jsw`, `.jsw`, `.jspf`

### 3. MIME 类型绕过
服务器仅检查 `Content-Type` 请求头。
- 修改 `Content-Type: image/jpeg` 上传 PHP 文件
- `Content-Type: application/octet-stream` 通用绕过

### 4. 内容检测绕过
服务器检查文件内容签名（Magic Bytes）。
- 添加图片文件头：`GIF89a` + PHP 代码
- 图片中包含代码（通过 steganography 或直接拼接）
- SVG 文件本身是 XML 可包含 JavaScript

### 5. 竞争条件上传
上传到临时目录后可执行，但在被删除/重命名前的短暂窗口期内访问执行。

### 6. 文件名处理漏洞
- **路径遍历**：文件名包含 `../../malicious.php`
- **文件名注入**：特殊字符导致命令注入（如 `;id.php`）

## 检测方法

### 扩展名检测
1. **基础扩展名测试**：尝试上传 `.php`, `.jsp`, `.asp`, `.aspx` 文件
2. **替代扩展名**：上传 `.php5`, `.phtml`, `.jspx` 等
3. **大小写变体**：`.PHP`, `.Jsp`, `.AspX`
4. **双扩展名**：`shell.php.jpg`, `test.jsp.png`
5. **特殊后缀**：`shell.php.`, `shell.php%20`（需 Windows 服务器）
6. **Null 字节**：`shell.php%00.jpg`（旧版本）

### MIME 类型检测
1. **修改 Content-Type**：将 `Content-Type: application/x-php` 改为 `image/jpeg`
2. **Burp Repeater**：拦截上传请求，修改 Content-Type 后重放

### 内容检测
1. **文件头伪造**：在恶意文件前添加合法文件头（`GIF89a`, `\x89PNG\r\n`）
2. **polyglot 文件**：同时满足多种文件格式特征的恶意文件
3. **图片元数据注入**：在图片 EXIF 注释中嵌入代码

### 上传后验证
1. **访问上传文件**：尝试访问上传路径，观察是否返回文件内容或被解析执行
2. **目录遍历**：若无法直接访问，尝试遍历上传目录
3. **包含漏洞**：若文件不被直接执行，尝试通过本地文件包含执行

## 常见脆弱模式

### Java / Spring Boot
```java
// 危险：仅检查扩展名黑名单
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    String filename = file.getOriginalFilename();
    if (filename.endsWith(".jsp") || filename.endsWith(".jspx")) {
        throw new SecurityException("非法文件类型");
    }
    // 黑名单不完整，.php5, .phtml 等可绕过
    Files.copy(file.getInputStream(), Paths.get(UPLOAD_DIR, filename));
    return "上传成功";
}

// 危险：使用 OriginalFilename 未处理（可能包含路径）
Path target = Paths.get(UPLOAD_DIR, file.getOriginalFilename());
// 如果 filename = "../../../WEB-INF/malicious.jsp"

// 安全：白名单 + 随机文件名 + 不可执行目录
private static final Set<String> ALLOWED_EXTENSIONS = Set.of("jpg", "png", "gif", "pdf");

@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    String ext = FilenameUtils.getExtension(file.getOriginalFilename()).toLowerCase();
    if (!ALLOWED_EXTENSIONS.contains(ext)) {
        throw new SecurityException("非法文件类型");
    }
    String newFilename = UUID.randomUUID() + "." + ext;
    Files.copy(file.getInputStream(), Paths.get(UPLOAD_DIR, newFilename));
    return "上传成功";
}
```

### PHP
```php
// 危险：仅检查 MIME 类型
if ($_FILES['file']['type'] == 'image/jpeg') {
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);
}

// 危险：仅检查扩展名黑名单
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
$blacklist = ['php', 'jsp', 'asp'];
if (in_array($ext, $blacklist)) {
    die('非法文件类型');
}

// 安全：白名单 + 内容验证 + 随机文件名
$allowed_ext = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed_ext)) die('非法文件类型');

// 验证文件头
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
if (!in_array($mime, ['image/jpeg', 'image/png', 'image/gif'])) die('非法内容');

$newFilename = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $newFilename);
```

### Python / Flask
```python
# 危险：直接使用原始文件名
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(os.path.join(UPLOAD_FOLDER, file.filename))

# 安全：werkzeug.secure_filename + 白名单
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # 进一步使用 UUID 重命名
        new_filename = str(uuid.uuid4()) + '.' + filename.rsplit('.', 1)[1]
        file.save(os.path.join(UPLOAD_FOLDER, new_filename))
```

### Node.js / Express (multer)
```javascript
// 危险：无文件类型过滤
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), (req, res) => { ... });

// 安全：文件类型过滤 + 随机文件名
const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];
        if (!allowedExts.includes(ext)) return cb(new Error('非法文件类型'));
        cb(null, `${crypto.randomUUID()}${ext}`);
    }
});
const upload = multer({ storage });
```

## 绕过技巧

### 扩展名绕过
| 技术 | 示例 | 适用场景 |
|------|------|---------|
| 替代扩展名 | `.php5`, `.phtml`, `.phar` | 黑名单不完整 |
| 大小写 | `.PHP`, `.PhP` | Windows/IIS |
| 双扩展名 | `shell.php.jpg` | 仅检查最后扩展名 |
| 尾部特殊字符 | `shell.php.`, `shell.php%20` | Windows 自动去除 |
| Null 字节截断 | `shell.php%00.jpg` | PHP < 5.3.4, 旧版 Java |
| .htaccess 上传 | 上传 `.htaccess` 设置 PHP 处理器 | Apache |
| 用户自定义扩展名 | `.xxx` 配合 `.htaccess` | Apache 可配置 |
| SVG XSS | `<svg onload=alert(1)>` | 当 SVG 被浏览器直接渲染 |

### MIME 类型绕过
```
原始: Content-Type: application/x-php
绕过: Content-Type: image/jpeg
绕过: Content-Type: application/octet-stream
绕过: Content-Type: text/plain
```

### 内容检测绕过
- **GIF 文件头**：`GIF89a<?php phpinfo(); ?>`
- **PNG 文件头**：`\x89PNG\r\n\x1a\n` + 代码（代码放在文本块中）
- **JPEG 文件头**：`\xFF\xD8\xFF\xE0` + JFIF + 代码
- **图片中的 PHP**：使用 `exiftool` 在图片元数据中写入 PHP 代码
- **Polyglot 文件**：同时是合法 GIF 和合法 PHP 的文件

### 上传配置绕过
- **Apache .htaccess**：上传 `.htaccess` 设置 `AddType application/x-httpd-php .jpg`
- **IIS web.config**：上传 `web.config` 修改处理程序映射
- **Nginx 配置错误**：`location ~ \.php$` 未覆盖所有变体
- **临时目录执行**：文件在临时目录期间可被访问执行

## 验证策略

### POC 生成建议
1. **上传无害文件**：先上传合法图片确认上传功能正常
2. **扩展名测试**：依次尝试不同扩展名变体
3. **Content-Type 修改**：拦截上传请求修改 MIME 类型
4. **内容注入**：在图片文件中嵌入无害标记（如 `<!-- POC -->`）
5. **文件访问验证**：上传后尝试访问文件 URL

### 验证成功标志
- 上传的 `.php`/`.jsp` 文件可被服务器解析执行
- 上传的图片文件中嵌入的代码被执行（如通过文件包含）
- `.htaccess` 上传成功并改变了目录行为
- 上传文件名未正确清理导致路径遍历

### 自动化检测流程
```
1. 上传标准图片（确认功能正常）
2. 上传 PHP 文件（直接测试）
3. 修改 Content-Type 为 image/jpeg（MIME 绕过）
4. 修改扩展名为 .php5/.phtml（扩展名绕过）
5. 上传 GIF89a + PHP 代码（内容绕过）
6. 上传 .htaccess（配置绕过）
7. 上传文件名包含 ../（路径遍历）
8. 验证每个上传文件的访问结果
```

## 安全注意事项

### 测试安全边界
- **禁止**：上传真正的 Web Shell 或恶意脚本
- **推荐**：使用无害的 POC 文件（如 `<?php echo "POC"; ?>`）
- **推荐**：上传后立即删除测试文件
- **推荐**：记录上传路径和访问 URL，便于后续验证

### 防护建议
- **白名单验证**：仅允许特定扩展名和 MIME 类型
- **内容验证**：使用 `finfo`/文件头验证实际内容
- **随机文件名**：使用 UUID 重命名，禁止使用原始文件名
- **不可执行目录**：上传目录配置为禁止脚本执行（Apache: `Options -ExecCGI`）
- **存储分离**：将文件存储在独立域/CDN，与主应用分离
- **大小限制**：限制上传文件大小防止 DoS
- **病毒扫描**：对上传文件进行恶意代码扫描
