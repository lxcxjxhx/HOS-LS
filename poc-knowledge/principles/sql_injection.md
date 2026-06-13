# SQL 注入原理与测试技术

## 漏洞原理
SQL 注入 (SQL Injection, SQLi) 的根本原因是应用程序将用户输入直接拼接到 SQL 查询语句中，未经过参数化查询或充分的输入验证。当数据库引擎执行拼接后的 SQL 语句时，攻击者注入的恶意 SQL 代码会被当作合法的查询逻辑执行，从而绕过认证、提取/篡改/删除数据、甚至执行系统命令（取决于数据库配置和权限）。

核心机制：
- **数据与代码未分离**：用户输入被当作 SQL 语法的一部分而非纯数据
- **动态 SQL 构建**：使用字符串拼接、模板替换等方式构造查询
- **缺乏最小权限**：应用数据库账户拥有超出业务需要的权限（如 DROP TABLE、xp_cmdshell）

## 漏洞类型与变种

### 1. UNION 联合注入 (In-band SQLi)
利用 UNION/UNION ALL 操作符将注入查询的结果合并到原查询结果中返回。
- **前提**：原查询结果可控且回显，能确定列数和数据类型
- **关键**：`ORDER BY` 确定列数，`UNION SELECT NULL,...` 确定类型匹配
- **适用**：有数据回显的查询点

### 2. 布尔盲注 (Boolean-based Blind SQLi)
通过注入条件表达式（如 `AND 1=1` / `AND 1=2`），根据页面响应差异判断条件真假，逐字符推断数据。
- **特征**：响应内容或长度有可区分差异
- **效率**：逐位提取，较慢但稳定
- **适用**：无数据回显但有真假两种响应

### 3. 时间盲注 (Time-based Blind SQLi)
通过注入条件控制的延时函数（如 `IF(1=1,SLEEP(5),0)`），根据响应时间差异推断数据。
- **特征**：响应时间存在明显差异
- **适用**：无任何响应差异，只有成功/失败两种状态
- **常用函数**：MySQL `SLEEP()`, PostgreSQL `pg_sleep()`, SQL Server `WAITFOR DELAY`

### 4. 报错注入 (Error-based SQLi)
利用 SQL 语句中的函数错误或语法错误，使数据库报错信息中包含查询结果。
- **MySQL**：`ExtractValue()`, `UpdateXML()`, `GeometryCollection()`
- **PostgreSQL**：`cast(version() as int)`
- **Oracle**：`DBMS_XMLGEN.GETXML()`
- **SQL Server**：`convert(int,@@version)`

### 5. 堆叠查询注入 (Stacked Queries / Out-of-band)
使用 `;` 分隔符在原有查询后附加完全独立的 SQL 语句。
- **前提**：数据库驱动/框架支持多语句执行
- **风险最高**：可执行 DDL（CREATE/DROP）和某些数据库的系统命令
- **MySQL 限制**：需 `multi_statements=true` 连接参数

### 6. 二次注入 (Second-order SQLi)
恶意数据先被安全存储到数据库，后续被另一个查询使用时触发注入。
- **特征**：注入点与触发点分离，难以发现
- **常见场景**：注册用户名为 SQL 语句，在其他页面被引用

## 检测方法

### 自动化检测策略
1. **注入点探测**：在参数中添加 `'`, `"`, `)`, `))` 观察是否触发 SQL 错误
2. **布尔差异测试**：`AND 1=1` vs `AND 1=2` 比较响应差异
3. **时间延迟测试**：`AND SLEEP(5)` 观察响应时间
4. **UNION 可注入性**：`ORDER BY N` 探测列数，`UNION SELECT NULL,...` 测试联合
5. **错误信息分析**：触发 SQL 错误获取数据库版本、类型

### 手动检测清单
- [ ] 所有 GET/POST 参数是否经过参数化查询
- [ ] URL 路径参数（RESTful 路由）是否安全
- [ ] Cookie/Header 值是否用于 SQL 查询
- [ ] 搜索/过滤/排序参数是否可控
- [ ] HTTP Host/User-Agent 等头部是否记录到数据库

### 数据库类型识别
| 数据库 | 版本查询 | 延时函数 | 注释符 |
|--------|---------|---------|--------|
| MySQL | `SELECT @@version` | `SLEEP(5)` | `--`, `#`, `/**/` |
| PostgreSQL | `SELECT version()` | `pg_sleep(5)` | `--`, `/**/` |
| SQL Server | `SELECT @@version` | `WAITFOR DELAY '0:0:5'` | `--` |
| Oracle | `SELECT banner FROM v$version` | `DBMS_PIPE.RECEIVE_MESSAGE()` | `--` |
| SQLite | `SELECT sqlite_version()` | `RANDOMBLOB()` | `--`, `/**/` |

## 常见脆弱模式

### Java 中的危险模式
```java
// 危险：字符串拼接
String query = "SELECT * FROM users WHERE id = " + userInput;

// 危险：MyBatis ${} 语法（直接字符串替换）
<select id="findUser">SELECT * FROM users WHERE id = ${id}</select>

// 危险：Hibernate 非参数化 HQL
Query q = session.createQuery("FROM User WHERE name = '" + name + "'");

// 危险：JDBC Statement（非 PreparedStatement）
Statement stmt = conn.createStatement();
stmt.executeQuery("SELECT * FROM users WHERE name = '" + input + "'");

// 安全：MyBatis #{} 语法（参数化）
<select id="findUser">SELECT * FROM users WHERE id = #{id}</select>

// 安全：PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userInput);
```

### Python 中的危险模式
```python
# 危险：f-string / format 拼接
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))

# 危险：字符串拼接
query = "SELECT * FROM users WHERE name = '" + name + "'"
cursor.execute(query)

# 安全：参数化查询（元组/列表）
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
```

### PHP 中的危险模式
```php
// 危险：直接拼接
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// 危险：双引号变量插值
$query = "SELECT * FROM users WHERE name = '$name'";

// 安全：PDO 预编译
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// 安全：mysqli 预编译
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
```

### Node.js 中的危险模式
```javascript
// 危险：模板字符串拼接
const query = `SELECT * FROM users WHERE id = ${userId}`;

// 危险：字符串连接
const query = "SELECT * FROM users WHERE name = '" + name + "'";

// 安全：参数化查询
const [rows] = await pool.query("SELECT * FROM users WHERE id = ?", [userId]);
```

## 绕过技巧

### 关键词过滤绕过
| 技术 | 示例 |
|------|------|
| 大小写混写 | `SeLeCt`, `FrOm`, `UNION` → `uNiOn` |
| 内联注释 (MySQL) | `/*!UNION*/`, `/*!50000SELECT*/` |
| 空白符替换 | `%09` (Tab), `%0A` (LF), `%0D` (CR), `%0C` (FF), `%A0` |
| 双写绕过 | `UNUNIONION` (过滤后变 UNION) |
| 等价函数替换 | `substring()` → `mid()`, `substr()`, `left()` |
| 字符串拼接 | `'ad'||'min'` → `'admin'`, `CONCAT('a','d','min')` |
| 十六进制编码 | `'admin'` → `0x61646d696e` |
| 科学计数法 | `SELECT 1` → `SELECT 1e0`, `0e` |
| NULL 比较绕过 | `WHERE id IS NULL` → `WHERE id <=> NULL` |
| LIKE 替代 | `WHERE name='admin'` → `WHERE name LIKE 'admin'` |
| BETWEEN 替代 | `WHERE id=1` → `WHERE id BETWEEN 1 AND 1` |

### WAF 特定绕过
- **ModSecurity 绕过**：使用 `/*!*/` 注释包裹、`%0A` 换行分割关键词
- **URL 编码**：`'` → `%27`, ` ` → `%20`, `=` → `%3D`
- **双重 URL 编码**：`'` → `%2527`（后端可能双重解码）
- **分块传输编码**：`Transfer-Encoding: chunked` 绕过基于 body 扫描的 WAF
- **HTTP 参数污染**：`id=1&id=2&id=3` 利用后端取最后/第一个参数的逻辑

## 验证策略

### POC 生成建议
1. **最小化原则**：先用最简单 payload（`'`, `"`, `1=1`）确认注入点存在
2. **数据库指纹**：使用数据库特有函数确认后端数据库类型
3. **信息提取链**：
   - 数据库版本 → 表名 (`information_schema.tables`) → 列名 (`information_schema.columns`) → 数据
   - 注意：MySQL 8.0+ 可使用 `mysql.innodb_table_stats`
4. **盲注优化**：使用二分法（binary search）逐字符提取，而非逐位遍历
5. **OOB 技术**：当无回显时，利用 `LOAD_FILE()`, `INTO OUTFILE`, DNS 解析等外带数据

### 安全验证载荷（推荐用于 POC）
- **布尔盲注**：`' AND 1=1--` / `' AND 1=2--`
- **时间盲注**：`' AND IF(1=1,SLEEP(2),0)--`
- **UNION 探测**：`' ORDER BY 1--` 递增直到报错
- **无害信息提取**：仅查询 `SELECT @@version`, `SELECT user()`, `SELECT current_user()`

### 验证成功标志
- 响应内容/长度出现可预期差异
- 响应时间出现可控延迟
- 返回 SQL 错误信息（含数据库类型和版本）
- UNION 注入时页面出现额外字段内容

## 安全注意事项

### POC 执行安全边界
- **禁止**：`DROP TABLE`, `DELETE`, `UPDATE` 等破坏性操作
- **禁止**：执行系统命令（`xp_cmdshell`, `sys_exec`, `UDF` 提权）
- **禁止**：写文件到服务器（`INTO OUTFILE`）
- **推荐**：仅执行 `SELECT` 查询，提取版本/用户名/数据库名等元数据
- **推荐**：使用事务和 ROLLBACK 避免数据变更

### 测试环境要求
- 使用专用测试环境，避免影响生产数据
- 控制注入查询的数据提取量（LIMIT 限制）
- 记录所有测试 payload 和时间戳，便于审计
- 对时间盲注测试使用合理超时值（建议 2-5 秒，避免服务挂起）
