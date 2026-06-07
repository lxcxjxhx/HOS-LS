# SQL 注入原理与知识

## 概述

SQL 注入 (SQL Injection) 是最常见且最危险的 Web 漏洞之一。当用户输入未经适当处理就被拼接到 SQL 查询中时，攻击者可以注入恶意的 SQL 语句，从而绕过认证、窃取数据或修改数据库。

## 触发条件

1. **用户输入直接拼接到 SQL 语句**
2. **缺乏参数化查询或预编译**
3. **输入验证不足或绕过**

## 常见模式

### Java 中的危险模式

```java
// 危险：字符串拼接
String query = "SELECT * FROM users WHERE id = " + userInput;

// 危险：MyBatis ${} 语法
<select id="findUser" resultType="User">
    SELECT * FROM users WHERE id = ${id}
</select>

// 危险：Hibernate 非参数化查询
Query q = session.createQuery("FROM User WHERE name = '" + name + "'");
```

### Python 中的危险模式

```python
# 危险：f-string 拼接
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# 危险：format 方法
cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))

# 安全：参数化查询
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

## POC 验证要点

1. **布尔盲注**: 注入 `1=1` 和 `1=2` 观察响应差异
2. **时间盲注**: 使用 `SLEEP()` 或 `WAITFOR DELAY` 观察延迟
3. **Union 注入**: 使用 `UNION SELECT` 提取数据
4. **报错注入**: 触发 SQL 错误信息获取数据库信息
5. **堆叠查询**: 使用 `;` 执行多条语句

## 绕过技术

- **大小写混写**: `SeLeCt`, `FrOm`
- **注释绕过**: `/**/`, `--`, `#`
- **编码绕过**: URL 编码, 十六进制
- **空白符替换**: `%09`, `%0A`, `%0D`
