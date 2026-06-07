# 反序列化漏洞原理与知识

## 概述

反序列化漏洞 (Deserialization Vulnerability) 发生在将字节流还原为对象时，如果数据来源不可信或反序列化过程未正确控制，攻击者可以构造恶意序列化数据执行任意代码。

## 常见类型

### Java 反序列化

```java
// 危险：ObjectInputStream 反序列化不可信数据
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // 可能执行恶意 readObject()

// 危险：JSON 反序列化 gadget chain
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // 允许指定类，可能导致 gadget 执行
Object obj = mapper.readValue(jsonData, Object.class);
```

### Python 反序列化

```python
# 危险：pickle 反序列化不可信数据
import pickle
data = pickle.loads(user_input)  # 可执行任意代码

# 危险：yaml.load 未使用 SafeLoader
import yaml
data = yaml.load(user_input)  # 旧版本可能执行代码
```

## Gadget Chain

常见的 Java gadget chain 包括：
- **CommonsCollections**: 利用 Apache Commons Collections
- **Spring AOP**: 利用 Spring 框架 AOP 组件
- **JDK RMI**: 利用 JDK RMI 组件
- **Jackson**: 利用 Jackson Databind 默认类型功能

## POC 验证要点

1. ** gadget 检测**: 检查依赖库是否包含已知 gadget
2. **反序列化入口**: 确认 `readObject`, `readExternal` 等入口点
3. **数据流追踪**: 从反序列化入口追踪到最终执行
4. **版本检查**: 检查库版本是否受已知 gadget chain 影响

## 修复建议

- 使用安全的反序列化方法 (如 `ObjectInputFilter`)
- 禁用默认类型 (`mapper.disableDefaultTyping()`)
- 使用白名单限制可反序列化的类
- 避免反序列化不可信数据
