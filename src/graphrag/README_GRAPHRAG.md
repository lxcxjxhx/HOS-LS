# GraphRAG 集成说明

## 1. 概述

GraphRAG 是一种结合图数据库和向量检索的增强型 RAG 技术，专为 HOS-LS（AI安全扫描）场景深度定制。它能够：

- 表达代码结构关系
- 表达攻击路径
- 表达跨文件漏洞链
- 将 CVE 从文本转换为结构

## 2. 架构

```
                 ┌────────────────────────┐
                 │      原始输入数据        │
                 │  (代码 / CVE / AST)     │
                 └─────────┬──────────────┘
                           ↓
         ┌────────────────────────────────────┐
         │        语义抽取 + 结构解析层         │
         │ (AST / 数据流 / 漏洞语义提取)       │
         └─────────┬──────────────────────────┘
                   ↓
      ┌──────────────────────────────────────┐
      │         Graph构建层（核心）           │
      │  节点 + 边（漏洞 / 函数 / 数据流）    │
      └─────────┬────────────────────────────┘
                ↓
      ┌──────────────────────────────────────┐
      └─────────┬────────────────────────────┘
                ↓
      ┌──────────────────────────────────────┐
      │   Graph + Vector 混合检索层          │
      └─────────┬────────────────────────────┘
                ↓
      ┌──────────────────────────────────────┐
      │     推理层（漏洞判断 / 攻击链）       │
      └──────────────────────────────────────┘
```

## 3. 核心模块

### 3.1 图谱构建模块 (`src/graphrag/graph_builder.py`)

- **功能**：从 AST、污点分析和 CVE 数据构建知识图谱
- **输入**：分析上下文（代码内容、语言等）
- **输出**：图节点和边

### 3.2 图存储模块 (`src/graphrag/graph_store.py`)

- **功能**：将构建好的图谱存储到 Neo4j 数据库中
- **输入**：图节点和边
- **输出**：存储结果

### 3.3 图检索模块 (`src/graphrag/graph_retriever.py`)

- **功能**：执行 Graph + Vector 混合检索、图遍历、子图构建和漏洞链推理
- **输入**：查询文本
- **输出**：检索结果

### 3.4 GraphRAG 适配器 (`src/graphrag/graphrag_adapter.py`)

- **功能**：将 GraphRAG 功能集成到现有的 RAG 系统中
- **输入**：分析上下文、查询文本等
- **输出**：混合搜索结果、攻击链等

## 4. 图谱设计

### 4.1 节点类型

| 节点类型 | 标签 | 描述 |
|---------|------|------|
| 代码结构 | `Function` | 函数节点 |
|  | `Class` | 类节点 |
|  | `File` | 文件节点 |
| 漏洞语义 | `Vulnerability` | 漏洞节点 |
|  | `CVE` | CVE 节点 |
|  | `Weakness` | CWE 节点 |
| 行为节点 | `Source` | 用户输入节点 |
|  | `Sink` | 危险函数节点 |
|  | `Sanitizer` | 过滤函数节点 |
| 系统节点 | `Service` | 服务节点 |
|  | `API` | API 节点 |
|  | `Endpoint` | 端点节点 |

### 4.2 边类型

| 边类型 | 关系 | 描述 |
|---------|------|------|
| 代码关系 | `CALLS` | 函数调用 |
|  | `IMPORTS` | 模块导入 |
|  | `EXTENDS` | 类继承 |
| 数据流 | `TAINT_FLOW` | 污点流 |
|  | `DATA_FLOW` | 数据流 |
| 漏洞关系 | `CAUSES` | 导致 |
|  | `TRIGGERS` | 触发 |
|  | `EXPLOITS` | 利用 |
| 攻击链 | `LEADS_TO` | 导致 |
|  | `CHAIN_STEP` | 攻击链步骤 |

## 5. 使用方法

### 5.1 从代码构建图谱

```python
from src.graphrag.graphrag_adapter import get_graphrag_adapter
from src.analyzers.base import AnalysisContext

# 创建分析上下文
context = AnalysisContext(
    file_path="test.py",
    file_content="""
def login():
    username = input("Enter username: ")
    password = input("Enter password: ")
    return username, password

def process_data(data):
    import os
    os.system("echo " + data)

user = input("Enter input: ")
process_data(user)
""",
    language="python"
)

# 获取 GraphRAG 适配器
adapter = get_graphrag_adapter()

# 从代码构建图谱
adapter.build_graph_from_code(context)

# 获取图谱统计信息
stats = adapter.get_graph_statistics()
print(stats)
```

### 5.2 混合搜索

```python
# 混合搜索
query = "是否存在命令注入漏洞"
results = adapter.hybrid_search(query, top_k=5)

for result in results:
    print(f"{result['type']} ({result['source']}): {result['content']} (score: {result['score']:.2f})")
```

### 5.3 查找攻击链

```python
# 查找攻击链
attack_chains = adapter.find_attack_chains()
print(f"攻击链数量: {len(attack_chains)}")
```

## 6. 依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| neo4j | 5.0+ | 图数据库 |
| langchain | 0.1.0+ | 链管理 |
| faiss-cpu | 1.7.4+ | 向量存储 |
| transformers | 4.30.0+ | 嵌入模型 |
| networkx | 3.0+ | 图处理 |

## 7. 注意事项

1. **Neo4j 服务**：GraphRAG 需要 Neo4j 服务运行在 `bolt://localhost:7687`，默认用户名 `neo4j`，密码 `password`。

2. **性能优化**：对于大规模代码库，建议：
   - 使用子图缓存
   - 启用并行处理
   - 配置合适的内存限制

3. **扩展**：可以通过以下方式扩展 GraphRAG：
   - 添加更多节点和边类型
   - 实现更复杂的攻击链推理
   - 集成更多数据源

## 8. 测试

### 8.1 测试图谱构建

```bash
python test_graphrag_builder.py
```

### 8.2 测试 GraphRAG 适配器

```bash
python test_graphrag_adapter.py
```

## 9. 结论

GraphRAG 集成将为 HOS-LS 带来质的飞跃，从简单的关键词匹配升级到深度理解攻击路径的能力。通过不破坏现有架构，只做增强层的方式，实现平滑过渡。

实施后，HOS-LS 将具备：
- 理解完整攻击路径的能力
- 识别跨文件漏洞的能力
- 识别组合漏洞的能力
- 自动推断 exploit 链的能力

这将使 HOS-LS 在 AI 安全扫描领域处于领先地位。