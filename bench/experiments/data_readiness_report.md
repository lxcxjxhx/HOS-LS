# HOS-LS 论文实验数据就绪报告

生成时间: 2026-08-28 19:49:38

---

## 1. VulnGym 数据集

| 指标 | 数值 |
|---|---|
| 总 Entries | 408 |
| 已验证 (verify=1) | 393 (96.3%) |
| 总 Advisories | 184 |
| 项目数 | 38 |

### 漏洞类别分布

- **业务逻辑**: 278
- **代码注入**: 21
- **命令注入**: 14
- **反序列化漏洞**: 11
- **XSS**: 9
- **SSRF**: 9
- **路径穿越**: 8
- **反序列化**: 8
- **沙箱逃逸**: 6
- **认证绕过**: 5
- **文件操作安全**: 4
- **越界文件读取**: 4
- **特权提升**: 4
- **模板注入**: 3
- **供应链攻击**: 3
- **注入与反序列化**: 3
- **原型链污染**: 3
- **Code Injection**: 2
- **权限绕过**: 2
- **注入类**: 2
- **路径遍历 / 越权写入**: 2
- **信息泄露**: 2
- **注入**: 1
- **路径遍历 / 任意文件读取**: 1
- **XSS（跨站脚本）**: 1
- **路径遍历 / 沙箱逃逸**: 1
- **注入攻击**: 1

### 跨文件复杂度

- **single**: 148
- **2-3_files**: 202
- **4plus_files**: 58

### 语言分布

- **typescript**: 300
- **python**: 74
- **go**: 19
- **unknown**: 11
- **javascript**: 4

### 代码长度统计

- 平均: 82.0 字符, 中位数: 61, 范围: 1–604
- 含 trace 的条目: 408/408

---

## 2. SecureVibeBench 数据集

| 指标 | 数值 |
|---|---|
| HuggingFace 数据集 | iCSawyer/SecureVibeBench |
| 总实例数 | 105 |

### 漏洞类别分布（样本内）

---

## 3. 止损实验分层样本

| 指标 | 数值 |
|---|---|
| 总样本数 | 0 |
| 目标样本数 | 40–60 |
| 状态 | ⚠️ 需调整 |

### 各层样本数


---

## 4. AI Patch 对

| 指标 | 数值 |
|---|---|
| 已构造 | 0 |
| 输出目录 | `bench/experiments/ai_patches/` |

### Patch 类型分布


---

## 5. 工具链验证

### semgrep: ✅
- **version**: 1.150.0
- **rules_per_lang**: {"python": 151, "javascript": 74, "typescript": 74, "java": 60, "go": 42, "c": 2, "cpp": 0, "ruby": 44, "rust": 0}

### codeql: ✅
- **version**: CodeQL command-line toolchain release 2.26.4.
- **qlpack_dir**: C:\1AAA-PROJECT\HOS\HOS-LS\envs\codeql-packs
- **qlpacks**: ['.devcontainer', '.git', '.github', '.vscode', 'actions', 'change-notes', 'config', 'cpp', 'csharp', 'docs', 'go', 'java', 'javascript', 'misc', 'python', 'ql', 'ruby', 'rust', 'shared', 'swift', 'unified']

### hosls_cli: ✅
- **version**: ┌──────────────────────────────────────────────────┐
│ ╔══════════════════════════════════════╗     

### local_repos: ℹ️
- **count**: 23
- **total_size_mb**: 2740.4
- **repos**: {"adk-python": {"size_mb": 33.8}, "airflow": {"size_mb": 178.9}, "AutoGPT": {"size_mb": 183.8}, "fastmcp": {"size_mb": 57.0}, "Flowise": {"size_mb": 42.3}, "langchain": {"size_mb": 39.3}, "langflow": {"size_mb": 206.5}, "litellm": {"size_mb": 158.4}, "milvus": {"size_mb": 116.7}, "mlflow": {"size_mb": 383.7}, "n8n": {"size_mb": 192.8}, "n8n-mcp": {"size_mb": 112.9}, "NeMo": {"size_mb": 132.5}, "nltk": {"size_mb": 9.3}, "ollama": {"size_mb": 52.7}, "onnx": {"size_mb": 23.0}, "open-webui": {"size_mb": 100.1}, "openclaw": {"size_mb": 421.3}, "paperclip": {"size_mb": 117.2}, "trivy": {"size_mb": 90.3}, "typescript-sdk": {"size_mb": 10.0}, "vulngym-source": {"size_mb": 2.0}, "WeKnora": {"size_mb": 75.9}}

---

## 6. 基线覆盖状态

| 基线 | 状态 | 说明 |
|---|---|---|
| ✅ Semgrep (规则) | ✅ | 按语言选规则包 (Rules: {'python': 151, 'javascript': 74, 'typescript': 74, 'java': 60, 'go': 42, 'c': 2, 'cpp': 0, 'ruby': 44, 'rust': 0}) |
| ✅ CodeQL | ✅ | 本地 QL packs: 21 |
| ✅ 本地仓库 | ✅ | 23 个 (2740.4 MB) |
| ✅ 裸 Agent (same-backbone) | ✅ | 通过 HOS-LS 纯 AI 模式 |
| ✅ SAL/DEP 消融 | ✅ | 配置开关控制 |
| ✅ 定位基线 | ✅ | changed-files/BM25/call graph 集成 |

---

*报告由 `bench/prepare_benchmark_data.py` 自动生成*