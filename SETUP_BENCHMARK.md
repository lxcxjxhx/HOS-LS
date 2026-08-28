# HOS-LS 止损实验 — 资源下载与安装指南

> **背景**：本实验旨在 40-60 个分层样本上验证 SAL（Semgrep-Agent 前置筛选）是否真正提升最终检测率、DEP（反事实验证）是否显著提高 Pair-Correct。
>
> **两套数据主线**：
> - **AI 代码检测主线**：SecureVibeBench (ACL 2026) + A.S.E.
> - **通用检测副线**：VulnGym (Tencent)

---

## ✅ 已完成的准备工作

| 项目 | 状态 | 位置 |
|------|------|------|
| API Key 管理系统 | ✅ 已完成 | `src/ai/key_manager.py` — 统一密钥管理，支持 .env |
| DeepInfra Provider | ✅ 已完成 | `src/ai/providers/deepinfra.py` — flex 模式请求头 |
| API Key 已填入 | ✅ 已完成 | `.env` 文件（已加入 .gitignore） |
| SemgrepAgent | ✅ 已完成 | `src/ai/pure_ai/semgrep_agent.py` — 硬性前置筛选 |
| DiffAnalysisAgent | ✅ 已完成 | `src/ai/pure_ai/diff_analysis_agent.py` |
| ContractViolationAgent | ✅ 已完成 | `src/ai/pure_ai/contract_violation_agent.py` |
| CounterfactualAgent | ✅ 已完成 | `src/ai/pure_ai/counterfactual_agent.py` |
| Agent Selector 增强版 | ✅ 已完成 | `src/ai/pure_ai/agent_selector.py` |
| Semgrep CLI | ✅ 已安装 | v1.159.0 |
| VulnGym 数据集 | ✅ 已克隆 | `bench/datasets/VulnGym/` (408 entries) |
| SecureVibeBench 代码 | ✅ 已克隆 | `bench/datasets/SecureVibeBench/` (105 任务评估框架) |
| 对比测试脚本 | ✅ 已完成 | `bench/run_comparison.py` |
| 基准评测脚本 | ✅ 已有 | `bench/benchmark.py` |

---

## 📦 需要手动下载的数据集

### 1. VulnGym 源项目代码库（止损实验核心）

VulnGym `entries.jsonl` 中的 `critical_operation` / `entry_point` / `trace` 字段包含漏洞代码片段，但**要进行完整的 HOS-LS 仓库级扫描**，需要下载源项目的完整代码仓库。

**共 38 个项目，按漏洞条目数排序：**

| # | 项目 | 条目数 | 仓库地址（请填写实际下载链接） |
|--:|------|-------:|-------------------------------|
| 1 | openclaw | 188 | [ ] |
| 2 | n8n | 52 | [ ] |
| 3 | FlowiseAI/Flowise | 39 | [ ] |
| 4 | NVIDIA/NeMo | 19 | [ ] |
| 5 | langflow | 11 | [ ] |
| 6 | paperclip | 17 | [ ] |
| 7 | mlflow | 7 | [ ] |
| 8 | ollama | 6 | [ ] |
| 9 | WeKnora | 6 | [ ] |
| 10 | fastmcp | 6 | [ ] |
| 11 | google/adk-python | 6 | [ ] |
| 12 | open-webui | 4 | [ ] |
| 13 | milvus-io/milvus | 4 | [ ] |
| 14 | apache/airflow | 4 | [ ] |
| 15 | aquasecurity/trivy | 3 | [ ] |
| 16 | n8n-mcp | 3 | [ ] |
| 17 | AutoGPT | 2 | [ ] |
| 18 | modelcontextprotocol/typescript-sdk | 2 | [ ] |
| 19 | Significant-Gravitas/AutoGPT | 2 | [ ] |
| ... | (共 38 个项目) | 408 | |

**止损实验分层抽样建议（40-60 条）：**

下载优先级：**openclaw (188) → n8n (52) → Flowise (39) → 其余**（任选各项目 2-5 条）

```powershell
# 下载到 bench/datasets/repos/ 目录
# 示例（需要你填写正确的 repo URL）：
git clone <repo_url> bench/datasets/repos/openclaw
git clone <repo_url> bench/datasets/repos/n8n
# ...
```

### 2. SecureVibeBench 实例数据（HuggingFace）

SecureVibeBench 的 105 个 C/C++ 漏洞任务实例托管在 HuggingFace，不在 GitHub 仓库内。
GitHub 仓库（已克隆）仅包含评估框架脚本，实例数据需要额外下载。

| 项目 | 值 |
|------|-----|
| 数据集 | `iCSawyer/SecureVibeBench` |
| 平台 | HuggingFace Datasets |
| 大小 | ~1-2 GB（包含 105 个任务的代码仓库快照） |
| 用途 | AI 代码安全的止损实验主基准 |

**下载方法**：
```bash
# 方法1: 通过 huggingface_hub
pip install huggingface_hub
python -c "
from huggingface_hub import snapshot_download
snapshot_download(repo_id='iCSawyer/SecureVibeBench', 
                  local_dir='bench/datasets/SecureVibeBench_HF')
"

# 方法2: 直接 git clone（需要安装 git-lfs）
git lfs install
git clone https://huggingface.co/datasets/iCSawyer/SecureVibeBench bench/datasets/SecureVibeBench_HF
```

> **提示**: SecureVibeBench 评估框架已存在于 `bench/datasets/SecureVibeBench/`，运行 `bash run.sh aider MODEL 992` 可触发单条评估；但实例数据需要从 HF 拉取。

### 2. A.S.E. (Automated Security Experiment) 数据集

在论文 SecureVibeBench 的姊妹工作中被提及，包含 120 个仓库级安全生成实例（仅覆盖四类 Web 漏洞：SQLi, XSS, Command Injection, Path Traversal）。

| 项目 | 值 |
|------|-----|
| 参考文献 | SecureVibeBench A.S.E. |
| 规模 | ~120 个仓库级实例 |
| 覆盖 | SQLi, XSS, CMDi, Path Traversal |
| 搜索关键词 | `A.S.E. Automated Security Experiment` 或 `ASE benchmark security` |

**建议搜索方式**:
- Google: `"SecureVibeBench" "A.S.E." github`
- 查看 SecureVibeBench 论文的"Related Work"部分引用
- GitHub: `github.com/topics/security-benchmark`

### 3. DREA 对比基线工具

| 项目 | 搜索关键词 |
|------|-----------|
| DREA | `DREA vulnerability detection LLM agents` |
| IRIS | `IRIS vulnerability detection LLM` |
| SemTaint | `SemTaint semantic taint analysis` |

---

## 🔧 需要安装的对比工具

### 1. CodeQL（高优先级）

CodeQL 是论文基线中最关键的对比工具之一（"正确配置后的 CodeQL"）。

| 项目 | 值 |
|------|-----|
| 版本 | CodeQL CLI 2.20+ |
| 下载 | https://github.com/github/codeql-cli-binaries/releases |
| 查询包 | `codeql/<language>-queries` |
| 配置 | HOS-LS 已支持自动检测（`sast_prefilter.py`） |

**安装步骤**：
```powershell
# 1. 下载 CodeQL CLI
# 从 https://github.com/github/codeql-cli-binaries/releases 下载 codeql-win64.zip

# 2. 解压到项目 envs 目录
Expand-Archive codeql-win64.zip -DestinationPath envs/codeql/

# 3. 下载查询包
git clone --depth 1 https://github.com/github/codeql.git envs/codeql-packs/

# 4. 验证
envs\codeql\codeql.exe version
```

### 2. Bandit（可选）

纯 Python SAST 工具，HOS-LS 的 `sast_prefilter.py` 中作为 Semgrep 失败时的兜底工具。

```bash
pip install bandit
```

### 3. DREA / IRIS / SemTaint（低优先级）

这些是论文基线，用于消融实验的对比，可以在止损实验之后再安装。

| 工具 | 安装方式 |
|------|---------|
| DREA | `git clone https://github.com/[org]/DREA.git` |
| IRIS | `pip install iris-toolkit` |
| SemTaint | `git clone https://github.com/[org]/SemTaint.git` |

---

## 🎯 止损实验步骤（VulnGym 优先）

**第0步：确认环境**
```powershell
# 确认 Key 已加载
cd C:\1AAA-PROJECT\HOS\HOS-LS
python -c "from src.ai.key_manager import get_api_key; print('DeepSeek key:', get_api_key('deepseek')[:8]+'...' if get_api_key('deepseek') else 'NOT SET')"
```

**第1步：拉取 VulnGym 的代码样本**
```powershell
# VulnGym 的 entries.jsonl 中的关键字段:
# - entry_id: 唯一 ID
# - vuln_category_l1: 漏洞大类（业务逻辑、SQL注入、XSS、SSRF等）
# - vuln_category_l2: 漏洞子类
# - project: 源项目（openclaw, n8n, Flowise, paperclip, langflow 等）
# - origin: GitHub Advisory Database
# - critical_operation: {code, desc, file, line} — 漏洞关键操作代码片段
# - entry_point: {code, desc, file, line} — 漏洞入口点
# - trace: [...] — 完整攻击链（每个节点有 code 和 desc）

# 如果需要完整仓库来跑 HOS-LS，需要下载源项目代码
# 常用的项目：
git clone --depth 1 https://github.com/n8n-io/n8n.git bench/datasets/repos/n8n
git clone --depth 1 https://github.com/FlowiseAI/Flowise.git bench/datasets/repos/Flowise
git clone --depth 1 https://github.com/langflow-ai/langflow.git bench/datasets/repos/langflow
git clone --depth 1 https://github.com/mlflow/mlflow.git bench/datasets/repos/mlflow
git clone --depth 1 https://github.com/open-webui/open-webui.git bench/datasets/repos/open-webui
```

**第2步：运行对比测试**
```powershell
# Semgrep 基准（快，50 条约 2-3 分钟）
python bench/run_comparison.py --tool semgrep --limit 50

# HOS-LS 基准（慢，5 条约 10-15 分钟，需要 API Key）
python bench/run_comparison.py --tool hosls --limit 5
```

**第3步：执行 40-60 分层抽样**

分层维度：
1. **漏洞类型**（DREA 论文中使用）：
   - SQL注入、XSS、命令注入、路径穿越 → 各类 10 条
   - SSRF、反序列化、认证绕过 → 各类 5 条
2. **项目规模**：
   - 小项目（openclaw 系列：190 条）
   - 中项目（n8n: 52 条、Flowise: 39 条）
   - 大项目（milvus、airflow 等：10-20 条）
3. **来源**：全部来自 GitHub Advisory Database (reviewed) — 有权威性

**第4步：对比指标**

| 指标 | 说明 |
|------|------|
| CONFIRMED 检出率 | 最终确认的漏洞 / 总样本 |
| Pair-Correct@1 | 正确定位到漏洞行（SAL 对比裸 agent） |
| 误报率 | patched/安全样本中被标记为漏洞的 |
| 平均 Token 消耗 | SAL 筛选后 token 对比全 LLM 模式 |
| 差分证据正确率 | DiffAnalysisAgent 正确标记变更风险路径的比例 |
| 反事实通过率 | CounterfactualAgent 验证通过的比例 |

---

## 📊 基线对比矩阵（论文要求）

| 基线 | 状态 | 说明 |
|------|------|------|
| Semgrep (p/default + p/security-audit) | ✅ 可用 | 直接命中率作为硬性检出基线 |
| CodeQL | ❌ 需安装 | 仓库级深度分析，高精度基线 |
| 裸 Agent（same-backbone, same-budget） | ✅ 已有 | HOS-LS 不加新 Agent 的原始版 |
| SAL (SemgrepAgent 前置筛选) | ✅ 可用 | 新组件，效果需要实验验证 |
| DEP (CounterfactualAgent) | ✅ 可用 | 新组件，效果需要实验验证 |
| SAL + DEP 完整消融 | ✅ 可用 | 两个新组件同时启用 |
| DREA | ❌ 需下载 | LLM 漏洞检测基线 |
| IRIS/SemTaint | ❌ 需下载 | 在其支持语言上的可比子集 |
| changed-files / BM25 定位基线 | ❌ 需实现 | 候选文件定位的对比方法 |
