# Ground Truth 订装模板（P0 方案 §3.1 / §6 W1*）

> 每个漏洞案例一份，命名 `GT-<sample_id>.md`（如 `GT-svb-0092.md`）。
> 字段命名沿用 v1 `src/ecatsl/models.py::BenchmarkSample` 风格，
> 按方案 §6 只新增 `introducing_hunk` / `pov_ref` 两字段；
> 其余 P0 字段为数据集原字段与订装包内容的展开，不进入 v1 manifest。

```yaml
# ── v1 BenchmarkSample 风格字段（沿用命名，不接 v1 manifest）──
sample_id: "svb-<localid>"        # = case_id，全局唯一
classification: ""                 # 官方四分类：IC / C-VUL / C-SUS / C-SEC
project_id: ""                     # 从 repo_url 提取（如 file、zstd）
project_time_group: ""             # 订装周次（W1-W4），沿用 v1 分组风格
content_hash: ""                   # 人工复核通过后对本文件计算 sha256
pair_id: ""                        # v1 字段保留；P0 单例订装，默认空

# ── P0 方案 §6 新增两字段 ──
introducing_hunk: ""               # 引入 hunk：git show vic 的 diff 片段引用（file:line 范围）
pov_ref: ""                        # PoV 程序引用：ARVO 现成产物路径/标识

# ── 数据集原字段（SecureVibeBench，实测核实）──
localid: ""
repo_url: ""
vic: ""                            # vulnerability-inducing commit（ground truth 锚点）
repo_cwd: ""
description: ""                    # 安全中性任务描述，原样拷贝，不得改写

# ── P0 订装扩展（仲裁与三场景映射用）──
fix_commit: ""                     # 修复 commit 引用（只作仲裁参照，B 臂不可见）
vuln_mechanism: ""                 # 漏洞机制一句话（人工概括）
scenario: ""                       # 三场景标签：1=权限/边界作用域 2=遗漏 sibling 3=不完整修改
cwe: ""                            # 人工核实 CWE（数据集不提供，逐条核实）
```

## 随附材料清单

| 项 | 要求 |
| --- | --- |
| R_before | `git worktree add <dir> <vic>^` 检出路径 |
| R_after | `git worktree add <dir> <vic>` 检出路径 |
| 引入 hunk | 从 `git show vic` 摘出，写入 `introducing_hunk` |
| PoV 程序 | ARVO 现成产物，登记 `pov_ref`，不做二次开发 |
| 修复 commit | 登记哈希，仅仲裁用 |
