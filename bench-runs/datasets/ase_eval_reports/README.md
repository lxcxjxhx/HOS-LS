# A.S.E AI-Patch 差分验证实验数据（SAL × DEP 止损实验）

> 面向 AI 生成代码变更的可归因、可证伪漏洞验证 —— (R_before, task, Δ_AI, R_after)
> 协议与机制说明见论文 18/20/22 号文档；本文档说明数据与复现。

## 目录

```
bench-runs/datasets/
  ase_with_vuln_code.json       A.S.E 27 实例元数据（vuln_code 摘录）
  ase_samples/                  （本 PR 新增）
    manifest.json               27 样本清单（CWE/语言/上下文来源/行数）
    *.php / *.py                漏洞代码（R_before：6 个真实仓库样本为 base_commit 完整文件，
                                 其余为漏洞函数摘录）
    patched/*.php|*.py          Δ_AI 修复版（R_after，mimo-v2.5-pro 生成）
    patched/_patch_meta_full.json  补丁生成记录（usage/行数）
  ase_eval_reports/             （本 PR 新增）
    ase-vuln-scan-results.json   27 个 vuln 端 HOS-LS pure-ai 扫描汇总
    ase-patched-scan-results.json 10 个 patched 端扫描汇总（DEP 子集）
    ase-vuln-analysis.json       检出/类型错位逐样本分析
```

## 复现

```bash
# 1. 环境
export HOS_LS_AI_API_KEY=<key>          # token-plan key
export HTTP_PROXY=http://127.0.0.1:7890 # 或本机可用代理
export GIT_SSL_BACKEND=openssl          # Windows git + 本地代理必需

# 2. 扫描 vuln 端（27 文件，3 并发，约 20 分钟）
python scripts/ai_patch_eval.py scan bench-runs/datasets/ase_samples/_scan_list.json \
    bench-runs/ase_eval_reports/ase-vuln-scans 3 ase-vuln

# 3. 生成 Δ_AI 补丁（对 CONFIRMED 子集）
python scripts/ai_patch_eval.py gen-patch-full bench-runs/datasets/ase_samples/manifest-dep-subset.json \
    bench-runs/datasets/ase_samples/patched 3

# 4. 扫描 patched 端 + DEP 判定
python scripts/ai_patch_eval.py scan <patched列表> bench-runs/ase_eval_reports/ase-patched-scans 3 ase-patched
python scripts/ai_patch_eval.py dep-ase bench-runs/datasets/ase_samples/manifest.json \
    bench-runs/ase_eval_reports/ase-vuln-scan-results.json bench-runs/ase_eval_reports/ase-patched-scan-results.json
```

## 结果（2026-08-27，mimo-v2.5-pro）

| 指标 | 值 |
|---|---|
| vuln 端检出（CONFIRMED） | **10/27 = 37.0%** |
| Pair-Correct（no-DEP） | 7/27 = 25.9% |
| Pair-Correct（DEP-tight） | 7/27 = 25.9% |
| **AI 补丁残留（DEP 拒绝）** | **3/10 = 30%**（路径遍历残留 ×2、修复引入 SQL 参数问题 ×1） |
| 成本 | ~¥1.5（止损线内） |

关键结论：无差分验证时 30% 的 AI 生成修复会被误判为"已修复"；DEP 把
"AI 修好了"从 10 收紧到 7 —— 该信号在真实 AI 补丁上可复现、可证伪。

## 注意

- `ase_with_vuln_code.json` 的 `vuln_code` 带行号前缀，`prep_ase_samples.py` 负责剥离。
- `ase_with_diffs.json` 的 `vuln_content`/`diff` 字段为下载时截断（1000/2000 字符），
  不可用作完整文件；6 个有 base_commit 的样本直接经 GitHub API 拉取完整文件。
