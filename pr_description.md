# feat: AI 补丁差分验证（SAL × DEP）止损实验数据 + 候选精化

## 问题
HOS-LS 的 AI 漏洞检测缺一个"可证伪"的验证协议：现有 CONFIRMED 依赖模型自我确认，
Pair-Correct 口径不检查"危险模式在修复后是否消失"（论文 §一.2 口径脆弱性）。

## 本 PR 内容
1. **A.S.E 27 实例 AI 补丁双端扫描数据**（`bench-runs/datasets/ase_samples/` +
   `ase_eval_reports/`）：漏洞代码（R_before）→ mimo-v2.5-pro 生成修复（Δ_AI）→
   修复版（R_after）→ vuln/patched 双端独立 HOS-LS pure-ai 扫描 + DEP 消失性判定。
2. **SAL 候选精化**（`audit_eval.py`）：跳过 vendored/打包产物（node_modules/dist/
   static/vendor、`.min.`/`bundle`、>1.5MB），消除 swagger-ui 类 bundle 对候选排名的污染。
3. **复现脚本**：`scripts/ai_patch_eval.py`（Δ_AI 生成 / 双端扫描 / DEP 判定 / 断点续跑 /
   超时兜底）、`scripts/prep_ase_samples.py`（行号剥离 + base_commit 全文件拉取）。
4. **代理修复**：脚本硬编码的 7897 代理（已失效）改为环境变量驱动（当前 7890）；
   Windows 下 git 需 `GIT_SSL_BACKEND=openssl`。

## 结果（2026-08-27，mimo-v2.5-pro，成本 ~¥1.5）
- vuln 端检出：**10/27 = 37.0%**（CONFIRMED；6 个完整文件样本 0 检出 → 大文件上下文稀释，
  支持 SAL 候选压缩而非全仓扫描）
- **DEP 收紧：3/10（30%）AI 生成补丁仍被检出 CONFIRMED** —— 路径遍历残留 ×2
  （主路径修复、分支路径仍可利用）+ 修复引入 SQL 参数未验证问题 ×1
- Pair-Correct：7/27 = 25.9%（no-DEP 与 DEP 口径一致，因残留均为 CONFIRMED）

## 验证
- `python scripts/ai_patch_eval.py dep-ase ...` 一键复算（README 有完整步骤）
- token_records 记账：vuln 端 78.1 万 input / 17.1 万 output tokens ≈ ¥0.49

## 后续
- SecureVibeBench 105 仓库多文件任务 + A.S.E 120 全量（补 XSS）→ 40-60 分层全量
- 基线补齐：Semgrep / CodeQL / DREA / 裸 agent 同口径
