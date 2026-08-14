# HOS-LS 评测分数卡（Benchmark）

在标准评测集上以 `--pure-ai` 模式扫描，产出可复现的分数卡，用于量化每次优化的
**召回率 / 误报率 / 耗时 / Token 消耗**。

## 评测集

- 位置：`bench-runs/hosls-eval/`（仓库外，`HOS-LS-paper/bench-runs/hosls-eval`）
- `vuln/`：100 个含漏洞的真实代码样本
- `patched/`：100 个对应修复后样本（用于测误报/精度）

## 用法

```bash
# 默认：扫 vuln 前 20 个文件，3 并发
python -m bench.benchmark --groups vuln --limit 20 --workers 3 --tag my-run

# 全量 vuln + patched（约 1-3 小时，视 API 速度）
python -m bench.benchmark --groups vuln,patched --limit 100 --workers 3 --tag release-check

# 指定评测集目录
python -m bench.benchmark --vuln-dir <路径> --patched-dir <路径> --limit 50
```

## 输出

- `bench/artifacts/<tag>/<group>-results.json`：每个文件的原始指标
- `bench/artifacts/<tag>/scorecard.json`：汇总分数卡

```json
{
  "groups": {
    "vuln": {
      "confirmed_hit_rate": 35.0,      // 文件级 CONFIRMED 召回（主指标）
      "any_finding_rate": 57.0,
      "total_tokens": 123456,          // 输入+输出 token（来自报告 token_records）
      "avg_total_tokens_per_file": 1234.6,
      "wall_time_s": 3534.0
    },
    "patched": {
      "confirmed_hit_rate": 60.0       // 误报率（patched 被 CONFIRMED 的文件占比）
    }
  },
  "summary": { "vuln_recall": 35.0, "patched_fp_rate": 60.0 }
}
```

## 关键指标定义

| 指标 | 定义 |
|---|---|
| CONFIRMED 召回 | 至少 1 条 finding 的顶层 `status == CONFIRMED` 的文件占比 |
| 误报率 | patched 样本中被 CONFIRMED 的文件占比 |
| token | 报告 `token_records` 中 `prompt_tokens` / `completion_tokens` 之和 |
| 耗时 | 全部文件扫描的墙钟时间 |

## 注意

- 每个文件在独立子进程中扫描（避免单例状态污染），超时 400s。
- API Key 来自 `hos-ls.yaml`（本地，不入库）或环境变量 `HOS_LS_AI_API_KEY`。
- CI 不运行本工具（需要 API Key）。
