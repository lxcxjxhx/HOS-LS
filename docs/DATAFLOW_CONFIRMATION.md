# HOS-LS 数据流确认

> 验证 `PureAIAnalyzer` (7 Agent) 的结果是否被持久化到扫描输出。

## 完整数据流

```
_analyze_files()
│
├── [pure_ai = True]
│   ├── Step1: ConfigScanner → findings
│   ├── Step1.5: CodeVulnScanner → findings
│   ├── Step2: Dependency-CVE → findings
│   ├── OPT-SASTR: SastPrefilter (CodeQL + TaintEngine) → ai_findings
│   ├── Step3: PureAIAnalyzer (7 Agent) → ai_findings
│   │         └── src/cli/main.py:L2621: findings.extend(ai_findings) ✅
│   └── Step4: 去重 + 保护 ✅
│       └── return findings, len(prioritized_files) ✅ (L2788)
│
├── [pure_ai = False]
│   └── 逐个文件分析（不用 ALL 路径）
│
└── scan() L906: findings, analyzed_count = await self._analyze_files(files)
    └── pure_ai 模式 L971-1055:
        for finding in findings:  # ← 包含 7 Agent 结果
            result.add_finding(finding) ✅
    └── result 写入 JSON 输出 ✅
```

## 关键确认点

| 行号 | 代码 | 含义 |
|---|---|---|
| L2621 | `findings.extend(ai_findings)` | 7 Agent 结果合并入 findings |
| L2788 | `return findings, len(prioritized_files)` | 返回值包含所有 findings |
| L906 | `findings, _ = await self._analyze_files(files)` | 接收 findings |
| L971 | `if self.config.pure_ai:` | 进入 pure_ai 结果汇总 |
| L979 | `for finding in findings:` | 逐条写入 result |
| L1055 | `result.add_finding(finding)` | 持久化到扫描结果 |

## 报告输出格式

`--output report.json` 输出的 JSON 包含：

```json
{
  "results": [
    {
      "target": "...",
      "status": "completed",
      "findings": [
        {
          "rule_name": "<7 Agent 推理结果>",
          "severity": "high",
          "confidence": 0.88,
          ...
        }
      ],
      "summary": {
        "total_findings": 155,
        "high": 30
      }
    }
  ]
}
```

> 确认时间: 2026-08-17
