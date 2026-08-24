# 面向AI生成代码变更的差分漏洞验证系统

## 概述

本系统实现了导师要求的**"AI生成代码补丁的差分漏洞验证"**，核心创新点：

1. **输入格式**：三元组 `(R_before, task_desc, Δ_AI)`
2. **核心机制**：SAL（定位）+ DEP（验证）
3. **验证方式**：差分 + 反事实验证
4. **评测指标**：Pair-Correct（成对准确率）

## 系统架构

```
输入: (R_before, task_desc, Δ_AI)
        ↓
[1] 定位员 (Locator Agent)
    - 从Modified_Funcs出发
    - 找到到Sink的路径
        ↓
[2] 差分员 (Differ Agent)
    - 对比改前改后路径
    - 标记Suspicious路径
        ↓
[3] 证伪员 (Verifier Agent)
    - 反事实验证
    - 回退补丁后路径是否消失
        ↓
输出: JSON报告
    - vulnerability_found: bool
    - critical_path: 调用链
    - verification_evidence: 验证证据
```

## 文件结构

```
HOS-LS-paper/bench-runs/hos-ls/
├── src/
│   ├── sal/                              # SAL模块
│   │   ├── sink_registry.py             # Sink注册表
│   │   └── path_explorer.py             # 路径探索器
│   ├── dep/                              # DEP模块
│   │   ├── differ.py                    # 路径差异对比
│   │   └── counterfactual.py            # 反事实验证
│   ├── ai/pure_ai/
│   │   ├── locator_agent.py             # 定位员Agent
│   │   ├── differ_agent.py              # 差分员Agent
│   │   └── verifier_agent.py            # 证伪员Agent
│   └── orchestrator.py                  # 主控协调器
├── data/
│   ├── schema.py                        # 数据Schema
│   ├── securevibench_loader.py          # SecureVibeBench加载器
│   └── ase_loader.py                    # A.S.E加载器
├── eval/
│   ├── metrics.py                       # Pair-Correct指标
│   ├── ablation.py                      # 消融实验
│   └── baseline_runner.py              # 基线对比
└── scripts/
    ├── download_datasets.py             # 数据集下载
    ├── run_stoploss_experiment.py       # 止损实验
    └── run_baseline_comparison.py       # 基线对比
```

## 快速开始

### 1. 下载数据集

```bash
cd HOS-LS-paper/bench-runs/hos-ls
python scripts/download_datasets.py
```

### 2. 运行止损实验

```bash
python scripts/run_stoploss_experiment.py
```

### 3. 运行基线对比

```bash
python scripts/run_baseline_comparison.py
```

### 4. 使用Python API

```python
import asyncio
from src.orchestrator import Orchestrator, PatchTriplet

async def main():
    # 输入三元组
    triplet = PatchTriplet(
        r_before="/path/to/repo",
        task_desc="Fix SQL injection vulnerability",
        delta_ai="--- a/app.py\n+++ b/app.py\n...",
    )
    
    # 运行分析
    orchestrator = Orchestrator()
    report = await orchestrator.analyze(triplet)
    
    # 输出结果
    print(f"Vulnerability found: {report.vulnerability_found}")
    print(f"Confidence: {report.confidence}")
    print(f"Evidence: {report.verification_evidence}")

asyncio.run(main())
```

## Agent复用说明

| 新Agent | 复用来源 | 说明 |
|---------|----------|------|
| **定位员** | Agent 2 (风险枚举) | 修改prompt，从"枚举风险"→"找路径到Sink" |
| **差分员** | 无（全新） | 全新实现，对比前后路径 |
| **证伪员** | Agent 3 + Agent 5 | 合并验证+对抗逻辑 |

## 评测指标

### Pair-Correct

成对准确率：漏洞样本预测为有漏洞，修复样本预测为无漏洞。

```
Pair-Correct = 正确对数 / 总对数
```

### 消融实验

比较三种配置：
- **LOCATOR_ONLY**：只运行定位员
- **DIFFER_ONLY**：只运行差分员
- **FULL**：运行完整系统

## 基线对比

与以下基线对比：
- **Semgrep**：静态规则扫描
- **CodeQL**：代码QL查询
- **Bare Agent**：不带SAL/DEP的裸Agent

## 下一步

1. **数据准备**：下载SecureVibeBench和A.S.E数据集
2. **集成测试**：运行止损实验（40-60样本）
3. **基线对比**：运行Semgrep/CodeQL/DREA/IRIS
4. **性能优化**：并行扫描、缓存机制

## 参考

- [SecureVibeBench](https://github.com/iCSawyer/SecureVibeBench)
- [A.S.E (AICGSecEval)](https://github.com/Tencent/AICGSecEval)
- [DREA](https://github.com/DREA-Artifact)
