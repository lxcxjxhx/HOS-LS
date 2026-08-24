## 概述

实现导师要求的**「AI生成代码补丁的差分漏洞验证」**系统，将问题从仓库级扫描收紧为差分验证。

## 核心创新点

| 创新点 | 实现 |
|--------|------|
| **输入格式** | `PatchTriplet(r_before, task_desc, Δ_AI)` 三元组 |
| **SAL机制** | Sink注册表（30+定义）+ 正向/反向路径探索 |
| **DEP机制** | 差分对比 + 反事实验证（回退补丁后路径消失） |
| **评测指标** | Pair-Correct（成对准确率） |
| **性能优化** | LLM客户端封装 + 结果缓存 + 并行处理 |

## 新增文件（22个源码 + 7个测试）

### 核心模块
- `src/sal/` - Sink Anchoring & Localization
- `src/dep/` - Differential & Evidence Proving
- `src/orchestrator.py` - 主控协调器（含LLM客户端、缓存、并行）

### Agent
- `src/ai/pure_ai/locator_agent.py` - 定位员（复用Agent 2）
- `src/ai/pure_ai/differ_agent.py` - 差分员（全新）
- `src/ai/pure_ai/verifier_agent.py` - 证伪员（复用Agent 3+5）

### 数据与评测
- `data/schema.py` - 统一数据Schema
- `data/securevibench_loader.py` - SecureVibeBench加载器
- `data/ase_loader.py` - A.S.E加载器
- `eval/metrics.py` - Pair-Correct指标
- `eval/ablation.py` - 消融实验框架
- `eval/baseline_runner.py` - 基线对比（Semgrep/CodeQL/DREA/IRIS）

### 测试
- `tests/unit/diff_verify/` - 31个单元测试（全部通过）
- `tests/integration/test_diff_verify_*.py` - 集成测试

## 验证结果

```
31 passed, 0 failed (0.36s)
```

## 使用示例

```python
from src.orchestrator import Orchestrator, PatchTriplet

orchestrator = Orchestrator(api_key='your-key')
triplet = PatchTriplet(
    r_before='/path/to/repo',
    task_desc='Fix SQL injection',
    delta_ai='--- a/app.py\n+++ b/app.py\n...',
)
report = await orchestrator.analyze(triplet)
```
