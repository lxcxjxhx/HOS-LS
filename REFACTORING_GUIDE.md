# 重构工具使用指南

本指南介绍如何使用集成到 HOS-LS 项目的重构工具。

## 已集成工具

### 1. refactoring-agent (Python)

**版本**: 3.12.7
**用途**: AI 辅助的代码重构和安全修复
**文档**: https://pypi.org/project/refactoring-agent/

#### 安装

已安装在项目环境中，无需额外安装。

#### 使用方式

refactoring-agent 主要通过 Python API 调用：

```python
from refactoring_agent import RefactoringAgent

agent = RefactoringAgent(
    project_path="./",
    config_path=".refactoring-agent.yml"
)

# 分析代码质量问题
analysis = agent.analyze_code_quality()

# 生成重构建议
suggestions = agent.generate_refactoring_suggestions()

# 应用重构
agent.apply_refactoring(suggestions)
```

#### 配置文件

配置文件 `.refactoring-agent.yml` 已创建在项目根目录，包含：
- 扫描路径：`src/`, `tests/`
- 忽略路径：虚拟环境、缓存目录等
- 重构规则：代码质量、风格、性能优化
- AI 辅助配置
- Git 集成配置

### 2. OpenRewrite

**版本**: 8.85.5 (recipes)
**用途**: 自动化批量代码重构
**文档**: https://github.com/openrewrite/rewrite

#### 安装

OpenRewrite CLI 需要 Java 环境（已安装 JDK 25）。

**下载 CLI**（待网络问题解决）:
```bash
# 下载 JAR
curl -L https://github.com/openrewrite/rewrite/releases/download/v8.85.5/rewrite-cli-8.85.5.jar -o rewrite-cli.jar

# 运行
java -jar rewrite-cli.jar --help
```

#### 使用方式

```bash
# 列出可用 recipes
java -jar rewrite-cli.jar list recipes

# 运行特定 recipe
java -jar rewrite-cli.jar run -r com.hosls.cleanup.UnusedImports

# 运行所有清理 recipes
java -jar rewrite-cli.jar run -r com.hosls.cleanup.*
```

#### 配置文件

配置文件 `rewrite.yml` 已创建，定义了以下 recipes：

1. **com.hosls.cleanup.UnusedImports** - 移除未使用的导入
2. **com.hosls.cleanup.CodeFormat** - 代码格式化
3. **com.hosls.quality.UnifyExceptionHandling** - 统一异常处理
4. **com.hosls.quality.RemoveUnusedVariables** - 移除未使用变量

## 重构流程

### 阶段 1: 代码质量治理

**目标**: 修复 flake8 和 mypy 报告的问题

1. 使用 refactoring-agent 分析代码质量
2. 按优先级修复问题：
   - 批次 1: 简单问题（未使用导入、变量、格式）
   - 批次 2: 中等问题（默认参数、异常处理）
   - 批次 3: 复杂问题（代码复杂度、函数长度）
3. 使用 OpenRewrite 批量处理重复模式
4. 验证测试通过
5. 提交到 GitHub，创建 tag `phase1-quality`

### 阶段 2: 模块化重构

**目标**: 消除重复代码，改善模块边界

1. 分析模块依赖关系
2. 合并重复模块（如 `src/core/config.py` 和 `src/config/config.py`）
3. 提取公共工具函数到 `src/utils/`
4. 消除循环依赖
5. 验证功能无回归
6. 提交到 GitHub，创建 tag `phase2-modular`

### 阶段 3: 架构演进

**目标**: 引入 Agent 能力，保持向后兼容

1. 设计 Agent 核心组件（Planner、Memory、Tool Router）
2. 实现 Agent Loop
3. 保持现有 CLI 接口
4. 新增 `hos agent <workflow>` 命令
5. 实现基础工作流（Web 扫描）
6. 提交到 GitHub，创建 tag `phase3-agent`

### 阶段 4: 性能优化

**目标**: 优化关键路径，建立性能基线

1. 测量扫描时间、LLM 调用、内存使用
2. 识别性能瓶颈
3. 实现缓存、并行化、批处理
4. 验证性能改进
5. 提交到 GitHub，创建 tag `phase4-performance`

## 回退策略

每个阶段完成后都会创建 Git tag，可随时回退：

```bash
# 查看可用 tags
git tag

# 回退到特定阶段
git reset --hard phase1-quality
git reset --hard phase2-modular
git reset --hard phase3-agent
git reset --hard phase4-performance
```

## 常见问题

### Q: OpenRewrite CLI 无法下载？

A: 检查网络连接，或使用 Maven 构建：
```bash
git clone https://github.com/openrewrite/rewrite.git
cd rewrite
mvn install
```

### Q: refactoring-agent 没有 CLI 命令？

A: refactoring-agent 主要通过 Python API 使用，参见上方示例代码。

### Q: 重构后测试失败？

A: 检查重构是否改变了功能逻辑。必要时回退到上一个 tag，调整重构策略后重试。

### Q: 如何只重构特定模块？

A: 修改 `.refactoring-agent.yml` 的 `scan_paths`，或使用 OpenRewrite 的 `--path` 参数。

## 参考资源

- [OpenRewrite GitHub](https://github.com/openrewrite/rewrite)
- [refactoring-agent PyPI](https://pypi.org/project/refactoring-agent/)
- [Refact.ai](https://refact.ai/)
- [GitClaw](https://oss.lyzr.ai/gitclaw)
- [GitHub Agentic Workflows](https://github.github.com/gh-aw/blog/2026-01-13-meet-the-workflows-continuous-refactoring/)
