# HOS-LS 重构指南

本指南记录了 HOS-LS 项目的完整重构流程，包括代码格式化、导入排序、静态检查、类型检查和测试验证。

## 目录

- [重构流程概述](#重构流程概述)
- [阶段1: 代码格式化](#阶段1-代码格式化)
- [阶段2: 导入排序](#阶段2-导入排序)
- [阶段3: 静态检查](#阶段3-静态检查)
- [阶段4: 类型检查和测试](#阶段4-类型检查和测试)
- [阶段5: 文档和GitHub推送](#阶段5-文档和github推送)
- [工具使用指南](#工具使用指南)
- [Pre-commit 钩子使用](#pre-commit-钩子使用)
- [常见问题和解决方案](#常见问题和解决方案)
- [回退机制](#回退机制)

## 重构流程概述

重构分为5个阶段：

1. **阶段1**: 使用 Black 进行代码格式化
2. **阶段2**: 使用 isort 进行导入排序
3. **阶段3**: 使用 flake8 进行静态检查
4. **阶段4**: 使用 mypy 进行类型检查，使用 pytest 运行测试
5. **阶段5**: 创建文档并推送到 GitHub

## 阶段1: 代码格式化

### 使用 Black 格式化代码

Black 是一个零配置的 Python 代码格式化工具，遵循 PEP 8 标准。

```bash
# 格式化整个项目
black .

# 格式化特定目录
black src/
black tests/

# 格式化特定文件
black src/main.py

# 检查哪些文件需要格式化（不修改）
black --check .

# 显示格式化差异
black --diff .
```

### Black 配置

在 `pyproject.toml` 中配置：

```toml
[tool.black]
line-length = 100
target-version = ['py38', 'py39', 'py310', 'py311']
include = '\.pyi?$'
```

## 阶段2: 导入排序

### 使用 isort 排序导入

isort 自动对 Python 导入语句进行排序，遵循 PEP 8 规范。

```bash
# 排序整个项目的导入
isort .

# 排序特定目录
isort src/
isort tests/

# 排序特定文件
isort src/main.py

# 检查哪些文件需要排序（不修改）
isort --check-only .

# 显示排序差异
isort --diff .
```

### isort 配置

在 `pyproject.toml` 中配置：

```toml
[tool.isort]
profile = "black"
line_length = 100
multi_line_output = 3
include_trailing_comma = true
force_grid_wrap = 0
use_parentheses = true
ensure_newline_before_comments = true
```

## 阶段3: 静态检查

### 使用 flake8 进行静态检查

flake8 检查代码风格、语法错误和代码质量问题。

```bash
# 检查整个项目
flake8 .

# 检查特定目录
flake8 src/
flake8 tests/

# 检查特定文件
flake8 src/main.py

# 显示统计信息
flake8 --statistics .

# 输出到文件
flake8 . > flake8_report.txt
```

### flake8 配置

在 `.flake8` 文件中配置：

```ini
[flake8]
max-line-length = 100
extend-ignore = E203, W503
exclude =
    .git,
    __pycache__,
    build,
    dist,
    *.egg-info,
    .venv,
    venv
```

### 常见 flake8 错误

- **E501**: 行太长（超过最大长度）
- **E203**: 切片操作符前的空格（与 Black 冲突，已忽略）
- **W503**: 二元运算符前的换行（与 Black 冲突，已忽略）
- **F401**: 导入了但未使用的模块
- **F841**: 赋值了但未使用的变量
- **E302**: 期望2个空行
- **E303**: 太多空行

## 阶段4: 类型检查和测试

### 使用 mypy 进行类型检查

mypy 是 Python 的静态类型检查工具。

```bash
# 检查整个项目
mypy .

# 检查特定目录
mypy src/
mypy tests/

# 检查特定文件
mypy src/main.py

# 显示错误消息
mypy --show-error-codes .

# 生成 HTML 报告
mypy --html-report mypy_report .
```

### mypy 配置

在 `pyproject.toml` 中配置：

```toml
[tool.mypy]
python_version = "3.8"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = false
disallow_incomplete_defs = false
check_untyped_defs = true
ignore_missing_imports = true
```

### 使用 pytest 运行测试

pytest 是 Python 的测试框架。

```bash
# 运行所有测试
pytest

# 运行特定目录的测试
pytest tests/unit/
pytest tests/integration/

# 运行特定测试文件
pytest tests/test_main.py

# 运行特定测试函数
pytest tests/test_main.py::test_function_name

# 显示详细输出
pytest -v

# 显示打印输出
pytest -s

# 遇到第一个失败就停止
pytest -x

# 运行失败测试
pytest --lf

# 生成覆盖率报告
pytest --cov=src --cov-report=html
```

### pytest 配置

在 `pyproject.toml` 中配置：

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = "-v --tb=short"
```

## 阶段5: 文档和GitHub推送

### 创建文档

创建 `REFACTORING_GUIDE.md` 文件，记录重构流程和工具使用指南。

### 推送到 GitHub

```bash
# 配置远程仓库
git remote add origin https://github.com/lxcxjxhx/HOS-LS

# 推送代码到 master 分支
git push -u origin master

# 推送代码到 main 分支
git push -u origin main
```

### 验证推送

```bash
# 查看远程仓库
git remote -v

# 查看分支状态
git branch -a

# 查看提交历史
git log --oneline
```

## 工具使用指南

### 安装工具

```bash
# 安装所有工具
pip install black isort flake8 mypy pytest pytest-cov

# 或者使用 pip 安装
pip install -r requirements-dev.txt
```

### 工具执行顺序

推荐的执行顺序：

1. **Black**: 先格式化代码
2. **isort**: 然后排序导入
3. **flake8**: 检查代码风格
4. **mypy**: 类型检查
5. **pytest**: 运行测试

### 一键执行脚本

创建 `refactor.sh` 脚本：

```bash
#!/bin/bash

echo "=== 阶段1: 代码格式化 ==="
black .

echo "=== 阶段2: 导入排序 ==="
isort .

echo "=== 阶段3: 静态检查 ==="
flake8 .

echo "=== 阶段4: 类型检查 ==="
mypy .

echo "=== 阶段5: 运行测试 ==="
pytest

echo "=== 重构完成 ==="
```

### Windows 批处理脚本

创建 `refactor.bat` 脚本：

```batch
@echo off

echo === 阶段1: 代码格式化 ===
black .

echo === 阶段2: 导入排序 ===
isort .

echo === 阶段3: 静态检查 ===
flake8 .

echo === 阶段4: 类型检查 ===
mypy .

echo === 阶段5: 运行测试 ===
pytest

echo === 重构完成 ===
```

## Pre-commit 钩子使用

### 安装 pre-commit

```bash
pip install pre-commit
```

### 配置 pre-commit

创建 `.pre-commit-config.yaml` 文件：

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black
        language_version: python3

  - repo: https://github.com/pycqa/isort
    rev: 5.13.2
    hooks:
      - id: isort
        language_version: python3

  - repo: https://github.com/pycqa/flake8
    rev: 7.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=100]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.8.0
    hooks:
      - id: mypy
        language_version: python3
        additional_dependencies: [types-requests]
```

### 安装钩子

```bash
# 安装 pre-commit 钩子
pre-commit install

# 安装 pre-push 钩子
pre-commit install --hook-type pre-push
```

### 使用 pre-commit

```bash
# 手动运行所有钩子
pre-commit run --all-files

# 运行特定钩子
pre-commit run black --all-files
pre-commit run isort --all-files
pre-commit run flake8 --all-files

# 更新钩子到最新版本
pre-commit autoupdate
```

### 跳过钩子

```bash
# 跳过 pre-commit 钩子
git commit -m "message" --no-verify

# 跳过特定文件的钩子
SKIP=black git commit -m "message"
```

## 常见问题和解决方案

### 问题1: Black 和 isort 冲突

**解决方案**: 使用兼容的配置

```toml
[tool.isort]
profile = "black"
```

### 问题2: flake8 报告 E203 错误

**解决方案**: 在 `.flake8` 中忽略 E203

```ini
[flake8]
extend-ignore = E203
```

### 问题3: flake8 报告 W503 错误

**解决方案**: 在 `.flake8` 中忽略 W503

```ini
[flake8]
extend-ignore = W503
```

### 问题4: mypy 报告缺少类型提示

**解决方案**: 逐步添加类型提示，或禁用严格检查

```toml
[tool.mypy]
disallow_untyped_defs = false
check_untyped_defs = true
```

### 问题5: mypy 报告第三方库缺少类型

**解决方案**: 安装类型存根或忽略导入

```bash
# 安装类型存根
pip install types-requests
pip install types-PyYAML
```

或在 `pyproject.toml` 中：

```toml
[tool.mypy]
ignore_missing_imports = true
```

### 问题6: pytest 找不到测试

**解决方案**: 确保测试文件命名正确

- 测试文件必须以 `test_` 开头或 `_test` 结尾
- 测试函数必须以 `test_` 开头
- 测试类必须以 `Test` 开头

### 问题7: pre-commit 钩子失败

**解决方案**: 手动运行钩子并修复问题

```bash
pre-commit run --all-files
```

### 问题8: 大量文件需要格式化

**解决方案**: 分批处理

```bash
# 格式化特定目录
black src/
black tests/

# 或使用缓存
black --fast .
```

## 回退机制

### 使用 git reset 回退

```bash
# 回退到上一个提交（保留更改）
git reset --soft HEAD~1

# 回退到上一个提交（丢弃更改）
git reset --hard HEAD~1

# 回退到特定提交
git reset --hard <commit-hash>
```

### 使用 git revert 回退

```bash
# 撤销特定提交
git revert <commit-hash>

# 撤销最近的提交
git revert HEAD

# 撤销多个提交
git revert HEAD~3..HEAD
```

### 使用 git checkout 恢复文件

```bash
# 恢复单个文件
git checkout -- <file>

# 恢复所有文件
git checkout -- .
```

### 使用 git stash 暂存更改

```bash
# 暂存当前更改
git stash

# 恢复暂存的更改
git stash pop

# 查看暂存列表
git stash list
```

### 回退最佳实践

1. **在重构前创建分支**: `git checkout -b refactor`
2. **定期提交**: 每个阶段完成后提交一次
3. **使用标签**: `git tag -a v1.0 -m "重构前版本"`
4. **推送到远程**: 定期推送到远程仓库备份

## 总结

本重构指南提供了完整的代码重构流程，包括：

- 代码格式化（Black）
- 导入排序（isort）
- 静态检查（flake8）
- 类型检查（mypy）
- 测试验证（pytest）
- Pre-commit 钩子自动化
- 常见问题解决方案
- 回退机制

通过遵循本指南，可以确保代码质量、一致性和可维护性。
