# HOS-LS 独立环境布局（envs/）

> 目标：SAST 工具链与运行时依赖全部收敛到项目内独立文件夹，可维护、可重建、不污染系统环境。

## 目录

```
envs/
├── README.md            # 本文件
├── install.ps1          # 一键搭建（幂等）
├── venv/                # HOS-LS 主运行环境（python -m venv + pip install -r requirements.txt）
│                        #   ⚠ 重型依赖（torch/unsloth/chromadb…）；如已有可用部署环境可跳过
├── sast-venv/           # SAST 工具链环境（requirements-sast.txt：semgrep/bandit）
├── codeql/              # CodeQL CLI 独立二进制（2.26.3，非 pip）
├── codeql-packs/        # 查询包缓存（codeql/python-queries@1.8.8）
├── semgrep-rules/       # 社区规则集（semgrep-rules develop：2156 yaml，python 337 条）
└── scripts/
    ├── install-codeql.ps1   # codeql 安装/升级（下载→解压→本目录）
    └── pull-semgrep-rules.ps1  # 规则集更新（走代理 7897）
```

## 依赖入口（requirements.txt 已注明）

| 依赖 | 位置 | 安装方式 |
|------|------|---------|
| semgrep | `sast-venv` | `pip install -r requirements-sast.txt` |
| bandit | `sast-venv` | 同上（纯 Python 兜底层） |
| codeql | `envs/codeql/` | `scripts/install-codeql.ps1` |
| 查询包 | `envs/codeql-packs/` | `codeql pack download -d envs\codeql-packs codeql/python-queries` |
| 规则集 | `envs/semgrep-rules/` | `scripts/pull-semgrep-rules.ps1`（GitHub develop 分支 zip） |

## 环境事实（2026-08 实测）

1. **Windows 证书库与沙箱**：semgrep（OCaml X509）与 curl（schannel）在受限环境会因无法打开系统证书库而崩溃
   （`CertOpenSystemStore NULL` / `SEC_E_NO_CREDENTIALS`）；Python/certifi 自带证书库不受影响。
   → semgrep 需**完整权限**运行；bandit/codeql 无此问题。
2. **CodeQL Python 提取器**用 multiprocessing 命名管道 → 受限沙箱建库需完整权限。
3. **网络**：GitHub/PyPI 直连被墙，走本地代理 `http://127.0.0.1:7897`（HTTP(S)_PROXY 环境变量）。
4. **CodeQL 对松散函数切片**亦可建库（Python 提取器无需编译），盲区样本若被 CodeQL 命中则升级为硬检出。

## 重建流程（另一台机器）

```powershell
# 1) 主环境（可选，已有部署环境可跳过）
python -m venv envs/venv
envs/venv/Scripts/pip install -r requirements.txt

# 2) SAST 工具链
python -m venv envs/sast-venv
envs/sast-venv/Scripts/pip install -r requirements-sast.txt

# 3) CodeQL + 规则（需要网络代理）
powershell -ExecutionPolicy Bypass -File envs/scripts/install-codeql.ps1
envs/codeql/codeql.exe pack download -d envs\codeql-packs codeql/python-queries

# 4) 验证
envs/sast-venv/Scripts/semgrep.exe --version
envs/codeql/codeql.exe version
```
