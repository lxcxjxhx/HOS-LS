"""HOS-LS 扫描入口脚本

直接调用 HOS-LS 的 Scanner，绕过 click CLI 层。
用于 run_comparison.py 的子进程调用。

用法：
    python bench/run_hosls_scan.py <target> --ai-provider deepinfra
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ["HOS_LS_QUIET"] = "1"
os.environ["TERM"] = "xterm"
os.environ["FORCE_COLOR"] = "0"
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
# 指定配置文件路径（get_config() 会通过 auto_load 读这个，而非默认的 config/default.yaml）
os.environ["HOS_LS_CONFIG_PATH"] = "hos-ls.yaml"
# 不走代理直连 API
os.environ["HTTP_PROXY"] = ""
os.environ["HTTPS_PROXY"] = ""
os.environ["NO_PROXY"] = "*"


def main():
    ap = argparse.ArgumentParser(description="HOS-LS 单文件扫描入口")
    ap.add_argument("target", help="扫描目标文件")
    ap.add_argument("--ai-provider", default="deepseek", help="AI provider（默认 deepseek）")
    args = ap.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        print(json.dumps({"error": f"文件不存在: {target}"}))
        sys.exit(1)

    # 修改配置文件，让 HOS-LS 内部 get_config() 读到正确的值
    import yaml
    yaml_path = str(REPO_ROOT / "hos-ls.yaml")
    with open(yaml_path, 'r', encoding='utf-8') as f:
        yaml_cfg = yaml.safe_load(f)

    # 统一使用 openai 兼容模式走 DeepInfra（支持 deepseek 模型）
    yaml_cfg['ai']['provider'] = 'openai'
    yaml_cfg['ai']['model'] = 'deepseek-ai/DeepSeek-V4-Flash'
    yaml_cfg['ai']['base_url'] = 'https://api.deepinfra.com/v1'
    yaml_cfg['ai']['allow_fallback'] = False
    yaml_cfg['ai']['enabled'] = True

    # 模块级配置也改为 openai（走 DeepInfra）
    if 'modules' in yaml_cfg.get('ai', {}):
        pure_ai_mod = yaml_cfg['ai']['modules'].get('pure_ai', {})
        pure_ai_mod['provider'] = 'openai'
        pure_ai_mod['model'] = 'deepseek-ai/DeepSeek-V4-Flash'

    with open(yaml_path, 'w', encoding='utf-8') as f:
        yaml.dump(yaml_cfg, f, default_flow_style=False, allow_unicode=True)

    # 加载配置
    from src.core.config import ConfigManager
    cm = ConfigManager()
    cm._config_cache.clear()
    cm._config_mtime.clear()
    cfg = cm.load_from_file(yaml_path)

    # 设置 API key（使用 .env 中的 HOS_LS_DEEPSEEK_API_KEY）
    from src.ai.key_manager import get_api_key
    cfg.ai.api_key = get_api_key("deepinfra")
    cfg.ai.enabled = True
    cfg.pure_ai = True
    cfg.nvd.enabled = False

    # 验证 key
    if not cfg.ai.api_key:
        print(json.dumps({"error": "DeepInfra API key 未设置"}))
        sys.exit(1)

    print(f"[DEBUG] Using model: {cfg.ai.model} via openai-compat on {cfg.ai.base_url}, api_key: {cfg.ai.api_key[:8]}...")

    # 导入并初始化 scanner
    from src.core.scanner import SecurityScanner
    scanner = SecurityScanner(cfg)

    try:
        asyncio.run(main_scan(scanner, target, args))
    except Exception as e:
        error_msg = str(e)[:200]
        print(json.dumps({
            "target": target,
            "ai_provider": args.ai_provider,
            "error": error_msg,
            "results": [{"file": target, "findings": []}],
            "total_findings": 0,
        }, ensure_ascii=False, indent=2))


async def main_scan(scanner, target, args):
    """执行扫描并捕获 console 编码问题"""
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    result = await scanner.scan(target)
    findings_list = []
    if result and hasattr(result, 'findings'):
        for f in (result.findings or []):
            findings_list.append({
                "file": getattr(f, 'file_path', target),
                "line": getattr(f, 'line', 0),
                "severity": str(getattr(f, 'severity', 'unknown')),
                "description": getattr(f, 'description', str(f)[:200]),
                "status": str(getattr(f, 'status', 'CONFIRMED')),
            })
    output = {
        "target": target,
        "ai_provider": args.ai_provider,
        "results": [{
            "file": target,
            "findings": findings_list,
        }],
        "total_findings": len(findings_list),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
