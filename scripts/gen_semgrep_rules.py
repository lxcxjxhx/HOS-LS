"""RULEDROID 式动态 semgrep 规则生成（C2）：LLM + 知识库 → 安全公告 → semgrep 规则。

用法（cwd = hos-ls）：
  python scripts/gen_semgrep_rules.py --limit 3 --out envs/semgrep-rules/auto

流程：
1. 从 NVD/CVE 知识库（rag_knowledge_base/knowledge.json + cve_cwe 表）取近期漏洞样本；
2. LLM（deepseek-v4-flash）根据 CVE 描述/修复 commit 生成 semgrep 规则（pattern 列表）；
3. 落盘 envs/semgrep-rules/auto/<rule-id>.yaml，输出冲突/数量报告；
4. 人工/小样本 A/B 校验后才合入主规则集（防误报爆炸）。
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent  # hos-ls 根


def load_kb_cves(limit: int = 5):
    kb_path = HERE / "rag_knowledge_base" / "knowledge.json"
    items = []
    if kb_path.exists():
        try:
            kb = json.load(open(kb_path, encoding="utf-8"))
            data = kb.get("knowledge") or kb.get("entries") or kb if isinstance(kb, (list, dict)) else []
            if isinstance(data, dict):
                data = list(data.values())
            for it in data[:limit]:
                if isinstance(it, dict):
                    items.append({
                        "cve": it.get("cve", it.get("cve_id", "")),
                        "cwe": it.get("cwe", it.get("cwe_id", "")),
                        "desc": str(it.get("description", it.get("summary", "")))[:400],
                        "sink": str(it.get("sink", it.get("pattern", "")))[:200],
                    })
        except Exception as e:
            print("kb 读取失败:", e)
    return items


def gen_rules(items):
    """调 LLM 生成 semgrep 规则（经 deepseek API，走 7897 代理环境）。"""
    import urllib.request

    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    base = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    if not api_key:
        # 从 hos-ls.yaml 读取
        import yaml
        cfg = yaml.safe_load(open(HERE / "hos-ls-opt.yaml", encoding="utf-8"))
        api_key = (cfg.get("ai") or {}).get("api_key", "")
    if not api_key:
        print("无 API key（DEEPSEEK_API_KEY 或 hos-ls.yaml）")
        return []
    prompt = (
        "你是静态分析规则工程师。根据以下漏洞信息生成 Semgrep 规则（YAML，python 语言）：\n"
        "每条规则：id、message、severity、patterns（用 pattern-eithers 列 2-4 个危险 pattern 或 pattern-regex）。\n"
        "只输出 YAML，不要解释。\n\n" + json.dumps(items, ensure_ascii=False, indent=1)
    )
    body = json.dumps({
        "model": "deepseek-v4-flash", "temperature": 0.2, "max_tokens": 3000,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(base + "/chat/completions", data=body,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {api_key}"})
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.load(resp)
        content = data["choices"][0]["message"]["content"]
        return [content]
    except Exception as e:
        print("LLM 调用失败:", str(e)[:200])
        return []


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    out_dir = HERE / "envs" / "semgrep-rules" / "auto"
    out_dir.mkdir(parents=True, exist_ok=True)
    items = load_kb_cves(limit)
    if not items:
        print("知识库无样本，改用内置样例")
        items = [{"cve": "CVE-2022-2822", "cwe": "CWE-352", "desc": "CSRF 保护被禁用",
                  "sink": "flask_wtf.CSRFProtect"},
                 {"cve": "CVE-2021-41250", "cwe": "CWE-20", "desc": "token 过滤提前退出",
                  "sink": "filter"}]
    rules = gen_rules(items)
    for i, content in enumerate(rules):
        # 从 YAML 提取 rule id 做文件名
        rid = "auto-rule-%02d" % i
        path = out_dir / f"{rid}.yaml"
        path.write_text(content, encoding="utf-8")
        print("生成:", path, f"({len(content)} chars)")
    print(f"共 {len(rules)} 条 → {out_dir}；校验：semgrep scan --config {out_dir} <样本>")
    print("注意：生成规则需小样本 A/B + 冲突校验后才可合入主规则集（防误报爆炸）")


if __name__ == "__main__":
    main()
