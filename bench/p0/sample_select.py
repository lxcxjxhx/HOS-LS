"""样本初选脚本（W1*，P0 方案 §6）。

从 SecureVibeBench 数据集（105 个 C/C++ 任务）拉取全量行，按 P0 方案 §3.2
规则产出候选清单 CSV，供人工逐案订装。也可在 TSV 预筛选文件上离线跑同一
套约束（HTTP 不可达 / 镜像调试用）。

设计边界（方案写死的"防重复实现"条款）：
- 不重写评估/报告框架，不重复 dataset manifest 流水线：本脚本只出
  轻量 CSV + 统计行，`eval_dataset.py` / `dataset_release.py` 不动；
- 零新增依赖：只用标准库（urllib），不引入 huggingface_hub / datasets。

数据字段（已实测 datasets-server /first-rows 核实）：
    localid      ARVO 任务 id
    repo_url     仓库地址
    vic          漏洞引入 commit（ground truth 天然存在）
    repo_cwd     容器内工作目录
    description  任务描述（安全中性）

用法：
    # 在线：datasets-server 分页拉取全量 105 行 → 初选
    python -m bench.p0.sample_select fetch --out bench/p0/dataset_cache/rows.jsonl

    # 离线：从 TSV 预筛选文件跑同一套约束（--from-file）
    python -m bench.p0.sample_select fetch --from-file prefilter.tsv --out .../rows.jsonl

    # 约束过滤 + 排除清单 + 场景草配 + 汇总
    python -m bench.p0.sample_select check --rows .../rows.jsonl --out bench/p0/candidates.csv

    # 场景草配（纯启发式打分，仅供人工订装参考，非最终标签）
    python -m bench.p0.sample_select check --rows .../rows.jsonl --out ... --scenario

约束规则（方案 §3.2 写死）：场景配额优先；同 CWE 最多 3 个；单仓库最多 2 个；
排除清单原因必填。CWE 从 ARVO id 映射（本机映射表不全则记 UNKNOWN_CWE）。
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OUT_DIR = REPO_ROOT / "bench" / "p0" / "dataset_cache"

DATASET_ID = "iCSawyer/SecureVibeBench"
DEFAULT_ENDPOINT = "https://datasets-server.huggingface.co"
HF_MIRROR = "https://hf-mirror.com"

# 方案 §3.2 选取规则常量
MAX_PER_CWE = 3
MAX_PER_REPO = 2
EXPECTED_TOTAL = 105
REQUIRED_FIELDS = ("localid", "repo_url", "vic", "repo_cwd", "description")

SCENARIO_NAMES = {
    1: "权限/边界作用域错误",
    2: "遗漏 sibling path",
    3: "不完整修改",
}

# ARVO localid → CWE 映射。ARVO 只保证 PoV 可动态触发，不标注 CWE；
# 本表只收录已人工核实条目，其余记 UNKNOWN_CWE 并在 P0 报告声明子集口径。
LOCALID_TO_CWE = {
    "992": "CWE-787",
}

CSV_FIELDS = [
    "case_id", "localid", "repo_url", "vic", "repo_cwd", "description",
    "cwe", "scenario_draft", "scenario_scores", "repo_count", "cwe_count",
    "status", "exclude_reason",
]

# 场景草配关键词（方案 §3.2 场景映射表；纯启发式，仅供人工订装参考）
SCENARIO_KEYWORDS = {
    1: (
        r"bound", r"check", r"limit", r"size", r"len(gth)?", r"overflow",
        r"underflow", r"range", r"oob", r"access", r"scope", r"permission",
    ),
    2: (
        r"similar", r"sibling", r"other (call|use|place)s?", r"call sites?",
        r"memcpy", r"strcpy", r"sprintf", r"alloc", r"free",
    ),
    3: (
        r"error", r"cleanup", r"handle", r"path", r"branch", r"unwind",
        r"free", r"release", r"rollback", r"goto", r"teardown",
    ),
}


def _http_get_json(url: str, timeout: float) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "hosls-p0-sample-select/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


_TSV_ESCAPES = {"\\": "\\", "t": "\t", "n": "\n"}


def _tsv_unescape(cell: str) -> str:
    """TSV 单元格反转义：\\n→换行、\\t→制表、\\\\→反斜杠。"""
    if "\\" not in cell:
        return cell
    out: list[str] = []
    i = 0
    while i < len(cell):
        ch = cell[i]
        if ch == "\\" and i + 1 < len(cell):
            nxt = cell[i + 1]
            out.append(_TSV_ESCAPES.get(nxt, "\\" + nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _tsv_escape(cell: str) -> str:
    """TSV 单元格转义（与 _tsv_unescape 严格互逆）。"""
    return cell.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def fetch_dataset_rows(
    endpoint: str,
    timeout: float,
    from_file: str | None,
    offset: int,
    length: int,
) -> list[dict]:
    """拉取数据集全量行；HTTP 失败时打印镜像与离线备选后退出。"""
    if from_file:
        text = Path(from_file).read_text(encoding="utf-8")
        lines = [
            line for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if lines and lines[0].lstrip().startswith("{"):
            rows = [json.loads(line) for line in lines]
        else:
            # TSV：首行为列头（列名 = REQUIRED_FIELDS），供人工预筛导出。
            # 单元格转义规则：\n→换行、\t→制表、\\→反斜杠；多行 description
            # 必须转义后放入单元格，转义后的单元格内不会出现裸 \t / 裸 \n。
            header = [_tsv_unescape(c) for c in lines[0].split("\t")]
            raw_rows = [line.split("\t") for line in lines[1:]]
            bad_len = [i + 2 for i, cells in enumerate(raw_rows) if len(cells) != len(header)]
            if bad_len:
                print(
                    f"[FAIL] TSV 第 {bad_len} 行列数与表头 {len(header)} 列不符；"
                    "多行文本请按 \\n 转义后放入单元格",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            rows = [
                {h: _tsv_unescape(c) for h, c in zip(header, cells)}
                for cells in raw_rows
            ]
        print(f"from-file 模式：读取 {len(rows)} 行（{from_file}）")
        return rows

    rows: list[dict] = []
    while True:
        url = (
            f"{endpoint}/rows?dataset={DATASET_ID}&config=default&split=train"
            f"&offset={offset}&length={length}"
        )
        try:
            payload = _http_get_json(url, timeout)
        except Exception as exc:
            print(
                f"[FAIL] 拉取失败：{exc}\n"
                f"  备选 1（镜像）：--endpoint {HF_MIRROR}\n"
                f"  备选 2（离线）：人工预筛 TSV（列：{'/'.join(REQUIRED_FIELDS)}），"
                f"然后 --from-file 重跑同一套约束",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        fetched = payload.get("rows", [])
        if not fetched:
            break
        for item in fetched:
            rows.append(item["row"])
        offset += len(fetched)
        if offset >= int(payload.get("num_rows_total", offset)) or len(fetched) < length:
            break
    if len(rows) != EXPECTED_TOTAL:
        print(
            f"[WARN] 取回 {len(rows)} 行，数据集口径应为 {EXPECTED_TOTAL} 行；"
            "继续处理，但请核对上游",
            file=sys.stderr,
        )
    return rows


def score_scenarios(description: str) -> dict[int, int]:
    """对 description 做三场景启发式打分（方案 §3.2 映射关键词）。"""
    text = description.lower()
    scores: dict[int, int] = {}
    for scenario_id, patterns in SCENARIO_KEYWORDS.items():
        hits = sum(1 for pattern in patterns if re.search(pattern, text))
        scores[scenario_id] = hits
    return scores


def build_candidate_rows(rows: list[dict], with_scenario: bool) -> list[dict]:
    """逐行校验 + 衍生统计字段 + 排除判定（约束硬性执行）。"""
    repo_counter = Counter(row["repo_url"] for row in rows)
    cwe_counter = Counter(
        LOCALID_TO_CWE.get(str(row["localid"]), "UNKNOWN_CWE") for row in rows
    )
    candidates: list[dict] = []
    for row in rows:
        localid = str(row["localid"])
        missing = [field for field in REQUIRED_FIELDS if not row.get(field)]
        cwe = LOCALID_TO_CWE.get(localid, "UNKNOWN_CWE")
        repo_count = repo_counter[row["repo_url"]]
        cwe_count = cwe_counter[cwe]

        # 方案 §3.2：同 CWE 最多 3 个 / 单仓库最多 2 个是人工选样配额；
        # 初选阶段只标注配额压力（QUOTA_RISK），不替人工决定落选。
        # EXCLUDED 仅用于缺字段等硬性不可用（原因必填）。
        exclude_reason = ""
        if missing:
            exclude_reason = "missing_fields:" + ",".join(missing)
        quota_risk = (
            repo_count > MAX_PER_REPO
            or (cwe != "UNKNOWN_CWE" and cwe_count > MAX_PER_CWE)
        )

        scores = score_scenarios(row["description"]) if with_scenario else {}
        scenario_draft = ""
        scenario_scores = ""
        if with_scenario and scores:
            best = max(scores, key=lambda sid: (scores[sid], -sid))
            scenario_scores = json.dumps(scores, ensure_ascii=False, separators=(",", ":"))
            scenario_draft = str(best) if scores[best] > 0 else "UNCLEAR"

        candidates.append({
            "case_id": f"svb-{localid}",
            "localid": localid,
            "repo_url": row["repo_url"],
            "vic": row["vic"],
            "repo_cwd": row["repo_cwd"],
            "description": row["description"],
            "cwe": cwe,
            "scenario_draft": scenario_draft,
            "scenario_scores": scenario_scores,
            "repo_count": str(repo_count),
            "cwe_count": str(cwe_count),
            "status": ("EXCLUDED" if exclude_reason
                       else ("QUOTA_RISK" if quota_risk else "CANDIDATE")),
            "exclude_reason": exclude_reason,
        })
    return candidates


def write_candidates_csv(candidates: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(candidates)


def run_check(args: argparse.Namespace) -> int:
    rows_path = Path(args.rows)
    if not rows_path.exists():
        print(f"[FAIL] rows 文件不存在：{rows_path}", file=sys.stderr)
        return 1
    rows = [
        json.loads(line)
        for line in rows_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    invalid = [
        row for row in rows
        if any(field not in row for field in REQUIRED_FIELDS)
    ]
    if invalid:
        print(f"[FAIL] {len(invalid)} 行缺少必需字段 {REQUIRED_FIELDS}", file=sys.stderr)
        return 1

    candidates = build_candidate_rows(rows, with_scenario=args.scenario)
    write_candidates_csv(candidates, Path(args.out))

    kept = [c for c in candidates if c["status"] == "CANDIDATE"]
    quota_risked = [c for c in candidates if c["status"] == "QUOTA_RISK"]
    excluded = [c for c in candidates if c["status"] == "EXCLUDED"]
    print(f"输入 {len(rows)} 行 → 候选 {len(kept)}，配额压力 {len(quota_risked)}，"
          f"硬排除 {len(excluded)} → {args.out}")
    print(f"仓库数：{len({c['repo_url'] for c in candidates})}；"
          f"CWE 未知（需人工映射）：{sum(1 for c in candidates if c['cwe'] == 'UNKNOWN_CWE')}")

    exclude_counter = Counter(c["exclude_reason"].split(":")[0] for c in excluded)
    for reason, count in sorted(exclude_counter.items()):
        print(f"  排除[{reason}]：{count}")
    if args.scenario:
        draft_counter = Counter(c["scenario_draft"] for c in candidates)
        for scenario_id, name in SCENARIO_NAMES.items():
            print(f"  场景{scenario_id}（{name}）草配：{draft_counter.get(str(scenario_id), 0)}")
        print(f"  UNCLEAR：{draft_counter.get('UNCLEAR', 0)}"
              "（启发式仅供参考，场景标签以人工订装为准）")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bench.p0.sample_select",
        description="SecureVibeBench 样本初选（P0 方案 §6 W1*）",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_fetch = sub.add_parser("fetch", help="拉取数据集全量行到 JSONL")
    p_fetch.add_argument("--out", default=str(DEFAULT_OUT_DIR / "rows.jsonl"))
    p_fetch.add_argument("--from-file", dest="from_file",
                         help="离线 TSV/JSONL 预筛文件，跳过 HTTP")
    p_fetch.add_argument("--endpoint", default=DEFAULT_ENDPOINT,
                         help=f"datasets-server 端点，镜像可用 {HF_MIRROR}")
    p_check = sub.add_parser("check", help="约束过滤 + 排除清单 + 汇总")
    p_check.add_argument("--rows", required=True, help="fetch 产出的 JSONL")
    p_check.add_argument("--out", default=str(REPO_ROOT / "bench" / "p0" / "candidates.csv"))
    p_check.add_argument("--scenario", action="store_true",
                         help="附加三场景启发式草配")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "fetch":
        rows = fetch_dataset_rows(args.endpoint, timeout=30.0,
                                  from_file=args.from_file, offset=0, length=100)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"共 {len(rows)} 行 → {out}")
        return 0
    if args.command == "check":
        return run_check(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
