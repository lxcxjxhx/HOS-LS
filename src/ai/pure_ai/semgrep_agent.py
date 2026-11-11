"""SemgrepAgent — 硬性前置筛选 Agent

职责：
1. Phase 1: 用 Semgrep 官方规则（p/default + p/security-audit）扫描代码
2. 能直接命中的 → 直接作为硬检出结果输出（0 LLM token）
3. 未命中的代码段 → 传给下游 Agent 做深度分析

定位：作为管线中第一个执行的 Agent，位于 SCAN 阶段末尾或 SCAN→CONTEXT 之间。
与 SastPrefilter 的关系：SastPrefilter 负责多工具编排（CodeQL/Semgrep/Bandit），
SemgrepAgent 专注于 Semgrep 语义规则的单工具深度应用 + 规则自动更新。
"""

import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SemgrepMatch:
    """单个 Semgrep 匹配结果（标准化格式）"""
    file: str
    line: int
    column: int
    rule_id: str
    severity: str         # ERROR / WARNING / INFO
    message: str
    cwe: str              # 从 rule metadata 提取
    snippet: str          # 匹配到的代码片段
    backend: str = "semgrep"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "cwe": self.cwe,
            "snippet": self.snippet,
            "backend": self.backend,
        }

    def to_agent_vote_format(self) -> Dict[str, Any]:
        """转换为 AgentVote 兼容的格式，可直接进入 VotingPipeline"""
        return {
            "signal_id": f"SEMGREP-{self.rule_id}@{self.file}:{self.line}",
            "decision": "CONFIRMED",
            "confidence": 0.95,  # 规则命中 = 高置信度
            "severity": self.severity.upper(),
            "vuln_type": self._infer_vuln_type(),
            "location": f"{self.file}:{self.line}",
            "description": self.message,
            "title": f"[Semgrep] {self.rule_id}: {self.message[:80]}",
            "verification_reason": f"Semgrep 规则 {self.rule_id} 硬命中",
            "source": "rule_match",
            "rule_id": self.rule_id,
        }

    def _infer_vuln_type(self) -> str:
        """从 rule_id 或 CWE 推断漏洞类型"""
        cwe_upper = self.cwe.upper()
        rid_lower = self.rule_id.lower()
        if "sql" in rid_lower or "CWE-89" in cwe_upper:
            return "SQL_INJECTION"
        if "xss" in rid_lower or "CWE-79" in cwe_upper:
            return "XSS"
        if "command" in rid_lower or "rce" in rid_lower or "CWE-78" in cwe_upper or "CWE-77" in cwe_upper:
            return "COMMAND_INJECTION"
        if "path" in rid_lower or "traversal" in rid_lower or "CWE-22" in cwe_upper or "CWE-23" in cwe_upper:
            return "PATH_TRAVERSAL"
        if "auth" in rid_lower or "bypass" in rid_lower or "CWE-862" in cwe_upper or "CWE-863" in cwe_upper:
            return "AUTH_BYPASS"
        if "secret" in rid_lower or "hardcoded" in rid_lower or "CWE-798" in cwe_upper or "CWE-259" in cwe_upper:
            return "HARDCODED_SECRET"
        if "deserial" in rid_lower or "CWE-502" in cwe_upper:
            return "DESERIALIZATION"
        if "ssrf" in rid_lower or "CWE-918" in cwe_upper:
            return "SSRF"
        if "xxe" in rid_lower or "CWE-611" in cwe_upper:
            return "XXE"
        if "crypto" in rid_lower or "weak" in rid_lower or "CWE-327" in cwe_upper or "CWE-326" in cwe_upper:
            return "WEAK_CRYPTO"
        if "config" in rid_lower or "misconfig" in rid_lower:
            return "CONFIG_SENSITIVE"
        return "SECURITY_VULN"


class SemgrepRuleManager:
    """Semgrep 规则管理器 — 负责从官方 Registry 同步规则"""

    RULE_STORE = os.path.expanduser("~/.hos-ls/semgrep-rules")
    REGISTRY_CONFIGS = [
        "p/default",
        "p/security-audit",
        "p/command-injection",
        "p/sql-injection",
        "p/xss",
        "p/secrets",
    ]

    def __init__(self):
        self.rule_store = Path(self.RULE_STORE)
        self.rule_store.mkdir(parents=True, exist_ok=True)

    def build_registry_args(self) -> List[str]:
        """构建 semgrep --config 参数列表，优先本地缓存"""
        args = []
        # 检查本地是否已有规则缓存
        for config_name in self.REGISTRY_CONFIGS:
            local_path = self.rule_store / config_name.replace("/", "_")
            if local_path.exists() and local_path.is_dir():
                args.extend(["--config", str(local_path)])
            else:
                # 回退到在线 registry
                args.extend(["--config", config_name])
        return args

    def sync_rules(self) -> int:
        """同步本地规则缓存（增量更新）"""
        shutil = __import__("shutil")
        count = 0
        for config_name in self.REGISTRY_CONFIGS:
            local_path = self.rule_store / config_name.replace("/", "_")
            # 用 semgrep --config 下载到本地
            cmd = ["semgrep", "--config", config_name, "--dump-ast", "-"]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120,
                    encoding="utf-8", errors="replace",
                )
                # semgrep dump 成功后，规则被缓存在 ~/.semgrep/
                # 我们可以从缓存复制到本地 rule_store
                semgrep_cache = Path.home() / ".semgrep" / config_name.replace("/", "_")
                if semgrep_cache.exists():
                    if local_path.exists():
                        shutil.rmtree(local_path)
                    shutil.copytree(semgrep_cache, local_path)
                    count += 1
                    logger.info(f"[SemgrepAgent] 规则缓存同步: {config_name}")
            except Exception as e:
                logger.debug(f"[SemgrepAgent] 规则 {config_name} 同步失败: {e}")
        return count

    def get_semgrep_path(self) -> Optional[str]:
        """定位 semgrep 可执行文件路径"""
        cand = shutil.which("semgrep")
        if cand:
            return cand
        # 检查项目 envs 布局
        here = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        probes = [
            os.path.join(here, "envs", "sast-venv", "Scripts", "semgrep.exe"),
            os.path.join(here, "envs", "sast-venv", "bin", "semgrep"),
        ]
        for p in probes:
            if os.path.exists(p):
                return p
        return None


class SemgrepAgent:
    """SemgrepAgent — 硬性前置筛选 Agent

    按用户要求：Semgrep 能直接命中的直接作为部分结果输出，
    未命中的代码段才传给下游 Agent 做深度分析。
    """

    def __init__(self, rule_manager: Optional[SemgrepRuleManager] = None):
        self.rule_manager = rule_manager or SemgrepRuleManager()
        self._semgrep_path: Optional[str] = None

    @property
    def available(self) -> bool:
        if self._semgrep_path is not None:
            return True
        sp = SemgrepRuleManager.get_semgrep_path()
        if sp is None:
            return False
        self._semgrep_path = sp
        return True

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """对单个文件运行 Semgrep 扫描

        Args:
            file_path: 文件路径

        Returns:
            {
                "matches": [SemgrepMatch, ...],
                "hard_hits": bool,   # 是否有硬命中
                "note": str
            }
        """
        if not self.available:
            return {"matches": [], "hard_hits": False, "note": "Semgrep CLI 未安装"}

        sp = self._semgrep_path
        try:
            cmd = [sp, "scan", "--json", "-q"]
            # 加载规则配置
            registry_args = self.rule_manager.build_registry_args()
            cmd.extend(registry_args)
            cmd.append(str(file_path))

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600,
                encoding="utf-8", errors="replace",
            )

            data = json.loads(result.stdout or "{}")
            results = data.get("results", [])

            if not results:
                return {"matches": [], "hard_hits": False, "note": "无 Semgrep 命中"}

            matches = []
            for res in results:
                cwe = ""
                extra = res.get("extra", {})
                metadata = extra.get("metadata", {})
                # 尝试多种字段提取 CWE
                for field in ("cwe", "CWE", "weakness"):
                    raw = metadata.get(field, "")
                    if raw:
                        if isinstance(raw, list):
                            for item in raw:
                                if "CWE" in str(item):
                                    cwe = str(item).replace("external/cwe/cwe-", "CWE-").upper()
                                    break
                        elif "CWE" in str(raw):
                            cwe = str(raw).replace("external/cwe/cwe-", "CWE-").upper()

                match = SemgrepMatch(
                    file=str(res.get("path", file_path)).replace("\\", "/"),
                    line=int((res.get("start") or {}).get("line", 0) or 0),
                    column=int((res.get("start") or {}).get("col", 0) or 0),
                    rule_id=str(res.get("check_id", "semgrep")),
                    severity=str(extra.get("severity", "WARNING")).upper(),
                    message=str(extra.get("message", ""))[:300],
                    cwe=cwe,
                    snippet=str(extra.get("lines", ""))[:200],
                )
                matches.append(match)

            return {
                "matches": matches,
                "hard_hits": True,
                "note": f"Semgrep 命中 {len(matches)} 条规则",
            }

        except json.JSONDecodeError as e:
            return {"matches": [], "hard_hits": False, "note": f"解析失败: {e}"}
        except subprocess.TimeoutExpired:
            return {"matches": [], "hard_hits": False, "note": "Semgrep 扫描超时(600s)"}
        except Exception as e:
            return {"matches": [], "hard_hits": False, "note": f"扫描异常: {e}"}

    def scan_batch(self, files: List[str]) -> Dict[str, Any]:
        """批量扫描多个文件

        Args:
            files: 文件路径列表

        Returns:
            {
                "by_file": {file_path: [SemgrepMatch, ...]},
                "hit_files": [file_path, ...],    # 有命中的文件
                "miss_files": [file_path, ...],   # 未命中的文件 → 传给下游
                "total_hits": int,
                "note": str
            }
        """
        if not files:
            return {
                "by_file": {}, "hit_files": [], "miss_files": [],
                "total_hits": 0, "note": "空文件列表",
            }

        by_file: Dict[str, List[SemgrepMatch]] = {}
        all_hit_files: List[str] = []
        total = 0

        for fp in files:
            if not os.path.exists(fp):
                continue
            result = self.scan_file(fp)
            if result["hard_hits"] and result["matches"]:
                matches = result["matches"]
                by_file[fp] = matches
                all_hit_files.append(fp)
                total += len(matches)

        miss_files = [f for f in files if f not in all_hit_files]

        return {
            "by_file": {k: [m.to_dict() for m in v] for k, v in by_file.items()},
            "hit_files": all_hit_files,
            "miss_files": miss_files,
            "total_hits": total,
            "note": f"Semgrep: {len(all_hit_files)} 文件命中, {len(miss_files)} 文件未命中",
        }

    def get_hard_findings(self, files: List[str]) -> List[Dict[str, Any]]:
        """获取所有硬性检出结果（转为 AgentVote 兼容格式）"""
        result = self.scan_batch(files)
        findings = []
        for file_path, matches in result["by_file"].items():
            for match_dict in matches:
                match = SemgrepMatch(**match_dict)
                findings.append(match.to_agent_vote_format())
        return findings

    def get_missed_files(self, files: List[str]) -> List[str]:
        """获取所有未命中的文件列表（用于传给下游 Agent）"""
        result = self.scan_batch(files)
        return result["miss_files"]
