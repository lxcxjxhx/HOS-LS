"""DiffAnalysisAgent — 差分分析 Agent

针对 R_before → Δ_AI → R_after 场景：
- 输入：AI 生成的 patch/diff + 变更前后的文件内容
- 输出：新增/删除/修改的风险路径列表
- 核心问题：AI 变更是否新引入了一条可达漏洞路径？

定位：SemgrepAgent 之后、SemanticAgent 之前执行。
SemgrepAgent 命中 → 硬检出；未命中 → DiffAnalysisAgent 分析 diff 上下文。
"""

import difflib
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class DiffHunk:
    """单个 diff 块"""
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    added_lines: List[Tuple[int, str]] = field(default_factory=list)   # (new_line_no, content)
    removed_lines: List[Tuple[int, str]] = field(default_factory=list) # (old_line_no, content)
    context_lines: List[str] = field(default_factory=list)


@dataclass
class ChangedFile:
    """变更文件"""
    file_path: str
    hunks: List[DiffHunk] = field(default_factory=list)
    old_content: str = ""
    new_content: str = ""


@dataclass
class RiskPath:
    """发现的风险路径"""
    file: str
    line: int
    change_type: str          # ADDED / REMOVED / MODIFIED
    sink_keyword: str         # 命中哪个 sink
    source_keyword: str       # 是否可达 source
    has_sanitizer: bool       # 是否有消毒函数
    description: str
    confidence: float


SINK_PATTERNS = {
    "sql_exec": r"(?i)(execute(Query|Update)?|exec(ute)?)\s*\(",
    "cmd_exec": r"(?i)(os\.(system|popen)|subprocess\.(call|run|Popen)|Runtime\.exec|ProcessBuilder)",
    "code_eval": r"(?i)(eval|exec)\s*\(",
    "xss_sink": r"(?i)(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML)",
    "path_traversal": r"(?i)(open|file_get_contents|readFile|writeFile)\s*\(",
    "deserialize": r"(?i)(pickle\.loads?|ObjectInputStream\.readObject|yaml\.load\s*\()",
    "ssrf": r"(?i)(requests?\.(get|post|put|delete)|urllib\.request|HttpURLConnection|URL\.openStream)",
    "auth_bypass": r"(?i)(authenticate|login|authorize|hasPermission|checkRole)",
}

SOURCE_PATTERNS = {
    "http_input": r"(?i)(getParameter|getQueryString|getHeader|@RequestParam|@PathVariable|@RequestBody|request\.(body|query|params|form|args))",
    "user_input": r"(?i)(input\(|raw_input\(|sys\.argv|process\.argv|process\.env|user_input)",
    "file_upload": r"(?i)(request\.files|request\.FILES|multipart|file_upload)",
}

SANITIZER_PATTERNS = {
    "escape": r"(?i)(escape|sanitize|htmlspecialchars|strip_tags)",
    "prepared": r"(?i)(PreparedStatement|bindParam|placeholder|param\s*=)",
    "validation": r"(?i)(validate|isValid|Pattern\.matches|check\s*\()",
}


class DiffParser:
    """Diff 解析器 — 将文本 diff 解析为结构化数据"""

    @staticmethod
    def parse(diff_text: str) -> List[ChangedFile]:
        """解析 diff 文本"""
        files: List[ChangedFile] = []
        current_file: Optional[ChangedFile] = None
        current_hunk: Optional[DiffHunk] = None

        for line in diff_text.split("\n"):
            # 文件头: --- a/xxx  +++ b/xxx
            if line.startswith("--- a/"):
                if current_file and current_file.hunks:
                    files.append(current_file)
                current_file = ChangedFile(file_path=line[6:])
                continue
            if line.startswith("+++ b/"):
                if current_file is None:
                    current_file = ChangedFile(file_path=line[6:])
                continue

            # Hunk 头: @@ -old,count +new,count @@
            hunk_match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if hunk_match:
                if current_file and current_hunk:
                    current_file.hunks.append(current_hunk)
                current_hunk = DiffHunk(
                    old_start=int(hunk_match.group(1)),
                    old_count=int(hunk_match.group(2) or 1),
                    new_start=int(hunk_match.group(3)),
                    new_count=int(hunk_match.group(4) or 1),
                )
                continue

            if current_hunk is None:
                continue

            # 内容行
            if line.startswith("+") and not line.startswith("+++"):
                current_hunk.added_lines.append(
                    (current_hunk.new_start + len(current_hunk.added_lines) + len(current_hunk.removed_lines), line[1:])
                )
            elif line.startswith("-") and not line.startswith("---"):
                current_hunk.removed_lines.append(
                    (current_hunk.old_start + len(current_hunk.removed_lines), line[1:])
                )
            else:
                current_hunk.context_lines.append(line)

        if current_file and current_hunk:
            current_file.hunks.append(current_hunk)
        if current_file and current_file.hunks:
            files.append(current_file)

        return files


class DiffAnalysisAgent:
    """差分分析 Agent — 分析 AI patch 是否引入新漏洞路径"""

    SECURITY_KEYWORDS = {
        "sink": SINK_PATTERNS,
        "source": SOURCE_PATTERNS,
        "sanitizer": SANITIZER_PATTERNS,
    }

    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    def analyze_diff(self, diff_text: str) -> List[RiskPath]:
        """分析 diff 中的风险路径

        Args:
            diff_text: Git diff 格式文本

        Returns:
            风险路径列表
        """
        files = DiffParser.parse(diff_text)
        risk_paths: List[RiskPath] = []

        for changed_file in files:
            file_path = changed_file.file_path
            for hunk in changed_file.hunks:
                # 检查新增行
                for line_no, line_content in hunk.added_lines:
                    risks = self._check_line_risks(file_path, line_no, line_content, "ADDED")
                    risk_paths.extend(risks)

                # 检查修改行（删除的也要看：是否移除了安全防护）
                for line_no, line_content in hunk.removed_lines:
                    risks = self._check_line_risks(file_path, line_no, line_content, "REMOVED")
                    risk_paths.extend(risks)

        return risk_paths

    def _check_line_risks(self, file_path: str, line_no: int, line_content: str, change_type: str) -> List[RiskPath]:
        """单行风险检查"""
        risks = []

        # 检查是否命中 sink
        for sink_name, sink_pattern in SINK_PATTERNS.items():
            if re.search(sink_pattern, line_content):
                # 检查同一 hunk 中是否有 source
                source_found = ""
                for src_name, src_pattern in SOURCE_PATTERNS.items():
                    if re.search(src_pattern, line_content):
                        source_found = src_name
                        break

                # 检查是否有 sanitizer
                has_sanitizer = False
                for san_name, san_pattern in SANITIZER_PATTERNS.items():
                    if re.search(san_pattern, line_content):
                        has_sanitizer = True
                        break

                desc = f"[{change_type}] {sink_name}"
                if source_found:
                    desc += f" (可达 source: {source_found})"
                if has_sanitizer:
                    desc += " [已消毒]"
                else:
                    desc += " [未消毒]"

                confidence = 0.9 if source_found and not has_sanitizer else (0.7 if source_found else 0.5)

                risks.append(RiskPath(
                    file=file_path,
                    line=line_no,
                    change_type=change_type,
                    sink_keyword=sink_name,
                    source_keyword=source_found,
                    has_sanitizer=has_sanitizer,
                    description=desc,
                    confidence=confidence,
                ))

        return risks

    def analyze_new_vs_old(self, old_content: str, new_content: str, file_path: str) -> List[RiskPath]:
        """对比变更前后的文件内容，识别新增漏洞路径"""
        diff_text = self._generate_diff(old_content, new_content, file_path)
        return self.analyze_diff(diff_text)

    @staticmethod
    def _generate_diff(old_content: str, new_content: str, file_path: str) -> str:
        """生成统一 diff 格式"""
        old_lines = old_content.splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)
        diff = difflib.unified_diff(
            old_lines, new_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        return "".join(diff)

    def to_agent_format(self, risk_paths: List[RiskPath]) -> List[Dict[str, Any]]:
        """转换为 AgentVote 兼容格式"""
        results = []
        for i, rp in enumerate(risk_paths):
            results.append({
                "signal_id": f"DIFF-{rp.sink_keyword}@{rp.file}:{rp.line}",
                "decision": "CONFIRMED" if rp.confidence >= 0.7 else "UNCERTAIN",
                "confidence": rp.confidence,
                "severity": "HIGH" if (rp.confidence >= 0.7 and rp.source_keyword and not rp.has_sanitizer) else "MEDIUM",
                "vuln_type": "SECURITY_VULN",
                "location": f"{rp.file}:{rp.line}",
                "description": rp.description,
                "title": f"[DiffAnalysis] {rp.change_type}: {rp.sink_keyword}",
                "verification_reason": f"差分分析: {rp.description}",
                "source": "diff_analysis",
                "rule_id": f"diff-{rp.sink_keyword}",
            })
        return results
