"""PR 评论生成器

生成 GitHub PR 评论。
"""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class PRComment:
    """PR 评论"""

    body: str
    path: Optional[str] = None
    line: Optional[int] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    is_blocking: bool = False


@dataclass
class CommentConfig:
    """评论配置"""

    max_comment_length: int = 65536
    max_inline_comments: int = 50
    include_code_snippets: bool = True
    include_fix_suggestions: bool = True
    include_severity_breakdown: bool = True
    include_details: bool = True
    blocking_severities: Set[str] = field(default_factory=lambda: {"critical", "high"})


class PRCommenter:
    """PR 评论生成器"""

    def __init__(self, config: Optional[CommentConfig] = None) -> None:
        self.config = config or CommentConfig()

    def generate_summary_comment(
        self,
        findings: List[Dict[str, Any]],
        scan_info: Optional[Dict[str, Any]] = None,
        project_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        """生成摘要评论"""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        rule_counts: Dict[str, int] = {}
        file_counts: Dict[str, int] = {}

        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

            rule_id = finding.get("rule_id", "unknown")
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

            file_path = finding.get("file_path", finding.get("location", {}).get("file", "Unknown"))
            file_counts[file_path] = file_counts.get(file_path, 0) + 1

        total = len(findings)
        blocking_findings = sum(severity_counts[s] for s in self.config.blocking_severities)

        comment = "## 🔒 HOS-LS Security Scan Results\n\n"

        # 项目信息
        if project_info:
            project_name = project_info.get("name", "Project")
            branch = project_info.get("branch", "main")
            comment += f"**Project:** {project_name}\n"
            comment += f"**Branch:** {branch}\n\n"

        # 扫描信息
        if scan_info:
            comment += "### 📊 Scan Details\n\n"
            comment += f"- **Scanned Files:** {scan_info.get('files_scanned', 'N/A')}\n"
            comment += f"- **Scan Duration:** {scan_info.get('duration', 'N/A')}s\n"
            comment += f"- **Analyzer Version:** {scan_info.get('version', 'N/A')}\n"
            comment += f"- **Scan Timestamp:** {scan_info.get('timestamp', 'N/A')}\n\n"

        # 结果摘要
        comment += "### 📋 Summary\n\n"
        if total == 0:
            comment += "✅ **No security issues found!**\n"
            comment += "\nThe code has been scanned and no security vulnerabilities were detected.\n"
            return self.truncate_comment(comment)

        comment += f"**Total Findings:** {total}\n"
        comment += f"**Blocking Issues:** {blocking_findings}\n\n"

        # 严重程度分布
        if self.config.include_severity_breakdown:
            comment += "### 🎯 Severity Breakdown\n\n"
            comment += "| Severity | Count | Status |\n"
            comment += "|----------|-------|--------|\n"
            
            severities = [
                ("critical", "🔴 Critical", blocking_findings > 0),
                ("high", "🟠 High", blocking_findings > 0),
                ("medium", "🟡 Medium", False),
                ("low", "🔵 Low", False),
                ("info", "⚪ Info", False),
            ]

            for severity_key, severity_label, is_blocking in severities:
                count = severity_counts.get(severity_key, 0)
                status = "⚠️ Blocking" if is_blocking and count > 0 else "✅ Passing"
                comment += f"| {severity_label} | {count} | {status} |\n"

        # 按文件分布
        if file_counts:
            comment += "\n### 📁 Findings by File\n\n"
            sorted_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            for file_path, count in sorted_files:
                comment += f"- `{file_path}`: {count} findings\n"
            if len(file_counts) > 10:
                comment += f"- ... and {len(file_counts) - 10} more files\n"

        # 按规则分布
        if rule_counts:
            comment += "\n### 📝 Findings by Rule\n\n"
            sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            for rule_id, count in sorted_rules:
                comment += f"- `{rule_id}`: {count} findings\n"
            if len(rule_counts) > 10:
                comment += f"- ... and {len(rule_counts) - 10} more rules\n"

        # 高优先级问题详情
        critical_high = [
            f for f in findings if f.get("severity", "").lower() in ["critical", "high"]
        ]
        if critical_high and self.config.include_details:
            comment += "\n### ⚠️ Critical/High Severity Issues\n\n"
            for i, finding in enumerate(critical_high[:15], 1):
                severity = finding.get("severity", "unknown").upper()
                message = finding.get("message", finding.get("description", "No description"))
                file_path = finding.get("file_path", finding.get("location", {}).get("file", "Unknown"))
                line = finding.get("line", finding.get("location", {}).get("line", 0))
                rule_id = finding.get("rule_id", "unknown")
                cwe_id = finding.get("cwe_id", "N/A")
                owasp_category = finding.get("owasp_category", "N/A")

                comment += f"{i}. **[{severity}]** {message}\n"
                comment += f"   - **Rule:** `{rule_id}`\n"
                comment += f"   - **Location:** `{file_path}:{line}`\n"
                if cwe_id != "N/A":
                    comment += f"   - **CWE:** {cwe_id}\n"
                if owasp_category != "N/A":
                    comment += f"   - **OWASP Category:** {owasp_category}\n"
                if self.config.include_fix_suggestions and finding.get("fix_suggestion"):
                    fix = finding["fix_suggestion"]
                    if len(fix) > 150:
                        fix = fix[:150] + "..."
                    comment += f"   - **Suggested Fix:** {fix}\n"
                if self.config.include_code_snippets and finding.get("code_snippet"):
                    code = finding["code_snippet"]
                    if len(code) > 200:
                        code = code[:200] + "..."
                    language = self._get_language(file_path)
                    comment += f"   - **Code Snippet:**\n   ```{language}\n{code}\n   ```\n"
                comment += "\n"

            if len(critical_high) > 15:
                comment += f"_... and {len(critical_high) - 15} more high-severity issues_\n"

        # 总结和行动建议
        comment += "\n### 🚀 Next Steps\n\n"
        if blocking_findings > 0:
            comment += "⚠️ **ACTION REQUIRED:** Address the critical and high severity issues before merging.\n"
            comment += "\n**Recommended Actions:**\n"
            comment += "1. Fix all critical and high severity issues\n"
            comment += "2. Review medium severity issues\n"
            comment += "3. Address low severity and info issues if applicable\n"
        else:
            comment += "✅ **No blocking issues found!**\n"
            comment += "\n**Recommended Actions:**\n"
            comment += "1. Review medium severity issues if any\n"
            comment += "2. Consider addressing low severity and info issues\n"

        # 扫描信息链接
        if scan_info and scan_info.get("report_url"):
            comment += f"\n### 📄 Full Report\n\n"
            comment += f"[View detailed security report]({scan_info['report_url']})\n"

        return self.truncate_comment(comment)

    def generate_inline_comments(
        self, findings: List[Dict[str, Any]]
    ) -> List[PRComment]:
        """生成内联评论"""
        comments = []

        # 按严重程度排序，优先处理高优先级问题
        sorted_findings = sorted(
            findings,
            key=lambda x: (
                0 if x.get("severity", "medium").lower() == "critical" else
                1 if x.get("severity", "medium").lower() == "high" else
                2 if x.get("severity", "medium").lower() == "medium" else
                3
            )
        )

        for finding in sorted_findings[:self.config.max_inline_comments]:
            severity = finding.get("severity", "medium").lower()
            if severity not in ["critical", "high", "medium"]:
                continue

            message = finding.get("message", finding.get("description", ""))
            file_path = finding.get("file_path", finding.get("location", {}).get("file"))
            line = finding.get("line", finding.get("location", {}).get("line"))
            start_line = finding.get("start_line", line)
            end_line = finding.get("end_line", line)
            rule_id = finding.get("rule_id", "unknown")
            cwe_id = finding.get("cwe_id", "N/A")

            if not file_path or not line:
                continue

            # 构建评论内容
            body = f"**[{severity.upper()}] HOS-LS Security Finding**\n\n"
            body += f"{message}\n\n"
            body += f"**Rule:** `{rule_id}`\n"
            if cwe_id != "N/A":
                body += f"**CWE:** {cwe_id}\n"

            if self.config.include_fix_suggestions and finding.get("fix_suggestion"):
                body += f"\n**Suggested Fix:**\n{finding['fix_suggestion']}\n"

            if self.config.include_code_snippets and finding.get("code_snippet"):
                language = self._get_language(file_path)
                body += f"\n**Code Snippet:**\n``` {language}\n{finding['code_snippet']}\n```\n"

            is_blocking = severity in self.config.blocking_severities

            comments.append(
                PRComment(
                    body=body,
                    path=file_path,
                    line=line,
                    start_line=start_line,
                    end_line=end_line,
                    is_blocking=is_blocking,
                )
            )

        return comments

    def generate_label_comments(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """生成标签评论"""
        labels = []

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        if severity_counts["critical"] > 0:
            labels.append("security/critical")
        if severity_counts["high"] > 0:
            labels.append("security/high")
        if severity_counts["medium"] > 0:
            labels.append("security/medium")
        if severity_counts["low"] > 0:
            labels.append("security/low")

        if any(severity_counts[s] > 0 for s in ["critical", "high"]):
            labels.append("security/blocking")

        return labels

    def _get_language(self, file_path: str) -> str:
        """获取文件语言"""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".jsx": "javascript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".go": "go",
            ".rs": "rust",
            ".php": "php",
            ".cs": "csharp",
            ".swift": "swift",
            ".kt": "kotlin",
            ".md": "markdown",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".xml": "xml",
        }

        ext = os.path.splitext(file_path)[1].lower()
        return ext_map.get(ext, "")

    def truncate_comment(self, comment: str) -> str:
        """截断评论以符合 GitHub 限制"""
        if len(comment) <= self.config.max_comment_length:
            return comment

        truncated = comment[: self.config.max_comment_length - 150]
        truncated += "\n\n... _Comment truncated due to GitHub's length limit. View the full report for complete details._"
        return truncated

    def get_comment_stats(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """获取评论统计信息"""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        total = len(findings)
        blocking = sum(severity_counts[s] for s in self.config.blocking_severities)

        return {
            "total_findings": total,
            "blocking_findings": blocking,
            "severity_counts": severity_counts,
            "estimated_comments": min(total, self.config.max_inline_comments),
        }
