"""GitHub Actions 集成模块

提供 GitHub Actions 工作流相关的功能。
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class GitHubContext:
    """GitHub Actions 上下文"""

    workflow: str = ""
    run_id: str = ""
    run_number: str = ""
    event_name: str = ""
    event_path: str = ""
    repository: str = ""
    ref: str = ""
    sha: str = ""
    actor: str = ""
    token: Optional[str] = None

    @classmethod
    def from_env(cls) -> "GitHubContext":
        """从环境变量创建上下文"""
        return cls(
            workflow=os.getenv("GITHUB_WORKFLOW", ""),
            run_id=os.getenv("GITHUB_RUN_ID", ""),
            run_number=os.getenv("GITHUB_RUN_NUMBER", ""),
            event_name=os.getenv("GITHUB_EVENT_NAME", ""),
            event_path=os.getenv("GITHUB_EVENT_PATH", ""),
            repository=os.getenv("GITHUB_REPOSITORY", ""),
            ref=os.getenv("GITHUB_REF", ""),
            sha=os.getenv("GITHUB_SHA", ""),
            actor=os.getenv("GITHUB_ACTOR", ""),
            token=os.getenv("GITHUB_TOKEN"),
        )


@dataclass
class SARIFResult:
    """SARIF 结果"""

    rule_id: str
    message: str
    level: str
    file_path: str
    line: int = 1
    column: int = 1
    end_line: int = 0
    end_column: int = 0

    def to_sarif(self) -> Dict[str, Any]:
        """转换为 SARIF 格式"""
        return {
            "ruleId": self.rule_id,
            "level": self.level,
            "message": {"text": self.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.file_path},
                        "region": {
                            "startLine": self.line,
                            "startColumn": self.column,
                            "endLine": self.end_line or self.line,
                            "endColumn": self.end_column or self.column,
                        },
                    }
                }
            ],
        }


class SARIFGenerator:
    """SARIF 报告生成器"""

    def __init__(self, tool_name: str = "HOS-LS", version: str = "3.0.0") -> None:
        self.tool_name = tool_name
        self.version = version
        self.results: List[SARIFResult] = []

    def add_result(self, result: SARIFResult) -> None:
        """添加结果"""
        self.results.append(result)

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """从发现字典添加结果"""
        result = SARIFResult(
            rule_id=finding.get("rule_id", "UNKNOWN"),
            message=finding.get("message", finding.get("description", "")),
            level=self._map_severity(finding.get("severity", "medium")),
            file_path=finding.get("file_path", finding.get("location", {}).get("file", "")),
            line=finding.get("line", finding.get("location", {}).get("line", 1)),
            column=finding.get("column", finding.get("location", {}).get("column", 1)),
        )
        self.add_result(result)

    def _map_severity(self, severity: str) -> str:
        """映射严重级别到 SARIF 级别"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }
        return mapping.get(severity.lower(), "warning")

    def generate(self) -> Dict[str, Any]:
        """生成 SARIF 报告"""
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.version,
                            "informationUri": "https://github.com/hos-ls/hos-ls",
                            "rules": self._generate_rules(),
                        }
                    },
                    "results": [r.to_sarif() for r in self.results],
                }
            ],
        }

    def _generate_rules(self) -> List[Dict[str, Any]]:
        """生成规则列表"""
        seen_rules = set()
        rules = []

        for result in self.results:
            if result.rule_id not in seen_rules:
                seen_rules.add(result.rule_id)
                rules.append(
                    {
                        "id": result.rule_id,
                        "shortDescription": {"text": result.rule_id},
                        "defaultConfiguration": {"level": result.level},
                    }
                )

        return rules

    def save(self, output_path: str) -> None:
        """保存 SARIF 报告"""
        sarif = self.generate()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)


class GitHubActionsIntegration:
    """GitHub Actions 集成"""

    def __init__(self) -> None:
        self.context = GitHubContext.from_env()
        self.sarif_generator = SARIFGenerator()

    def is_running_in_actions(self) -> bool:
        """检查是否在 GitHub Actions 中运行"""
        return os.getenv("GITHUB_ACTIONS") == "true"

    def set_output(self, name: str, value: str) -> None:
        """设置 GitHub Actions 输出"""
        if self.is_running_in_actions():
            output_file = os.getenv("GITHUB_OUTPUT")
            if output_file:
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(f"{name}={value}\n")

    def set_secret(self, name: str, value: str) -> None:
        """设置 GitHub Actions 机密"""
        if self.is_running_in_actions():
            print(f"::add-mask::{value}")

    def log_error(self, message: str, file: str = "", line: int = 0) -> None:
        """记录错误"""
        if self.is_running_in_actions():
            if file and line:
                print(f"::error file={file},line={line}::{message}")
            else:
                print(f"::error::{message}")
        else:
            print(f"ERROR: {message}")

    def log_warning(self, message: str, file: str = "", line: int = 0) -> None:
        """记录警告"""
        if self.is_running_in_actions():
            if file and line:
                print(f"::warning file={file},line={line}::{message}")
            else:
                print(f"::warning::{message}")
        else:
            print(f"WARNING: {message}")

    def log_notice(self, message: str, file: str = "", line: int = 0) -> None:
        """记录通知"""
        if self.is_running_in_actions():
            if file and line:
                print(f"::notice file={file},line={line}::{message}")
            else:
                print(f"::notice::{message}")
        else:
            print(f"NOTICE: {message}")

    def start_group(self, title: str) -> None:
        """开始日志组"""
        if self.is_running_in_actions():
            print(f"::group::{title}")

    def end_group(self) -> None:
        """结束日志组"""
        if self.is_running_in_actions():
            print("::endgroup::")

    def generate_sarif(
        self, findings: List[Dict[str, Any]], output_path: str = "results.sarif"
    ) -> str:
        """生成 SARIF 报告"""
        for finding in findings:
            self.sarif_generator.add_finding(finding)

        self.sarif_generator.save(output_path)
        return output_path
