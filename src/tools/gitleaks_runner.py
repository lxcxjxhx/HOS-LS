"""Gitleaks 密钥泄露扫描器

基于 Gitleaks 检测代码中的敏感信息泄露
"""
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional


class GitleaksRunner:
    """Gitleaks 密钥扫描层"""

    SECRET_TYPES = {
        "aws_access_key": "AWS Access Key",
        "aws_secret_key": "AWS Secret Key",
        "github_token": "GitHub Token",
        "gitlab_token": "GitLab Token",
        "private_key": "Private Key",
        "password": "Password",
        "api_key": "API Key",
        "generic_secret": "Generic Secret",
        "token": "API Token",
        "secret": "Secret",
    }

    def __init__(self):
        self._check_available()

    def _check_available(self) -> bool:
        """检查 gitleaks 是否可用"""
        try:
            result = subprocess.run(
                ["gitleaks", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def scan_directory(self, dir_path: str) -> List[Dict[str, Any]]:
        """扫描目录

        Args:
            dir_path: 目录路径

        Returns:
            密钥泄露发现列表
        """
        if not self._check_available():
            print("[GITLEAKS] gitleaks 未安装或不可用")
            return []

        results = []
        try:
            cmd = [
                "gitleaks",
                "detect",
                "--format", "json",
                "--source", dir_path,
                "--no-git"
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.stdout:
                data = json.loads(result.stdout)
                findings = data if isinstance(data, list) else [data]
                for finding in findings:
                    results.append(self._parse_finding(finding))
        except subprocess.TimeoutExpired:
            print("[GITLEAKS] 扫描超时")
        except json.JSONDecodeError:
            print("[GITLEAKS] 解析输出失败")
        except Exception as e:
            print(f"[GITLEAKS] 扫描失败 {dir_path}: {e}")

        return results

    def scan_repo(self, repo_url: str) -> List[Dict[str, Any]]:
        """扫描 git 仓库

        Args:
            repo_url: 仓库 URL

        Returns:
            密钥泄露发现列表
        """
        if not self._check_available():
            print("[GITLEAKS] gitleaks 未安装或不可用")
            return []

        results = []
        try:
            cmd = [
                "gitleaks",
                "detect",
                "--format", "json",
                "--source", repo_url,
                "--no-git"
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.stdout:
                data = json.loads(result.stdout)
                findings = data if isinstance(data, list) else [data]
                for finding in findings:
                    results.append(self._parse_finding(finding))
        except subprocess.TimeoutExpired:
            print("[GITLEAKS] 仓库扫描超时")
        except json.JSONDecodeError:
            print("[GITLEAKS] 解析输出失败")
        except Exception as e:
            print(f"[GITLEAKS] 仓库扫描失败 {repo_url}: {e}")

        return results

    def scan_precommit(self) -> List[Dict[str, Any]]:
        """作为 precommit hook 运行

        Returns:
            密钥泄露发现列表
        """
        if not self._check_available():
            print("[GITLEAKS] gitleaks 未安装或不可用")
            return []

        results = []
        try:
            cmd = [
                "gitleaks",
                "detect",
                "--format", "json",
                "--staged",
                "--no-git"
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.stdout:
                data = json.loads(result.stdout)
                findings = data if isinstance(data, list) else [data]
                for finding in findings:
                    results.append(self._parse_finding(finding))
        except subprocess.TimeoutExpired:
            print("[GITLEAKS] precommit 扫描超时")
        except json.JSONDecodeError:
            print("[GITLEAKS] 解析输出失败")
        except Exception as e:
            print(f"[GITLEAKS] precommit 扫描失败: {e}")

        return results

    def _parse_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """解析单个发现结果

        Args:
            finding: gitleaks 原始发现

        Returns:
            统一格式的密钥发现
        """
        secret_type_raw = finding.get("RuleID", "").lower()
        secret_type = self._classify_secret(secret_type_raw)

        return {
            "file": finding.get("File", ""),
            "line": finding.get("StartLine", 0),
            "secret_type": secret_type,
            "match": finding.get("Match", ""),
            "commit_hash": finding.get("Commit", ""),
            "author": finding.get("Author", ""),
            "message": finding.get("Message", ""),
            "source": "gitleaks"
        }

    def _classify_secret(self, rule_id: str) -> str:
        """分类密钥类型

        Args:
            rule_id: gitleaks 规则 ID

        Returns:
            标准化密钥类型
        """
        if "aws_access" in rule_id or "awskey" in rule_id:
            return "AWS Access Key"
        if "aws_secret" in rule_id or "awssecret" in rule_id:
            return "AWS Secret Key"
        if "github" in rule_id and "token" in rule_id:
            return "GitHub Token"
        if "gitlab" in rule_id:
            return "GitLab Token"
        if "private_key" in rule_id or "ssh_key" in rule_id:
            return "Private Key"
        if "password" in rule_id:
            return "Password"
        if "api_key" in rule_id:
            return "API Key"
        if "generic" in rule_id or "secret" in rule_id:
            return "Generic Secret"
        if "token" in rule_id:
            return "API Token"

        return self.SECRET_TYPES.get(rule_id, "Secret")


def run_gitleaks_scan(target: str, scan_type: str = "directory") -> List[Dict[str, Any]]:
    """便捷函数：运行 Gitleaks 扫描

    Args:
        target: 目标路径或仓库 URL
        scan_type: 扫描类型（"directory" 或 "repo"）

    Returns:
        密钥泄露发现列表
    """
    runner = GitleaksRunner()

    if scan_type == "repo":
        return runner.scan_repo(target)
    else:
        return runner.scan_directory(target)
