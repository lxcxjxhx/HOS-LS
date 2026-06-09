"""安全工具目录自动更新器

每周自动从 GitHub API 发现最新安全工具，检查已注册工具的更新版本，
使用 AI 分析新工具价值，并更新 catalog.json。
"""

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import httpx
from tqdm import tqdm

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
GITHUB_SEARCH_ENDPOINT = f"{GITHUB_API_BASE}/search/repositories"
CATALOG_PATH = Path(__file__).parent / "catalog.json"
UPDATE_LOG_PATH = Path(__file__).parent / "update_log.json"


def load_catalog() -> dict[str, Any]:
    """加载 catalog.json 并返回 {tool_name: tool_info} 字典"""
    if CATALOG_PATH.exists():
        with open(CATALOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        tools = data.get("tools", [])
        return {t.get("name", ""): t for t in tools}
    return {}


def get_catalog_list() -> list[dict]:
    """加载 catalog.json 并返回工具列表"""
    if CATALOG_PATH.exists():
        with open(CATALOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("tools", [])
    return []

SECURITY_KEYWORDS = [
    "security",
    "pentest",
    "scanner",
    "vulnerability",
    "recon",
    "enumeration",
    "exploit",
    "fuzzer",
    "web-security",
    "network-security",
]


@dataclass
class GitHubRepoInfo:
    """GitHub 仓库信息"""

    name: str
    full_name: str
    description: str
    language: str
    stars: int
    forks: int
    updated_at: str
    url: str
    topics: list[str] = field(default_factory=list)


@dataclass
class UpdateLogEntry:
    """更新日志条目"""

    timestamp: str
    action: str  # "discover" | "check_updates" | "add_tool" | "update_tool"
    tool_name: str
    details: dict[str, Any] = field(default_factory=dict)
    success: bool = True


class AutoUpdater:
    """安全工具目录自动更新器"""

    def __init__(
        self,
        catalog_path: Optional[str] = None,
        update_log_path: Optional[str] = None,
        github_token: Optional[str] = None,
        proxy_url: Optional[str] = None,
    ):
        self.catalog_path = Path(catalog_path) if catalog_path else CATALOG_PATH
        self.update_log_path = (
            Path(update_log_path) if update_log_path else UPDATE_LOG_PATH
        )
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.proxy_url = proxy_url
        self._headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            self._headers["Authorization"] = f"token {self.github_token}"
        self._update_log: list[UpdateLogEntry] = []
        self._load_update_log()

    def _get_http_client(self) -> httpx.Client:
        """获取 HTTP 客户端（支持代理）"""
        kwargs: dict[str, Any] = {
            "headers": self._headers,
            "timeout": 30.0,
            "follow_redirects": True,
        }
        if self.proxy_url:
            kwargs["proxy"] = self.proxy_url
        return httpx.Client(**kwargs)

    def _load_catalog(self) -> dict[str, Any]:
        """加载工具目录"""
        if self.catalog_path.exists():
            with open(self.catalog_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"version": "1.0.0", "tools": []}

    def _save_catalog(self, catalog: dict[str, Any]) -> None:
        """保存工具目录"""
        catalog["last_updated"] = datetime.now().isoformat()
        with open(self.catalog_path, "w", encoding="utf-8") as f:
            json.dump(catalog, f, indent=2, ensure_ascii=False)
        logger.info("[AUTO_UPDATE] 目录已保存: %s", self.catalog_path)

    def _load_update_log(self) -> None:
        """加载更新日志"""
        if self.update_log_path.exists():
            try:
                with open(self.update_log_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._update_log = [
                        UpdateLogEntry(**entry) for entry in data.get("log", [])
                    ]
            except Exception:
                self._update_log = []

    def _save_update_log(self) -> None:
        """保存更新日志"""
        data = {
            "last_update": datetime.now().isoformat(),
            "total_entries": len(self._update_log),
            "log": [
                {
                    "timestamp": e.timestamp,
                    "action": e.action,
                    "tool_name": e.tool_name,
                    "details": e.details,
                    "success": e.success,
                }
                for e in self._update_log
            ],
        }
        with open(self.update_log_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _log_update(
        self,
        action: str,
        tool_name: str,
        details: dict[str, Any] | None = None,
        success: bool = True,
    ) -> None:
        """记录更新日志"""
        entry = UpdateLogEntry(
            timestamp=datetime.now().isoformat(),
            action=action,
            tool_name=tool_name,
            details=details or {},
            success=success,
        )
        self._update_log.append(entry)
        self._save_update_log()

    def search_github_security_tools(
        self,
        keywords: Optional[list[str]] = None,
        min_stars: int = 100,
        per_page: int = 30,
    ) -> list[GitHubRepoInfo]:
        """从 GitHub 搜索安全工具

        Args:
            keywords: 搜索关键词列表
            min_stars: 最小 star 数
            per_page: 每页结果数

        Returns:
            发现的仓库信息列表
        """
        keywords = keywords or SECURITY_KEYWORDS
        all_results: list[GitHubRepoInfo] = []
        seen: set[str] = set()

        with self._get_http_client() as client:
            for keyword in tqdm(keywords, desc="搜索 GitHub 安全工具", unit="keyword"):
                logger.info("[AUTO_UPDATE] 搜索关键词: %s", keyword)
                try:
                    params = {
                        "q": f"{keyword} language:python OR language:go stars:>={min_stars}",
                        "sort": "stars",
                        "order": "desc",
                        "per_page": per_page,
                    }
                    resp = client.get(GITHUB_SEARCH_ENDPOINT, params=params)
                    resp.raise_for_status()
                    data = resp.json()

                    for item in data.get("items", []):
                        full_name = item.get("full_name", "")
                        if full_name in seen:
                            continue
                        seen.add(full_name)

                        repo = GitHubRepoInfo(
                            name=item.get("name", ""),
                            full_name=full_name,
                            description=item.get("description", "") or "",
                            language=item.get("language", "") or "unknown",
                            stars=item.get("stargazers_count", 0),
                            forks=item.get("forks_count", 0),
                            updated_at=item.get("updated_at", ""),
                            url=item.get("html_url", ""),
                            topics=item.get("topics", []),
                        )
                        all_results.append(repo)

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 403:
                        logger.warning(
                            "[AUTO_UPDATE] GitHub API 速率限制，需要设置 GITHUB_TOKEN"
                        )
                    else:
                        logger.error(
                            "[AUTO_UPDATE] GitHub 搜索失败 (%s): %s",
                            keyword,
                            e.response.status_code,
                        )
                except Exception as e:
                    logger.error("[AUTO_UPDATE] GitHub 搜索异常 (%s): %s", keyword, e)

        logger.info(
            "[AUTO_UPDATE] 发现 %d 个候选安全工具",
            len(all_results),
        )
        return all_results

    def check_tool_updates(self, catalog: Optional[dict] = None) -> list[dict]:
        """检查已注册工具的最新版本

        Args:
            catalog: 工具目录，为 None 时自动加载

        Returns:
            有更新的工具列表
        """
        if catalog is None:
            catalog = self._load_catalog()

        tools = catalog.get("tools", [])
        updates: list[dict] = []

        with self._get_http_client() as client:
            for tool in tqdm(tools, desc="检查工具更新", unit="tool"):
                tool_name = tool.get("name", "")
                try:
                    resp = client.get(
                        f"{GITHUB_API_BASE}/repos/{tool_name}",
                    )
                    if resp.status_code == 200:
                        repo_data = resp.json()
                        current_version = tool.get("version", "")
                        latest_version = repo_data.get("default_branch", "main")

                        if current_version and current_version != latest_version:
                            updates.append(
                                {
                                    "name": tool_name,
                                    "current_version": current_version,
                                    "latest_version": latest_version,
                                    "url": repo_data.get("html_url", ""),
                                    "stars": repo_data.get("stargazers_count", 0),
                                }
                            )
                    elif resp.status_code == 404:
                        logger.debug(
                            "[AUTO_UPDATE] 未找到仓库: %s",
                            tool_name,
                        )
                except Exception as e:
                    logger.warning(
                        "[AUTO_UPDATE] 检查 %s 更新失败: %s",
                        tool_name,
                        e,
                    )

        self._log_update(
            "check_updates",
            "all",
            {"total_updates": len(updates), "updated_tools": [u["name"] for u in updates]},
        )
        logger.info("[AUTO_UPDATE] 发现 %d 个工具可更新", len(updates))
        return updates

    def analyze_new_tool(
        self, repo: GitHubRepoInfo, ai_callback: Optional[callable] = None
    ) -> Optional[dict]:
        """分析新工具是否值得添加

        Args:
            repo: GitHub 仓库信息
            ai_callback: AI 分析回调函数，为 None 时使用内置规则

        Returns:
            工具配置字典，不值得添加时返回 None
        """
        if ai_callback:
            try:
                result = ai_callback(repo)
                if result:
                    return result
            except Exception as e:
                logger.warning("[AUTO_UPDATE] AI 分析失败: %s", e)

        return self._rule_based_analysis(repo)

    def _rule_based_analysis(self, repo: GitHubRepoInfo) -> Optional[dict]:
        """基于规则的工具价值分析"""
        score = 0

        if repo.stars >= 1000:
            score += 3
        elif repo.stars >= 500:
            score += 2
        elif repo.stars >= 100:
            score += 1

        if repo.forks >= 100:
            score += 1

        for topic in repo.topics:
            if topic.lower() in ["security", "pentest", "scanner"]:
                score += 1

        relevant_keywords = ["scan", "audit", "pentest", "recon", "enum", "fuzz"]
        desc_lower = repo.description.lower()
        if any(kw in desc_lower for kw in relevant_keywords):
            score += 1

        if score >= 2:
            category = "python" if repo.language == "Python" else (
                "go" if repo.language == "Go" else "system"
            )

            return {
                "name": repo.name,
                "category": category,
                "description": repo.description,
                "install_cmd": self._generate_install_cmd(repo),
                "version_cmd": "--version",
                "tags": self._generate_tags(repo),
                "ai_capability": f"自动化{repo.description}功能",
                "ai_input_format": "根据工具特性自动推断",
                "ai_output_format": "结构化JSON输出",
                "source": {
                    "github": repo.full_name,
                    "stars": repo.stars,
                    "url": repo.url,
                },
            }

        logger.debug(
            "[AUTO_UPDATE] %s 评分 %d，不值得添加",
            repo.name,
            score,
        )
        return None

    def _generate_install_cmd(self, repo: GitHubRepoInfo) -> dict[str, str]:
        """生成安装命令"""
        cmds: dict[str, str] = {}

        if repo.language == "Python":
            cmds["pip"] = f"pip install {repo.name}"
            cmds["apt"] = f"apt install {repo.name}"

        elif repo.language == "Go":
            name = repo.name
            full = repo.full_name
            cmds["go"] = f"go install -v {full}/{name}@latest"
            cmds["brew"] = f"brew install {name}"

        cmds["brew"] = cmds.get("brew", f"brew install {repo.name}")
        cmds["choco"] = cmds.get("choco", f"choco install {repo.name}")

        return cmds

    def _generate_tags(self, repo: GitHubRepoInfo) -> list[str]:
        """生成工具标签"""
        tags: list[str] = []
        desc_lower = repo.description.lower()

        tag_map = {
            "scan": "scanner",
            "vuln": "vulnerability",
            "recon": "recon",
            "enum": "enum",
            "fuzz": "fuzzer",
            "exploit": "exploit",
            "discover": "recon",
            "crawl": "crawler",
            "port": "port",
            "web": "web",
        }

        for keyword, tag in tag_map.items():
            if keyword in desc_lower and tag not in tags:
                tags.append(tag)

        if not tags:
            tags = ["scanner"]

        return tags

    def add_new_tools(
        self,
        repos: list[GitHubRepoInfo],
        ai_callback: Optional[callable] = None,
    ) -> list[dict]:
        """添加新工具到目录

        Args:
            repos: GitHub 仓库信息列表
            ai_callback: AI 分析回调

        Returns:
            成功添加的工具列表
        """
        catalog = self._load_catalog()
        existing_names = {
            tool.get("name", "") for tool in catalog.get("tools", [])
        }
        added: list[dict] = []

        for repo in tqdm(repos, desc="分析并添加工具", unit="tool"):
            if repo.name in existing_names:
                continue

            tool_config = self.analyze_new_tool(repo, ai_callback)
            if tool_config:
                catalog["tools"].append(tool_config)
                added.append(tool_config)
                self._log_update(
                    "add_tool",
                    repo.name,
                    {
                        "stars": repo.stars,
                        "language": repo.language,
                        "url": repo.url,
                    },
                )
                logger.info(
                    "[AUTO_UPDATE] 新工具已添加: %s (%d stars)",
                    repo.name,
                    repo.stars,
                )

        if added:
            self._save_catalog(catalog)

        logger.info("[AUTO_UPDATE] 成功添加 %d 个新工具", len(added))
        return added

    def run_full_update(
        self,
        ai_callback: Optional[callable] = None,
        check_existing: bool = True,
        discover_new: bool = True,
    ) -> dict[str, Any]:
        """执行完整更新流程

        Args:
            ai_callback: AI 分析回调
            check_existing: 是否检查已有工具更新
            discover_new: 是否发现新工具

        Returns:
            更新结果摘要
        """
        logger.info("=" * 60)
        logger.info("[AUTO_UPDATE] 开始工具目录完整更新")
        logger.info("=" * 60)

        results: dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "updates": [],
            "new_tools": [],
            "errors": [],
        }

        if check_existing:
            logger.info("[AUTO_UPDATE] [1/2] 检查已注册工具更新...")
            try:
                results["updates"] = self.check_tool_updates()
            except Exception as e:
                logger.error("[AUTO_UPDATE] 检查更新失败: %s", e)
                results["errors"].append(f"check_updates: {e}")

        if discover_new:
            logger.info("[AUTO_UPDATE] [2/2] 发现新安全工具...")
            try:
                repos = self.search_github_security_tools()
                results["new_tools"] = self.add_new_tools(repos, ai_callback)
            except Exception as e:
                logger.error("[AUTO_UPDATE] 发现新工具失败: %s", e)
                results["errors"].append(f"discover_new: {e}")

        self._log_update(
            "discover",
            "all",
            {
                "total_updates": len(results["updates"]),
                "total_new_tools": len(results["new_tools"]),
            },
        )

        logger.info(
            "[AUTO_UPDATE] 更新完成: %d 个更新, %d 个新工具",
            len(results["updates"]),
            len(results["new_tools"]),
        )
        return results

    def schedule_update(
        self,
        days: int = 7,
        ai_callback: Optional[callable] = None,
    ) -> None:
        """安排定期更新

        Args:
            days: 更新间隔天数
            ai_callback: AI 分析回调
        """

        def _update_loop() -> None:
            logger.info(
                "[AUTO_UPDATE] 定时更新已启动，间隔 %d 天",
                days,
            )
            while True:
                try:
                    self.run_full_update(ai_callback=ai_callback)
                except Exception as e:
                    logger.error("[AUTO_UPDATE] 定期更新失败: %s", e)

                next_run = datetime.now() + timedelta(days=days)
                logger.info(
                    "[AUTO_UPDATE] 下次更新: %s",
                    next_run.isoformat(),
                )
                thread_event = threading.Event()
                thread_event.wait(timeout=days * 24 * 3600)

        thread = threading.Thread(target=_update_loop, daemon=True)
        thread.start()
        logger.info("[AUTO_UPDATE] 定时更新线程已启动")
