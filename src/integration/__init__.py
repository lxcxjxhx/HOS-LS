"""集成模块

提供 CI/CD 集成、IDE 集成和远程控制功能。
"""

from src.integration.github_actions import GitHubActionsIntegration
from src.integration.pr_commenter import PRCommenter
from src.integration.cve_crawler import CVECrawler

__all__ = [
    "GitHubActionsIntegration",
    "PRCommenter",
    "CVECrawler",
]
