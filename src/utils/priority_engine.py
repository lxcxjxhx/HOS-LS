"""文件优先级引擎

对扫描文件进行优先级评分和排序，优化扫描策略。
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

from src.utils.priority_models import (
    AssetValueCalculator,
    AssetValueLevel,
    ExploitabilityCalculator,
    ExploitabilityLevel,
    FilePriority,
    PriorityConfig,
    PriorityLevel,
    PriorityResult,
    PriorityStrategy,
    ReachabilityCalculator,
    ReachabilityLevel,
)
from src.utils.file_discovery import FileInfo, FileType, Language

logger = get_logger(__name__)



class FilePriorityEngine:
    """文件优先级引擎

    计算文件的扫描优先级，支持多种评分维度和策略。
    """

    def __init__(self, config: Optional[PriorityConfig] = None):
        """初始化文件优先级引擎

        Args:
            config: 优先级配置
        """
        self.config = config or PriorityConfig()
        self._score_cache: Dict[str, FilePriority] = {}

    def calculate_priority(
        self,
        file_info: FileInfo,
        strategy: PriorityStrategy = PriorityStrategy.BALANCED,
    ) -> FilePriority:
        """计算文件优先级

        Args:
            file_info: 文件信息
            strategy: 优先级策略

        Returns:
            文件优先级信息
        """
        cache_key = f"{file_info.path}_{strategy.value}"
        if cache_key in self._score_cache:
            return self._score_cache[cache_key]

        business_score = self.get_business_criticality_score(file_info)
        complexity_score = self.get_complexity_score(file_info)
        security_score = self.get_security_sensitivity_score(file_info)
        change_frequency_score = self.get_change_frequency_score(file_info)

        weights = self._get_weights(strategy)

        if strategy == PriorityStrategy.API_FIRST:
            api_first_scores = self.get_api_first_score(file_info)
            total_score = (
                business_score * weights["business"]
                + complexity_score * weights["complexity"]
                + security_score * weights["security"]
                + change_frequency_score * weights["change_frequency"]
                + api_first_scores["port_config"] * weights["port_config"]
                + api_first_scores["api_route"] * weights["api_route"]
                + api_first_scores["security_config"] * weights["security_config"]
            )
        else:
            total_score = (
                business_score * weights["business"]
                + complexity_score * weights["complexity"]
                + security_score * weights["security"]
                + change_frequency_score * weights["change_frequency"]
            )

        priority_level = self._determine_priority_level(total_score)

        priority = FilePriority(
            file_info=file_info,
            total_score=total_score,
            business_score=business_score,
            complexity_score=complexity_score,
            security_score=security_score,
            change_frequency_score=change_frequency_score,
            priority_level=priority_level,
        )

        self._score_cache[cache_key] = priority
        return priority

    def rank_files(
        self,
        files: List[FileInfo],
        strategy: PriorityStrategy = PriorityStrategy.BALANCED,
    ) -> List[FilePriority]:
        """对文件进行优先级排序

        Args:
            files: 文件列表
            strategy: 优先级策略

        Returns:
            排序后的文件优先级列表
        """
        priorities = [self.calculate_priority(file_info, strategy) for file_info in files]

        sorted_priorities = sorted(priorities, key=lambda p: p.total_score, reverse=True)

        for rank, priority in enumerate(sorted_priorities, 1):
            priority.rank = rank

        return sorted_priorities

    def get_business_criticality_score(self, file_info: FileInfo) -> float:
        """获取业务关键度评分

        Args:
            file_info: 文件信息

        Returns:
            业务关键度评分 (0.0 - 1.0)
        """
        score = 0.0
        path_str = str(file_info.path).lower()
        file_stem = file_info.path.stem.lower()

        for pattern in self.config.business_critical_patterns:
            if pattern in path_str or pattern in file_stem:
                score += 0.1

        if file_info.file_type == FileType.SOURCE:
            score += 0.2
        elif file_info.file_type == FileType.CONFIG:
            score += 0.15
        elif file_info.file_type == FileType.TEST:
            score -= 0.1

        if "entry" in path_str or "main" in path_str or "app" in path_str:
            score += 0.15

        if "core" in path_str or "engine" in path_str or "service" in path_str:
            score += 0.1

        return min(max(score, 0.0), 1.0)

    def get_complexity_score(self, file_info: FileInfo) -> float:
        """获取复杂度评分

        Args:
            file_info: 文件信息

        Returns:
            复杂度评分 (0.0 - 1.0)
        """
        score = 0.0

        if file_info.line_count > 0:
            if file_info.line_count > 1000:
                score += 0.4
            elif file_info.line_count > 500:
                score += 0.3
            elif file_info.line_count > 200:
                score += 0.2
            elif file_info.line_count > 100:
                score += 0.1

        if file_info.size > 0:
            if file_info.size > 100 * 1024:
                score += 0.3
            elif file_info.size > 50 * 1024:
                score += 0.2
            elif file_info.size > 20 * 1024:
                score += 0.1

        if file_info.language in [Language.CPP, Language.JAVA, Language.TYPESCRIPT]:
            score += 0.1
        elif file_info.language == Language.PYTHON:
            score += 0.05

        return min(max(score, 0.0), 1.0)

    def get_security_sensitivity_score(self, file_info: FileInfo) -> float:
        """获取安全敏感度评分

        Args:
            file_info: 文件信息

        Returns:
            安全敏感度评分 (0.0 - 1.0)
        """
        score = 0.0
        path_str = str(file_info.path).lower()
        file_stem = file_info.path.stem.lower()

        for pattern in self.config.security_sensitive_patterns:
            if pattern in path_str or pattern in file_stem:
                score += 0.08

        security_keywords = [
            "password",
            "secret",
            "key",
            "token",
            "credential",
            "auth",
            "login",
            "session",
            "cookie",
            "header",
            "input",
            "request",
            "query",
            "sql",
            "execute",
            "eval",
            "system",
            "subprocess",
            "shell",
            "command",
            "inject",
            "xss",
            "csrf",
            "srf",
            "rce",
            "lfi",
            "rfi",
            "ssrf",
            "xxe",
            "sqli",
            "bypass",
            "vulnerability",
            "exploit",
            "attack",
            "hack",
            "malicious",
            "threat",
            "risk",
            "dangerous",
            "unsafe",
            "insecure",
            "sensitive",
            "confidential",
            "private",
            "protected",
            "restricted",
            "classified",
            "critical",
            "important",
            "valuable",
        ]

        for keyword in security_keywords:
            if keyword in path_str or keyword in file_stem:
                score += 0.05

        if file_info.file_type == FileType.CONFIG:
            score += 0.15

        if file_info.language == Language.PYTHON:
            if any(
                kw in path_str for kw in ["views.py", "controllers.py", "handlers.py", "api.py"]
            ):
                score += 0.2

        if file_info.language in [Language.JAVASCRIPT, Language.TYPESCRIPT]:
            if any(
                kw in path_str for kw in ["route", "controller", "handler", "middleware", "api"]
            ):
                score += 0.15

        return min(max(score, 0.0), 1.0)

    def get_change_frequency_score(self, file_info: FileInfo) -> float:
        """获取变更频率评分

        Args:
            file_info: 文件信息

        Returns:
            变更频率评分 (0.0 - 1.0)
        """
        score = 0.0

        if file_info.metadata.get("commit_count", 0) > 0:
            commit_count = file_info.metadata["commit_count"]
            if commit_count > 50:
                score += 0.4
            elif commit_count > 20:
                score += 0.3
            elif commit_count > 10:
                score += 0.2
            elif commit_count > 5:
                score += 0.1

        if file_info.metadata.get("recently_modified", False):
            score += 0.2

        if file_info.metadata.get("hotspot", False):
            score += 0.2

        if file_info.metadata.get("bug_fix_count", 0) > 0:
            bug_fix_count = file_info.metadata["bug_fix_count"]
            if bug_fix_count > 10:
                score += 0.3
            elif bug_fix_count > 5:
                score += 0.2
            elif bug_fix_count > 2:
                score += 0.1

        return min(max(score, 0.0), 1.0)

    def get_api_first_score(self, file_info: FileInfo) -> Dict[str, float]:
        """获取 API 优先评分

        Args:
            file_info: 文件信息

        Returns:
            包含各维度评分的字典
        """
        port_config_score = 0.0
        api_route_score = 0.0
        security_config_score = 0.0

        path_str = str(file_info.path).lower()
        file_stem = file_info.path.stem.lower()

        port_config_patterns = [
            "application.yml",
            "application.yaml",
            "application.properties",
            "config.json",
            "config.yaml",
            "config.yml",
            "application-dev.yml",
            "application-prod.yml",
            "application-test.yml",
            "bootstrap.yml",
            "bootstrap.yaml",
            "nacos",
            "apollo",
            "consul",
            "etcd",
            "zookeeper",
            "port",
            "server.port",
            "server.address",
            "bind.address",
            "listen",
            "socket",
            "endpoint",
            "gateway",
            "proxy",
        ]

        api_route_patterns = [
            "restcontroller",
            "requestmapping",
            "getmapping",
            "postmapping",
            "putmapping",
            "deletemapping",
            "patchmapping",
            "apimapping",
            "router",
            "route",
            "endpoint",
            "controller",
            "handler",
            "view",
            "action",
            "app.route",
            "router.post",
            "router.get",
            "router.put",
            "router.delete",
            "router.patch",
            "api/",
            "/api",
            "rest/",
            "/rest",
            "graphql",
            "grpc",
            "websocket",
            "socket.io",
            "signalr",
        ]

        security_config_patterns = [
            "filter",
            "interceptor",
            "auth",
            "authentication",
            "authorization",
            "security",
            "shiro",
            "springsecurity",
            "oauth",
            "jwt",
            "token",
            "credential",
            "permission",
            "role",
            "access",
            "cors",
            "csrf",
            "xss",
            "waf",
            "firewall",
            "gateway",
        ]

        # data_access_patterns = [
        #     "repository",
        #     "mapper",
        #     "dao",
        #     "data",
        #     "database",
        #     "db.",
        #     "jpa",
        #     "mybatis",
        #     "hibernate",
        #     "jdbc",
        #     "sql",
        #     "query",
        #     "crud",
        #     "storage",
        #     "cache",
        #     "redis",
        #     "mongodb",
        # ]

        # business_patterns = [
        #     "service",
        #     "manager",
        #     "business",
        #     "logic",
        #     "core",
        #     "engine",
        #     "processor",
        #     "executor",
        #     "workflow",
        #     "transaction",
        #     "validator",
        # ]

        utility_patterns = [
            "util",
            "helper",
            "tool",
            "common",
            "constant",
            "enum",
            "model",
            "dto",
            "vo",
            "entity",
            "object",
            "bean",
        ]

        for pattern in port_config_patterns:
            if pattern in path_str or pattern in file_stem:
                port_config_score += 0.2
                break

        for pattern in api_route_patterns:
            if pattern in path_str or pattern in file_stem:
                api_route_score += 0.25
                break

        if file_info.file_type == FileType.SOURCE:
            if "controller" in path_str or "handler" in path_str:
                api_route_score += 0.3
            elif any(p in path_str for p in ["service", "manager", "business"]):
                api_route_score += 0.2
            elif any(p in path_str for p in ["repository", "mapper", "dao"]):
                api_route_score += 0.15

        for pattern in security_config_patterns:
            if pattern in path_str or pattern in file_stem:
                security_config_score += 0.15
                break

        if "config" in path_str and any(
            p in path_str for p in ["security", "auth", "filter", "cors"]
        ):
            security_config_score += 0.2

        if file_info.language == Language.JAVA:
            if any(
                kw in path_str
                for kw in ["@restcontroller", "@requestmapping", "@getmapping", "@postmapping"]
            ):
                api_route_score += 0.3
            elif any(kw in path_str for kw in ["@repository", "@mapper"]):
                api_route_score += 0.15
            elif any(kw in path_str for kw in ["@service", "@component"]):
                api_route_score += 0.1

        if file_info.language in [Language.JAVASCRIPT, Language.TYPESCRIPT]:
            if any(kw in path_str for kw in ["router", "controller", "handler", "middleware"]):
                api_route_score += 0.25
            if file_stem.endswith(".route") or file_stem.endswith(".router"):
                api_route_score += 0.3

        if file_info.language == Language.PYTHON:
            if file_stem in ["views", "controllers", "handlers", "api", "endpoints"]:
                api_route_score += 0.3
            if "app.route" in path_str or "@app.route" in path_str:
                api_route_score += 0.25

        for pattern in utility_patterns:
            if pattern in path_str and api_route_score == 0.0:
                port_config_score *= 0.5
                api_route_score *= 0.5
                security_config_score *= 0.5
                break

        return {
            "port_config": min(max(port_config_score, 0.0), 1.0),
            "api_route": min(max(api_route_score, 0.0), 1.0),
            "security_config": min(max(security_config_score, 0.0), 1.0),
        }

    def get_top_priority_files(
        self,
        files: List[FileInfo],
        top_n: int = 10,
        strategy: PriorityStrategy = PriorityStrategy.BALANCED,
    ) -> List[FilePriority]:
        """获取优先级最高的文件

        Args:
            files: 文件列表
            top_n: 返回数量
            strategy: 优先级策略

        Returns:
            优先级最高的文件列表
        """
        ranked = self.rank_files(files, strategy)
        return ranked[:top_n]

    def filter_by_priority_level(
        self,
        files: List[FileInfo],
        min_level: PriorityLevel,
        strategy: PriorityStrategy = PriorityStrategy.BALANCED,
    ) -> List[FilePriority]:
        """按优先级等级过滤文件

        Args:
            files: 文件列表
            min_level: 最低优先级等级
            strategy: 优先级策略

        Returns:
            过滤后的文件优先级列表
        """
        level_order = {
            PriorityLevel.CRITICAL: 5,
            PriorityLevel.HIGH: 4,
            PriorityLevel.MEDIUM: 3,
            PriorityLevel.LOW: 2,
            PriorityLevel.INFO: 1,
        }

        min_order = level_order[min_level]

        priorities = [self.calculate_priority(file_info, strategy) for file_info in files]

        return [p for p in priorities if level_order[p.priority_level] >= min_order]

    def _get_weights(self, strategy: PriorityStrategy) -> Dict[str, float]:
        """获取策略权重

        Args:
            strategy: 优先级策略

        Returns:
            权重字典
        """
        if strategy == PriorityStrategy.BALANCED:
            return {
                "business": self.config.business_weight,
                "complexity": self.config.complexity_weight,
                "security": self.config.security_weight,
                "change_frequency": self.config.change_frequency_weight,
            }
        elif strategy == PriorityStrategy.SECURITY_FIRST:
            return {
                "business": 0.15,
                "complexity": 0.15,
                "security": 0.50,
                "change_frequency": 0.20,
            }
        elif strategy == PriorityStrategy.COMPLEXITY_FIRST:
            return {
                "business": 0.20,
                "complexity": 0.40,
                "security": 0.20,
                "change_frequency": 0.20,
            }
        elif strategy == PriorityStrategy.BUSINESS_FIRST:
            return {
                "business": 0.40,
                "complexity": 0.20,
                "security": 0.20,
                "change_frequency": 0.20,
            }
        elif strategy == PriorityStrategy.CHANGE_FREQUENCY_FIRST:
            return {
                "business": 0.20,
                "complexity": 0.20,
                "security": 0.20,
                "change_frequency": 0.40,
            }
        elif strategy == PriorityStrategy.API_FIRST:
            return {
                "business": 0.0,
                "complexity": 0.15,
                "security": 0.25,
                "change_frequency": 0.0,
                "port_config": 0.30,
                "api_route": 0.25,
                "security_config": 0.05,
            }
        else:
            return {
                "business": self.config.business_weight,
                "complexity": self.config.complexity_weight,
                "security": self.config.security_weight,
                "change_frequency": self.config.change_frequency_weight,
            }

    def _determine_priority_level(self, score: float) -> PriorityLevel:
        """确定优先级等级

        Args:
            score: 总评分

        Returns:
            优先级等级
        """
        if score >= self.config.critical_threshold:
            return PriorityLevel.CRITICAL
        elif score >= self.config.high_threshold:
            return PriorityLevel.HIGH
        elif score >= self.config.medium_threshold:
            return PriorityLevel.MEDIUM
        elif score >= self.config.low_threshold:
            return PriorityLevel.LOW
        else:
            return PriorityLevel.INFO

    def _determine_priority_tier(self, real_risk_score: float) -> str:
        if real_risk_score >= 0.7:
            return "P0"
        elif real_risk_score >= 0.5:
            return "P1"
        elif real_risk_score >= 0.3:
            return "P2"
        return "P3"

    def calculate_real_risk_score(self, finding: Dict[str, Any]) -> PriorityResult:
        cvss_base = float(finding.get("cvss_base", 5.0)) / 10.0

        exploitability = ExploitabilityCalculator.calculate(finding)
        reachability = ReachabilityCalculator.calculate(finding)
        asset_value = AssetValueCalculator.calculate(finding)

        real_risk = cvss_base * exploitability * reachability * asset_value

        exploit_level = ExploitabilityCalculator.get_level(finding)
        reach_level = ReachabilityCalculator.get_level(finding)
        asset_level = AssetValueCalculator.get_level(finding)

        factors = {
            "exploitability_level": exploit_level.label,
            "reachability_level": reach_level.label,
            "asset_value_level": asset_level.label,
            "exploitability_raw": finding.get("exploitability", ""),
            "reachability_raw": finding.get("reachability", ""),
            "asset_type_raw": finding.get("asset_type", ""),
        }

        return PriorityResult(
            real_risk_score=real_risk,
            cvss_base=cvss_base,
            exploitability=exploitability,
            reachability=reachability,
            asset_value=asset_value,
            priority_tier=self._determine_priority_tier(real_risk),
            factors=factors,
        )

    def clear_cache(self) -> None:
        """清除缓存"""
        self._score_cache.clear()

    def get_statistics(self, priorities: List[FilePriority]) -> Dict[str, Any]:
        """获取统计信息

        Args:
            priorities: 文件优先级列表

        Returns:
            统计信息字典
        """
        if not priorities:
            return {
                "total_files": 0,
                "avg_score": 0.0,
                "by_level": {},
                "top_files": [],
            }

        by_level: Dict[str, int] = {}
        for priority in priorities:
            level = priority.priority_level.value
            by_level[level] = by_level.get(level, 0) + 1

        avg_score = sum(p.total_score for p in priorities) / len(priorities)

        top_files = sorted(priorities, key=lambda p: p.total_score, reverse=True)[:5]

        return {
            "total_files": len(priorities),
            "avg_score": avg_score,
            "by_level": by_level,
            "top_files": [p.to_dict() for p in top_files],
        }


def sort_by_priority(
    findings: List[Dict[str, Any]],
    engine: Optional[FilePriorityEngine] = None,
) -> List[Dict[str, Any]]:
    """对发现结果按优先级排序

    Args:
        findings: 发现结果列表
        engine: 优先级引擎实例

    Returns:
        按优先级排序后的发现结果列表
    """
    if not findings:
        return []

    priority_engine = engine or FilePriorityEngine()

    scored_findings = []
    for finding in findings:
        result = priority_engine.calculate_real_risk_score(finding)
        finding_copy = dict(finding)
        finding_copy["priority_result"] = result
        finding_copy["real_risk_score"] = result.real_risk_score
        finding_copy["priority_tier"] = result.priority_tier
        scored_findings.append(finding_copy)

    tier_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

    return sorted(
        scored_findings,
        key=lambda f: (
            tier_order.get(f["priority_tier"], 4),
            -(f.get("real_risk_score", 0.0)),
        ),
    )
