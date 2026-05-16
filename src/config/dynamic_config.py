from dataclasses import dataclass


@dataclass
class AnalysisConfig:
    enabled: bool = True
    prefer_static: bool = False
    docker_enabled: bool = True
    docker_auto_pull: bool = True
    docker_timeout: int = 30
    osv_enabled: bool = True
    github_advisory_enabled: bool = True
    fallback_enabled: bool = True
    cache_ttl: int = 3600


def load_config(config: dict | None) -> AnalysisConfig:
    if config is None:
        return AnalysisConfig()

    return AnalysisConfig(
        enabled=config.get("enabled", True),
        prefer_static=config.get("prefer_static", False),
        docker_enabled=config.get("docker_enabled", True),
        docker_auto_pull=config.get("docker_auto_pull", True),
        docker_timeout=config.get("docker_timeout", 30),
        osv_enabled=config.get("osv_enabled", True),
        github_advisory_enabled=config.get("github_advisory_enabled", True),
        fallback_enabled=config.get("fallback_enabled", True),
        cache_ttl=config.get("cache_ttl", 3600),
    )
