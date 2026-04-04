"""配置管理模块

提供统一的配置管理功能，支持从文件、环境变量和命令行参数加载配置。
"""

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AIConfig(BaseModel):
    """AI 配置"""

    enabled: bool = Field(default=False, description="是否启用 AI 分析")
    provider: str = Field(default="anthropic", description="AI 提供商")
    model: str = Field(default="claude-3-5-sonnet-20241022", description="AI 模型")
    api_key: Optional[str] = Field(default=None, description="API 密钥")
    base_url: Optional[str] = Field(default=None, description="API 基础 URL")
    temperature: float = Field(default=0.0, description="温度参数")
    max_tokens: int = Field(default=4096, description="最大令牌数")
    timeout: int = Field(default=60, description="超时时间（秒）")
    enable_learning: bool = Field(default=True, description="是否启用 AI 学习")

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        allowed = ["anthropic", "openai", "deepseek", "local"]
        if v not in allowed:
            raise ValueError(f"provider must be one of {allowed}")
        return v


class ScanConfig(BaseModel):
    """扫描配置"""

    max_workers: int = Field(default=4, description="最大工作线程数")
    cache_enabled: bool = Field(default=True, description="是否启用缓存")
    incremental: bool = Field(default=True, description="是否启用增量扫描")
    timeout: int = Field(default=300, description="扫描超时时间（秒）")
    max_file_size: int = Field(default=10 * 1024 * 1024, description="最大文件大小（字节）")
    exclude_patterns: List[str] = Field(
        default_factory=lambda: [
            "*.min.js",
            "*.min.css",
            "node_modules/**",
            "__pycache__/**",
            ".git/**",
            ".venv/**",
            "venv/**",
            "dist/**",
            "build/**",
        ],
        description="排除模式",
    )
    include_patterns: List[str] = Field(
        default_factory=lambda: ["*.py", "*.js", "*.ts", "*.java", "*.cpp", "*.c", "*.h"],
        description="包含模式",
    )


class RulesConfig(BaseModel):
    """规则配置"""

    enabled: List[str] = Field(default_factory=list, description="启用的规则")
    disabled: List[str] = Field(default_factory=list, description="禁用的规则")
    ruleset: str = Field(default="default", description="规则集")
    severity_threshold: str = Field(default="low", description="严重级别阈值")
    confidence_threshold: float = Field(default=0.5, description="置信度阈值")

    @field_validator("severity_threshold")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = ["critical", "high", "medium", "low", "info"]
        if v not in allowed:
            raise ValueError(f"severity_threshold must be one of {allowed}")
        return v


class ReportConfig(BaseModel):
    """报告配置"""

    format: str = Field(default="html", description="报告格式")
    output: str = Field(default="./security-report", description="输出路径")
    include_code_snippets: bool = Field(default=True, description="包含代码片段")
    include_fix_suggestions: bool = Field(default=True, description="包含修复建议")

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        allowed = ["html", "markdown", "json", "sarif", "xml"]
        if v not in allowed:
            raise ValueError(f"format must be one of {allowed}")
        return v


class DatabaseConfig(BaseModel):
    """数据库配置"""

    url: str = Field(default="sqlite:///hos-ls.db", description="数据库 URL")
    wal_mode: bool = Field(default=True, description="是否启用 WAL 模式")
    pool_size: int = Field(default=5, description="连接池大小")
    max_overflow: int = Field(default=10, description="最大溢出连接")
    echo: bool = Field(default=False, description="是否打印 SQL")


class SandboxConfig(BaseModel):
    """沙箱配置"""

    enabled: bool = Field(default=True, description="是否启用沙箱")
    max_memory: int = Field(default=512 * 1024 * 1024, description="最大内存（字节）")
    max_cpu_time: int = Field(default=30, description="最大 CPU 时间（秒）")
    network_access: bool = Field(default=False, description="是否允许网络访问")
    file_system_access: bool = Field(default=False, description="是否允许文件系统访问")


class Config(BaseSettings):
    """HOS-LS 主配置类"""

    model_config = SettingsConfigDict(
        env_prefix="HOS_LS_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # 版本信息
    version: str = "3.0.0"

    # 子配置
    ai: AIConfig = Field(default_factory=AIConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)

    # 全局配置
    debug: bool = Field(default=False, description="调试模式")
    verbose: bool = Field(default=False, description="详细输出")
    quiet: bool = Field(default=False, description="静默模式")
    config_path: Optional[str] = Field(default=None, description="配置文件路径")


class ConfigManager:
    """配置管理器

    提供配置的加载、保存和管理功能。
    """

    _instance: Optional["ConfigManager"] = None
    _config: Optional[Config] = None
    _config_cache: Dict[str, Dict[str, Any]] = {}
    _config_mtime: Dict[str, float] = {}
    _config_write_count: int = 0

    # 默认配置路径
    DEFAULT_CONFIG_PATHS = [
        "./config/default.yaml",
        "./hos-ls.yaml",
        "./hos-ls.yml",
        "./.hos-ls.yaml",
        "./.hos-ls.yml",
        "~/.hos-ls/config.yaml",
        "~/.hos-ls/config.yml",
        "~/.config/hos-ls/config.yaml",
        "~/.config/hos-ls/config.yml",
    ]

    def __new__(cls) -> "ConfigManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._config is None:
            self._config = Config()

    @property
    def config(self) -> Config:
        """获取当前配置"""
        if self._config is None:
            self._config = Config()
        return self._config

    def load_from_file(self, path: Union[str, Path]) -> Config:
        """从文件加载配置

        Args:
            path: 配置文件路径

        Returns:
            加载的配置对象
        """
        path = Path(path).expanduser().resolve()
        path_str = str(path)

        if not path.exists():
            raise FileNotFoundError(f"配置文件不存在: {path}")

        # 检查文件是否有变更
        current_mtime = path.stat().st_mtime
        if path_str in self._config_cache and current_mtime == self._config_mtime.get(path_str):
            # 使用缓存
            data = self._config_cache[path_str]
        else:
            # 读取文件
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            # 处理环境变量
            def resolve_env_vars(obj):
                if isinstance(obj, dict):
                    return {k: resolve_env_vars(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [resolve_env_vars(item) for item in obj]
                elif isinstance(obj, str) and obj.startswith('${') and obj.endswith('}'):
                    env_var = obj[2:-1]
                    return os.getenv(env_var, obj)
                return obj
            
            data = resolve_env_vars(data)
            
            # 更新缓存
            self._config_cache[path_str] = data
            self._config_mtime[path_str] = current_mtime

        self._config = Config(**data)
        return self._config

    def load_from_env(self) -> Config:
        """从环境变量加载配置

        Returns:
            加载的配置对象
        """
        self._config = Config()
        return self._config

    def auto_load(self) -> Config:
        """自动加载配置

        按照以下顺序尝试加载配置：
        1. 环境变量 HOS_LS_CONFIG_PATH 指定的路径
        2. 默认配置路径列表

        Returns:
            加载的配置对象
        """
        # 首先尝试从环境变量加载
        env_path = os.getenv("HOS_LS_CONFIG_PATH")
        if env_path:
            return self.load_from_file(env_path)

        # 然后尝试默认路径
        for path in self.DEFAULT_CONFIG_PATHS:
            expanded_path = Path(path).expanduser()
            if expanded_path.exists():
                return self.load_from_file(expanded_path)

        # 如果都没有找到，返回默认配置
        self._config = Config()
        return self._config

    def save_to_file(self, path: Union[str, Path], config: Optional[Config] = None) -> None:
        """保存配置到文件

        Args:
            path: 配置文件路径
            config: 要保存的配置对象，如果为 None 则保存当前配置
        """
        path = Path(path).expanduser().resolve()
        path_str = str(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if config is None:
            config = self._config or Config()

        # 创建备份
        self._create_backup(path)

        # 写入文件
        data = config.model_dump()
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

        # 更新缓存
        self._config_cache[path_str] = data
        self._config_mtime[path_str] = path.stat().st_mtime
        self._config_write_count += 1

    def _create_backup(self, path: Path) -> None:
        """创建配置文件备份

        Args:
            path: 配置文件路径
        """
        if not path.exists():
            return

        # 备份目录
        backup_dir = path.parent / ".backups"
        backup_dir.mkdir(exist_ok=True)

        # 备份文件名
        timestamp = int(time.time() * 1000)
        backup_path = backup_dir / f"{path.name}.backup.{timestamp}"

        # 复制文件
        import shutil
        shutil.copy2(path, backup_path)

        # 清理旧备份，保留最近 5 个
        backups = sorted(backup_dir.glob(f"{path.name}.backup.*"), key=lambda x: x.name, reverse=True)
        for old_backup in backups[5:]:
            old_backup.unlink(missing_ok=True)

    def reset(self) -> None:
        """重置配置为默认值"""
        self._config = Config()

    def update(self, **kwargs: Any) -> Config:
        """更新配置

        Args:
            **kwargs: 要更新的配置项

        Returns:
            更新后的配置对象
        """
        if self._config is None:
            self._config = Config()

        current_dict = self._config.model_dump()
        current_dict.update(kwargs)
        self._config = Config(**current_dict)
        return self._config

    def get_write_count(self) -> int:
        """获取配置文件写入次数

        Returns:
            写入次数
        """
        return self._config_write_count

    def clear_cache(self) -> None:
        """清除配置缓存"""
        self._config_cache.clear()
        self._config_mtime.clear()


def get_config() -> Config:
    """获取全局配置实例

    Returns:
        全局配置对象
    """
    return ConfigManager().config
