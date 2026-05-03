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


from enum import Enum


class AuditMode(Enum):
    """审计模式枚举"""
    STATIC = "static"      # 纯静态分析，不加载动态组件
    DYNAMIC = "dynamic"    # 纯动态AI红队POC测试，不进行静态扫描
    HYBRID = "hybrid"      # 静动态混合，原有行为


class AIModuleConfig(BaseModel):
    """AI 模块配置"""

    enabled: bool = Field(default=True, description="是否启用该模块")
    model: Optional[str] = Field(default=None, description="模块特定模型，None表示使用默认")
    provider: Optional[str] = Field(default=None, description="模块特定提供商，None表示使用默认")
    temperature: Optional[float] = Field(default=None, description="模块特定温度")
    max_tokens: Optional[int] = Field(default=None, description="模块特定最大token")


class AliyunConfig(BaseModel):
    """阿里云百炼配置"""

    enabled: bool = Field(default=False, description="是否启用阿里云API")
    api_key: Optional[str] = Field(default=None, description="阿里云API密钥")
    base_url: str = Field(default="https://dashscope.aliyuncs.com/compatible-mode/v1", description="阿里云API基础URL")
    model: str = Field(default="qwen3-coder-next", description="默认模型")


class TierModelConfig(BaseModel):
    """分层模型配置"""

    model: str = Field(default="", description="模型名称")
    provider: str = Field(default="deepseek", description="提供商")
    purpose: str = Field(default="", description="用途描述")


class TieredArchitectureConfig(BaseModel):
    """双层模型架构配置"""

    enabled: bool = Field(default=False, description="是否启用双层架构")
    risk_threshold: float = Field(default=0.5, description="可疑文件判定阈值")
    first_tier: TierModelConfig = Field(default_factory=lambda: TierModelConfig(
        model="deepseek-v4-flash",
        provider="deepseek",
        purpose="快速预扫描，识别可疑文件"
    ), description="第一层模型配置")
    second_tier: TierModelConfig = Field(default_factory=lambda: TierModelConfig(
        model="qwen3-coder-next",
        provider="aliyun",
        purpose="深度分析危险路径"
    ), description="第二层模型配置")


class AIConfig(BaseModel):
    """AI 配置"""

    enabled: bool = Field(default=False, description="是否启用 AI 分析")
    provider: str = Field(default="deepseek", description="默认 AI 提供商")
    model: str = Field(default="deepseek-chat", description="默认模型")
    api_key: Optional[str] = Field(default=None, description="API 密钥")
    base_url: Optional[str] = Field(default=None, description="API 基础 URL")
    temperature: float = Field(default=0.0, description="默认温度参数")
    max_tokens: int = Field(default=4096, description="最大令牌数")
    timeout: int = Field(default=60, description="超时时间（秒）")
    enable_learning: bool = Field(default=True, description="是否启用 AI 学习")

    modules: Dict[str, AIModuleConfig] = Field(default_factory=dict, description="各模块的AI配置")
    aliyun: AliyunConfig = Field(default_factory=AliyunConfig, description="阿里云配置")
    tiered_architecture: TieredArchitectureConfig = Field(default_factory=TieredArchitectureConfig, description="双层架构配置")

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        allowed = ["anthropic", "openai", "deepseek", "aliyun", "local"]
        if v not in allowed:
            raise ValueError(f"provider must be one of {allowed}")
        return v

    def get_model(self, module: str = None) -> str:
        """获取模块对应的模型，优先使用模块特定配置

        Args:
            module: 模块名称（如 'pure_ai', 'rag', 'nvd'）

        Returns:
            最终使用的模型名称
        """
        if module and module in self.modules:
            module_config = self.modules[module]
            if module_config.model:
                return module_config.model

        env_model = os.getenv("HOS_LS_AI_MODEL")
        if env_model:
            return env_model

        return self.model

    def get_provider(self, module: str = None) -> str:
        """获取模块对应的提供商

        Args:
            module: 模块名称

        Returns:
            最终使用的提供商
        """
        if module and module in self.modules:
            module_config = self.modules[module]
            if module_config.provider:
                return module_config.provider

        env_provider = os.getenv("HOS_LS_AI_PROVIDER")
        if env_provider:
            return env_provider

        return self.provider

    def get_temperature(self, module: str = None) -> float:
        """获取模块对应的温度参数"""
        if module and module in self.modules:
            module_config = self.modules[module]
            if module_config.temperature is not None:
                return module_config.temperature
        return self.temperature

    def get_max_tokens(self, module: str = None) -> int:
        """获取模块对应的最大token数"""
        if module and module in self.modules:
            module_config = self.modules[module]
            if module_config.max_tokens is not None:
                return module_config.max_tokens
        return self.max_tokens


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
    port_scan_enabled: bool = Field(default=False, description="是否启用API端口配置扫描")
    ports_only: bool = Field(default=False, description="是否仅执行端口扫描")
    port_range: str = Field(default="1-65535", description="端口扫描范围，格式: start-end")
    priority_strategy: str = Field(default="full-scan", description="扫描优先级策略: api-first, security-first, performance-first, full-scan, custom")
    priority_rules_path: str = Field(default="", description="自定义优先级规则文件路径")


class RulesConfig(BaseModel):
    """规则配置"""

    enabled: List[str] = Field(default_factory=list, description="启用的规则")
    disabled: List[str] = Field(default_factory=list, description="禁用的规则")
    ruleset: str = Field(default="default", description="规则集")
    severity_threshold: str = Field(default="low", description="严重级别阈值")
    confidence_threshold: float = Field(default=0.5, description="置信度阈值")
    poc_severity_threshold: str = Field(default="high", description="POC生成的严重级别阈值")

    @field_validator("severity_threshold", "poc_severity_threshold")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = ["critical", "high", "medium", "low", "info"]
        if v not in allowed:
            raise ValueError(f"severity threshold must be one of {allowed}")
        return v


class ReportConfig(BaseModel):
    """报告配置"""

    format: str = Field(default="html", description="报告格式")
    output: str = Field(default="./security-report", description="输出路径")
    include_code_snippets: bool = Field(default=True, description="包含代码片段")
    include_fix_suggestions: bool = Field(default=True, description="包含修复建议")
    category_filter: str = Field(default="all", description="报告分类过滤: all(全部), port-related(端口相关), general-static(一般静态), special-scan(特别扫描), api-security(API安全), auth-security(认证安全), data-protection(数据保护), config-security(配置安全)")

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
    mode: AuditMode = Field(default=AuditMode.HYBRID, description="审计模式: static(静态), dynamic(动态), hybrid(混合)")
    max_memory: int = Field(default=512 * 1024 * 1024, description="最大内存（字节）")
    max_cpu_time: int = Field(default=30, description="最大 CPU 时间（秒）")
    network_access: bool = Field(default=False, description="是否允许网络访问")
    file_system_access: bool = Field(default=False, description="是否允许文件系统访问")


class Neo4jConfig(BaseModel):
    """Neo4j 配置"""

    uri: str = Field(default="neo4j://localhost:7687", description="Neo4j URI")
    username: str = Field(default="neo4j", description="Neo4j 用户名")
    password: str = Field(default="password", description="Neo4j 密码")


class RAGHybridConfig(BaseModel):
    """RAG 混合检索配置"""
    enabled: bool = Field(default=True, description="是否启用混合检索")
    hybrid_search_weight: float = Field(default=0.7, description="混合搜索权重")
    top_k: int = Field(default=10, description="返回结果数量")


class RAGBM25Config(BaseModel):
    """RAG BM25 检索配置"""
    enabled: bool = Field(default=True, description="是否启用 BM25 检索")
    k1: float = Field(default=1.2, description="BM25 k1 参数")
    b: float = Field(default=0.75, description="BM25 b 参数")


class RAGRerankConfig(BaseModel):
    """RAG 重排序配置"""
    enabled: bool = Field(default=False, description="是否启用重排序")
    model: str = Field(default="BAAI/bge-reranker-large", description="重排序模型")


class RAGConfig(BaseModel):
    """RAG 配置"""
    hybrid: RAGHybridConfig = Field(default_factory=RAGHybridConfig)
    bm25: RAGBM25Config = Field(default_factory=RAGBM25Config)
    rerank: RAGRerankConfig = Field(default_factory=RAGRerankConfig)


class NVDConfig(BaseModel):
    """NVD漏洞数据库配置"""
    enabled: bool = Field(default=True, description="是否启用NVD漏洞数据库")
    database_path: str = Field(
        default="All Vulnerabilities/sql_data/nvd_vulnerability.db",
        description="NVD SQLite数据库路径"
    )
    min_cvss_score: float = Field(default=5.0, description="最低CVSS评分阈值")
    prefer_kev: bool = Field(default=True, description="是否优先显示已知被利用的漏洞")
    query_timeout: int = Field(default=30, description="查询超时时间（秒）")
    auto_connect: bool = Field(default=True, description="是否自动连接数据库")
    fallback_threshold: int = Field(default=10, description="数据不足时触发NVD回退的阈值")


class DataPreloadConfig(BaseModel):
    """数据预加载配置"""
    enabled: bool = Field(default=True, description="启用数据预加载检查")
    auto_update: bool = Field(default=False, description="是否自动更新（不询问）")
    update_threshold_days: int = Field(default=7, description="更新阈值（天）")
    sources_file: str = Field(
        default="All Vulnerabilities/download_source_link.txt",
        description="数据源 URL 列表文件路径"
    )
    temp_zip_dir: str = Field(
        default="All Vulnerabilities/temp_zip",
        description="压缩包缓存目录"
    )
    temp_data_dir: str = Field(
        default="All Vulnerabilities/temp_data",
        description="解压数据目录"
    )
    skip_on_checksum_match: bool = Field(
        default=True,
        description="校验和一致时跳过下载"
    )
    merge_strategy: str = Field(
        default="smart",
        description="解压合并策略: smart(智能合并) 或 overwrite(覆盖)"
    )


class SemgrepConfig(BaseModel):
    """Semgrep 工具配置"""
    enabled: bool = Field(default=True, description="是否启用 Semgrep")
    config: str = Field(default="auto", description="Semgrep 配置")
    timeout: int = Field(default=30, description="超时时间（秒）")


class TrivyConfig(BaseModel):
    """Trivy 工具配置"""
    enabled: bool = Field(default=True, description="是否启用 Trivy")
    severity: str = Field(default="HIGH,CRITICAL", description="严重级别过滤")
    timeout: int = Field(default=300, description="超时时间（秒）")


class SyftConfig(BaseModel):
    """Syft 工具配置"""
    enabled: bool = Field(default=True, description="是否启用 Syft")
    format: str = Field(default="json", description="输出格式")
    package_managers: List[str] = Field(default_factory=lambda: ["auto"], description="包管理器列表")


class GitleaksConfig(BaseModel):
    """Gitleaks 工具配置"""
    enabled: bool = Field(default=True, description="是否启用 Gitleaks")
    config: str = Field(default="", description="Gitleaks 配置文件路径")
    no_git: bool = Field(default=True, description="是否不使用 git 集成")


class ToolConfig(BaseModel):
    """工具编排配置"""
    enabled: bool = Field(default=True, description="是否启用工具编排")
    tool_chain: List[str] = Field(
        default_factory=lambda: ["semgrep", "trivy", "gitleaks", "code_vuln_scanner"],
        description="工具执行链"
    )
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    trivy: TrivyConfig = Field(default_factory=TrivyConfig)
    syft: SyftConfig = Field(default_factory=SyftConfig)
    gitleaks: GitleaksConfig = Field(default_factory=GitleaksConfig)


class PriorityWeightsConfig(BaseModel):
    """优先级权重配置"""
    cvss: float = Field(default=0.40, description="CVSS 评分权重")
    exploitability: float = Field(default=0.35, description="可利用性权重")
    reachability: float = Field(default=0.25, description="可达性权重")


class PriorityThresholdsConfig(BaseModel):
    """优先级阈值配置"""
    critical: float = Field(default=9.0, description="严重漏洞阈值")
    high: float = Field(default=7.0, description="高危漏洞阈值")
    medium: float = Field(default=4.0, description="中危漏洞阈值")


class PriorityConfig(BaseModel):
    """优先级配置"""
    enabled: bool = Field(default=True, description="是否启用优先级分析")
    weights: PriorityWeightsConfig = Field(default_factory=PriorityWeightsConfig)
    thresholds: PriorityThresholdsConfig = Field(default_factory=PriorityThresholdsConfig)


class ValidationConfig(BaseModel):
    """验证配置"""
    enabled: bool = Field(default=True, description="是否启用自动验证")
    auto_validate_high: bool = Field(default=True, description="是否自动验证高危漏洞")
    auto_validate_medium: bool = Field(default=False, description="是否自动验证中危漏洞")
    min_confidence_threshold: float = Field(default=0.7, description="最低置信度阈值")

    scanner_thresholds: Dict[str, float] = Field(
        default_factory=lambda: {
            "CodeVulnScanner": 0.6,
            "PureAIAnalyzer": 0.4,
            "SemgrepRunner": 0.5,
            "TrivyRunner": 0.5,
        },
        description="各扫描器特定的置信度阈值"
    )

    hallucination_threshold: float = Field(default=0.2, description="幻觉阈值")
    needs_review_threshold: float = Field(default=0.4, description="需审核阈值")
    enable_verification: bool = Field(default=True, description="是否启用验证流程")
    enable_fuzzy_matching: bool = Field(default=True, description="是否启用模糊CWE匹配")


class AgentConfig(BaseModel):
    """Agent 配置"""
    dynamic_selection: bool = Field(default=True, description="是否启用动态工具选择")
    skip_context_if_sufficient: bool = Field(default=True, description="当上下文充足时是否跳过")


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
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
    rag: RAGConfig = Field(default_factory=RAGConfig)
    nvd: NVDConfig = Field(default_factory=NVDConfig)
    data_preload: DataPreloadConfig = Field(default_factory=DataPreloadConfig)
    tools: ToolConfig = Field(default_factory=ToolConfig)
    priority: PriorityConfig = Field(default_factory=PriorityConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)

    # 全局配置
    debug: bool = Field(default=False, description="调试模式")
    verbose: bool = Field(default=False, description="详细输出")
    quiet: bool = Field(default=False, description="静默模式")
    config_path: Optional[str] = Field(default=None, description="配置文件路径")
    test_mode: bool = Field(default=False, description="测试模式")
    pure_ai: bool = Field(default=False, description="纯AI深度语义解析模式")
    scan_mode: str = Field(default="auto", description="扫描模式")

    # 幻觉过滤配置
    filter_hallucinations: bool = Field(default=True, description="是否过滤幻觉发现")

    # 国际化配置
    language: str = Field(default="zh", description="界面语言: zh(中文), en(英文)")

    # 截断和续传配置
    resume: bool = Field(default=False, description="从断点恢复扫描")
    truncate_output: bool = Field(default=False, description="启用截断模式")
    max_duration: int = Field(default=0, description="最大扫描时长（秒），0表示不限制")
    max_files: int = Field(default=0, description="最大扫描文件数，0表示不限制")

    @property
    def pure_ai_model(self) -> str:
        """获取 pure_ai 模块的模型（兼容属性）"""
        return self.ai.get_model("pure_ai")

    @property
    def pure_ai_provider(self) -> str:
        """获取 pure_ai 模块的提供商（兼容属性）"""
        return self.ai.get_provider("pure_ai")


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
    return ConfigManager().auto_load()
