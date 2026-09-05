"""安全扫描器模块

提供核心的安全扫描功能，集成文件发现、代码分析和 AI
from src.core.scan_runner import scan, scan_sync, pre_scan_cost_check, discover_files, get_location
 分析。
"""

import asyncio
import signal
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from rich.console import Console

from src.ai.models import AnalysisContext, SecurityAnalysisResult, VulnerabilityFinding
from src.core.config import Config
from src.core.engine import ScanEngine, ScanMode, ScanResult
from src.core.scanner_finding import deduplicate_findings, convert_to_finding
from src.core.types import AnalysisLevel
from src.utils.file_discovery import FileDiscoveryEngine, FileInfo
from src.utils.file_prioritizer import FilePrioritizer
from src.utils.logger import get_logger

logger = get_logger(__name__)

try:
    from src.ai.cost_estimator import get_cost_estimator
except ImportError:

    def get_cost_estimator(*args, **kwargs):
        return None


try:
    from src.ai.token_tracker import get_token_tracker
except ImportError:

    def get_token_tracker(*args, **kwargs):  # type: ignore[misc]
        return None


try:
    from src.core.scan_cache import ScanSession, get_scan_cache_manager

    SCAN_CACHE_AVAILABLE = True
except ImportError:
    SCAN_CACHE_AVAILABLE = False
    ScanSession = None  # type: ignore[misc,assignment]

console = Console()


def _token_record_to_dict(rec: Any) -> Dict[str, Any]:
    """将 TokenUsageRecord 对象转换为纯 dict（保证 JSON 报告可解析）。"""
    if rec is None:
        return {}
    if isinstance(rec, dict):
        return {
            k: (str(v) if not isinstance(v, (str, int, float, bool)) and v is not None else v)
            for k, v in rec.items()
        }
    attrs = [
        "provider",
        "model",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "duration",
        "success",
        "cached",
        "timestamp",
        "prompt",
        "response",
        "agent_name",
        "file_path",
    ]
    out: Dict[str, Any] = {}
    for attr in attrs:
        if hasattr(rec, attr):
            v = getattr(rec, attr)
            out[attr] = str(v) if not isinstance(v, (str, int, float, bool)) and v is not None else v
        else:
            out[attr] = ""
    return out


class SecurityScanner:
    """安全扫描器

    集成文件发现、代码分析和 AI 分析功能。
    """

    def __init__(self, config: Config):
        """初始化安全扫描器

        Args:
            config: 扫描配置
        """
        try:
            from src.ai.analyzer import AIAnalyzer
        except ImportError:
            AIAnalyzer = None
        try:
            from src.ai.local_semantic_analyzer import get_local_analyzer
        except ImportError:

            def get_local_analyzer(*args, **kwargs):
                return None

        try:
            from src.ai.priority_evaluator import get_ai_priority_evaluator
        except ImportError:

            def get_ai_priority_evaluator(*args, **kwargs):
                return None

        from src.analyzers.ast_analyzer import ASTAnalyzer
        from src.analyzers.cst_analyzer import CSTAnalyzer
        from src.integration.web_search import get_web_searcher
        from src.vuln_data.library_matcher import get_library_matcher

        self.config = config
        self.remote_mode = False
        self.remote_scanner: Optional[Any] = None
        self.scan_engine = ScanEngine(config)
        self.file_discovery = FileDiscoveryEngine()
        self.file_prioritizer = FilePrioritizer()  # 文件优先级评估器
        self.ast_analyzer = ASTAnalyzer()
        self.cst_analyzer = CSTAnalyzer()
        self.ai_analyzer: Optional[Any] = None
        self.local_analyzer = get_local_analyzer()  # 本地语义分析器
        self.library_matcher = get_library_matcher()  # 库匹配器
        self.priority_evaluator: Optional[Any] = None
        self.web_searcher: Optional[Any] = None

        # 扫描缓存管理初始化
        self.scan_cache_manager: Optional[Any] = None
        self.current_session: Optional[Any] = None
        self._scan_interrupted = False
        self._original_sigint_handler: Optional[Any] = None
        if SCAN_CACHE_AVAILABLE:
            try:
                self.scan_cache_manager = get_scan_cache_manager()
                if self.config.debug:
                    console.print("[dim][DEBUG] 扫描缓存管理器初始化成功[/dim]")
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 扫描缓存管理器初始化失败: {e}[/dim]")
                self.scan_cache_manager = None

        # 纯AI模式下跳过初始化可能导致模型加载的组件
        if not config.pure_ai:
            self.priority_evaluator = get_ai_priority_evaluator()  # 优先级评估器
            self.web_searcher = get_web_searcher()  # 网络搜索器

        # 初始化规则注册表（仅用于知识库检索，不加载硬编码规则）
        from src.rules.registry import get_registry

        self.rule_registry = get_registry()

        # 初始化 AST 分析器
        try:
            self.ast_analyzer.initialize()
            if self.config.debug:
                console.print("[dim][DEBUG] AST 分析器初始化成功[/dim]")
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] AST 分析器初始化失败: {e}[/dim]")

        if config.ai.enabled and not config.pure_ai:
            try:
                from src.attack.chain_analyzer import get_ai_attack_chain_builder

                self.ai_analyzer = AIAnalyzer(config)
                self.attack_chain_builder = get_ai_attack_chain_builder()
                if self.config.debug:
                    console.print("[dim][DEBUG] AI 分析器初始化成功[/dim]")
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] AI 分析器初始化失败: {e}[/dim]")

        # 初始化纯AI分析器
        self.pure_ai_analyzer = None
        self.ai_file_prioritizer = None
        if config.pure_ai:
            if self.config.debug:
                console.print("[dim][DEBUG] 开始初始化纯AI分析器[/dim]")
            try:
                from src.ai.pure_ai_analyzer import PureAIAnalyzer

                if self.config.debug:
                    console.print("[dim][DEBUG] 导入PureAIAnalyzer成功[/dim]")
                self.pure_ai_analyzer = PureAIAnalyzer(config)
                if self.config.debug:
                    console.print("[dim][DEBUG] 纯AI分析器初始化成功[/dim]")

                # 初始化AI文件优先级评估器
                try:
                    from src.utils.ai_file_prioritizer import AIFilePrioritizer

                    # 等待纯AI分析器完全初始化
                    if (
                        self.pure_ai_analyzer
                        and hasattr(self.pure_ai_analyzer, "client")
                        and self.pure_ai_analyzer.client
                    ):
                        self.ai_file_prioritizer = AIFilePrioritizer(
                            ai_client=self.pure_ai_analyzer.client, config=config
                        )
                        if self.config.debug:
                            if self.ai_file_prioritizer.enabled:
                                console.print("[dim][DEBUG] AI文件优先级评估器初始化成功并已启用[/dim]")
                            else:
                                console.print("[dim][DEBUG] AI文件优先级评估器初始化成功但未启用（客户端不可用）[/dim]")
                    else:
                        if self.config.debug:
                            console.print("[dim][DEBUG] AI文件优先级评估器未初始化：纯AI分析器客户端未就绪[/dim]")
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] AI文件优先级评估器初始化失败: {e}[/dim]")

            except Exception as e:
                console.print(f"[dim][DEBUG] 纯AI分析器初始化失败: {e}[/dim]")
                import traceback

                traceback.print_exc()

        if config.debug:
            console.print("[dim][DEBUG] 安全扫描器初始化完成，规则注册表已就绪（仅用于知识库检索）[/dim]")
            console.print("[dim][DEBUG] 本地语义分析器已启用[/dim]")
            if config.ai.enabled:
                console.print("[dim][DEBUG] 攻击链路分析器已启用[/dim]")

        self.is_vuln_lab_mode = config.scan_mode == ScanMode.VULN_LAB.value
        if self.is_vuln_lab_mode:
            console.print("[bold yellow]🎯 靶场对抗模式已启用[/bold yellow]")

        self._data_manager: Optional[Any] = None
        self.nvd_adapter: Optional[Any] = None
        self._init_nvd_adapter()
        self._init_data_manager()

        self._init_related_file_preloader()

        self.tool_orchestrator: Optional[Any] = None
        self.tool_chain_enabled = config.tools.enabled
        self.custom_tool_chain = config.tools.tool_chain if config.tools.tool_chain else None
        if self.tool_chain_enabled:
            try:
                from src.tools.orchestrator import create_orchestrator

                tool_config = {"semgrep_rules_dir": getattr(config, "semgrep_rules_dir", None)}
                self.tool_orchestrator = create_orchestrator(tool_config)
                if self.config.debug:
                    console.print("[dim][DEBUG] 工具编排器初始化成功[/dim]")
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 工具编排器初始化失败: {e}[/dim]")

        # 沙盒初始化（仅当启用且模式不是STATIC时）
        self.sandbox_enabled = False
        self.sandbox_executor = None
        self.audit_mode = None
        sandbox_config = getattr(config, "sandbox", None)

        if sandbox_config:
            from src.core.config import AuditMode

            self.audit_mode = getattr(sandbox_config, "mode", AuditMode.HYBRID)

            # STATIC模式：不加载任何动态组件
            if self.audit_mode == AuditMode.STATIC:
                if self.config.debug:
                    console.print("[dim][DEBUG] 审计模式: STATIC，跳过动态组件初始化[/dim]")
                self.sandbox_enabled = False
                return

            # DYNAMIC或HYBRID模式：加载动态组件
            if getattr(sandbox_config, "enabled", False) or self.audit_mode == AuditMode.DYNAMIC:
                try:
                    from src.sandbox.executor_pool import SandboxExecutorPool

                    sandbox_timeout = getattr(sandbox_config, "timeout", 30)
                    self.sandbox_executor = SandboxExecutorPool()
                    self.sandbox_enabled = True
                    if self.config.debug:
                        mode_str = "DYNAMIC" if self.audit_mode == AuditMode.DYNAMIC else "HYBRID"
                        console.print(
                            f"[dim][DEBUG] 沙盒执行器初始化成功，模式: {mode_str}，超时: {sandbox_timeout}s[/dim]"
                        )
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 沙盒执行器初始化失败: {e}[/dim]")

    def _init_nvd_adapter(self):
        """初始化NVD适配器"""
        if self.config.pure_ai:
            return

        try:
            from src.vuln_data.nvd_adapter import get_nvd_adapter

            self.nvd_adapter = get_nvd_adapter()
            if self.nvd_adapter.is_available():
                db_type = self.nvd_adapter.get_db_type()
                console.print(f"[cyan]📦 NVD漏洞数据库已启用 ({db_type})[/cyan]")
                if self.config.debug:
                    stats = (
                        self.nvd_adapter._query_engine.conn.get_vulnerability_stats()
                        if hasattr(self.nvd_adapter, "_query_engine")
                        and self.nvd_adapter._query_engine
                        else {}
                    )
                    if stats:
                        console.print(f"[dim][DEBUG] NVD数据库统计: {stats}[/dim]")
            else:
                console.print(
                    "[yellow][!] NVD vulnerability DB unavailable, using built-in DB[/yellow]"
                )
        except Exception as e:
            self.nvd_adapter = None
            if self.config.debug:
                console.print(f"[dim][DEBUG] NVD适配器初始化失败: {e}[/dim]")

    def _init_data_manager(self):
        """初始化漏洞数据管理器"""
        if self.config.pure_ai:
            self._data_manager = None
            return

        try:
            from src.vuln_data.vulnerability_data_manager import VulnerabilityDataManager

            self._data_manager = VulnerabilityDataManager(self.config)
            if self._data_manager:
                logger.info("漏洞数据管理器初始化成功")
                if self.config.debug:
                    console.print("[dim][DEBUG] 漏洞数据管理器初始化成功[/dim]")
        except Exception as e:
            self._data_manager = None
            if self.config.debug:
                console.print(f"[dim][DEBUG] 数据管理器初始化失败: {e}[/dim]")

    def _init_related_file_preloader(self):
        """初始化关联文件预加载器"""
        self.related_file_preloader = None
        try:
            from src.analysis.file_dependency_graph import FileDependencyGraph
            from src.core.related_file_preloader import RelatedFilePreloader

            project_root = getattr(self.config, "project_root", "") or str(Path.cwd())
            dependency_graph = FileDependencyGraph(project_root)
            self.related_file_preloader = RelatedFilePreloader(
                dependency_graph=dependency_graph, max_workers=4
            )
            if self.config.debug:
                console.print("[dim][DEBUG] 关联文件预加载器初始化成功[/dim]")
        except Exception as e:
            self.related_file_preloader = None
            if self.config.debug:
                console.print(f"[dim][DEBUG] 关联文件预加载器初始化失败: {e}[/dim]")

    def _setup_interrupt_handler(self) -> None:
        """设置中断信号处理器"""
        if self._original_sigint_handler is not None:
            return

        def interrupt_handler(signum, frame):
            console.print("\n[bold yellow][!] 检测到中断信号，正在保存扫描进度...[/bold yellow]")
            self._scan_interrupted = True
            self._save_intermediate_report()
            console.print("[bold yellow][!] 已保存中间报告，可使用 --resume 恢复扫描[/bold yellow]")
            if self._original_sigint_handler:
                self._original_sigint_handler(signum, frame)

        try:
            self._original_sigint_handler = signal.signal(signal.SIGINT, interrupt_handler)
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 无法设置中断处理器: {e}[/dim]")

    def _restore_interrupt_handler(self) -> None:
        """恢复原始中断信号处理器"""
        if self._original_sigint_handler is not None:
            try:
                signal.signal(signal.SIGINT, self._original_sigint_handler)
                self._original_sigint_handler = None
            except Exception:
                pass

    def _save_intermediate_report(self) -> None:
        """保存中间报告"""
        if not self.scan_cache_manager or not self.current_session:
            return

        try:
            self.scan_cache_manager.save_session(self.current_session)
            if self.config.debug:
                console.print("[dim][DEBUG] 已保存扫描进度到缓存[/dim]")
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 保存扫描进度失败: {e}[/dim]")

    def _start_session(self, target: str) -> Optional[str]:
        """开始新的扫描会话

        Args:
            target: 扫描目标路径

        Returns:
            session_id 或 None
        """
        if not self.scan_cache_manager:
            return None

        try:
            session = self.scan_cache_manager.create_session(
                target=target, config={"pure_ai": self.config.pure_ai}
            )
            self.current_session = session
            if self.config.debug:
                console.print(f"[dim][DEBUG] 创建扫描会话: {session.session_id}[/dim]")
            return str(session.session_id)
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 创建扫描会话失败: {e}[/dim]")
            return None

    def _end_session(self) -> None:
        """结束当前扫描会话"""
        if self.current_session and self.scan_cache_manager:
            try:
                self.scan_cache_manager.save_session(self.current_session)
            except Exception:
                pass
            self.current_session = None

    @staticmethod
    def _content_hash(file_path: str) -> str:
        """[OPT-CACHE] 文件内容哈希（批量去重用）。"""
        import hashlib

        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()[:16]
        except Exception:
            return str(file_path)

    def _save_file_result(
        self, file_path: str, vulnerabilities: List[Any], error: Optional[str] = None
    ) -> None:
        """保存单个文件的扫描结果

        Args:
            file_path: 文件路径
            vulnerabilities: 漏洞列表
            error: 错误信息
        """
        if not self.scan_cache_manager or not self.current_session:
            return

        try:
            vuln_dicts = []
            for v in vulnerabilities:
                if hasattr(v, "to_dict"):
                    try:
                        vuln_dicts.append(v.to_dict())
                    except Exception as ve:
                        console.print(f"[yellow][WARN] to_dict() 失败: {ve}[/yellow]")
                        vuln_dicts.append(
                            {
                                "rule_id": getattr(v, "rule_id", "UNKNOWN"),
                                "rule_name": getattr(
                                    v, "rule_name", getattr(v, "title", "Unknown")
                                ),
                                "description": getattr(v, "description", ""),
                                "severity": str(getattr(v, "severity", "info")).split(".")[-1],
                                "confidence": getattr(v, "confidence", 0.5),
                                "message": getattr(v, "message", getattr(v, "description", "")),
                                "code_snippet": getattr(v, "code_snippet", ""),
                                "fix_suggestion": getattr(v, "fix_suggestion", ""),
                                "location": {
                                    "file": str(
                                        getattr(getattr(v, "location", None), "file", file_path)
                                    ),
                                    "line": getattr(getattr(v, "location", None), "line", 0),
                                },
                                "metadata": getattr(v, "metadata", {}),
                            }
                        )
                elif isinstance(v, dict):
                    vuln_dicts.append(v)
                else:
                    try:
                        vuln_dicts.append(
                            {
                                "rule_id": getattr(v, "rule_id", "UNKNOWN"),
                                "rule_name": getattr(
                                    v, "rule_name", getattr(v, "title", "Unknown")
                                ),
                                "description": str(v),
                            }
                        )
                    except Exception:
                        pass

            if not vuln_dicts:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 无漏洞数据可保存: {Path(file_path).name}[/dim]")
                return

            result = self.scan_cache_manager.add_result(
                session_id=self.current_session.session_id,
                file_path=str(file_path),
                vulnerabilities=vuln_dicts,
                error=error,
            )
            if result:
                self.current_session = self.scan_cache_manager.load_session(
                    self.current_session.session_id
                )
        except Exception as e:
            console.print(f"[yellow][WARN] 保存文件结果失败: {e}[/yellow]")
            import traceback

            traceback.print_exc()

    def trigger_related_file_preload(self, file_path: str, depth: int = 2) -> None:
        """触发关联文件预加载

        Args:
            file_path: 文件路径
            depth: 预加载深度
        """
        if not self.related_file_preloader:
            return
        try:
            self.related_file_preloader.preload_related_files(file_path, depth=depth)
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 触发关联文件预加载失败: {e}[/dim]")

    def _trigger_preload_for_finding(self, finding) -> None:
        """为漏洞发现触发关联文件预加载

        Args:
            finding: 漏洞发现对象
        """
        if not self.related_file_preloader:
            return

        try:
            is_multi_file = (
                getattr(finding, "is_multi_file", False) or len(getattr(finding, "files", [])) > 1
            )

            if is_multi_file:
                files = getattr(finding, "files", [])
                for file_path in files:
                    self.trigger_related_file_preload(file_path, depth=2)
            else:
                file_path = getattr(finding, "location", None)
                if file_path and hasattr(file_path, "file"):
                    self.trigger_related_file_preload(file_path.file, depth=1)
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 触发多文件预加载失败: {e}[/dim]")

    def _apply_nvd_fallback(
        self, file_info: FileInfo, current_results: List, context_type: str = "library"
    ) -> List:
        """应用NVD回退机制补充数据

        Args:
            file_info: 文件信息
            current_results: 当前已有的分析结果
            context_type: 上下文类型 ('library' 或 'code')

        Returns:
            补充后的结果列表
        """
        if not self._data_manager:
            return current_results

        if self._data_manager.should_use_nvd_fallback(len(current_results)):
            context = {
                "type": context_type,
                "file_path": str(file_info.path),
                "libraries": [],
                "keywords": [],
            }

            if context_type == "library":
                try:
                    with open(file_info.path, "r", encoding="utf-8") as f:
                        content = f.read()

                    libraries = self.library_matcher.detect_libraries(
                        content, file_info.language.value if file_info.language else "unknown"
                    )

                    from src.vuln_data.vulnerability_data_manager import LibraryInfo

                    library_infos = []
                    for lib in libraries:
                        lib_info = LibraryInfo(name=lib.name, version=getattr(lib, "version", None))
                        library_infos.append(lib_info)

                    context["libraries"] = library_infos  # type: ignore[assignment]
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 提取库信息失败: {e}[/dim]")

            supplemented = self._data_manager.get_supplemental_data(context, current_results)

            if len(supplemented) > len(current_results):
                if self.config.debug:
                    console.print(
                        f"[dim][DEBUG] NVD回退补充了 {len(supplemented) - len(current_results)} 个结果[/dim]"
                    )

            return supplemented  # type: ignore[no-any-return]

        return current_results

    async def _tool_prescan(self, target: str) -> List:
        """执行基于工具的预扫描"""
        from src.core.scanner_tools import tool_prescan as _tool_prescan_impl

        project_root = getattr(self.config, "project_root", "") or str(
            Path(target).parent if Path(target).is_file() else Path(target)
        )

        return await _tool_prescan_impl(
            tool_orchestrator=self.tool_orchestrator,
            custom_tool_chain=self.custom_tool_chain,
            config_debug=self.config.debug,
            nvd_adapter=self.nvd_adapter if hasattr(self, "nvd_adapter") else None,
            project_root=project_root,
            target=target,
        )

    async def scan(self, target: Union[str, Path]) -> ScanResult:
        """执行异步扫描

        Args:
            target: 扫描目标

        Returns:
            扫描结果
        """
        from datetime import datetime

        # Direct API callers must receive the same fail-fast behavior as the CLI.
        if self.config.pure_ai:
            from src.ai.pure_ai.configuration import (
                PureAIConfigurationError,
                require_pure_ai_api_key,
            )

            try:
                require_pure_ai_api_key(self.config)
            except PureAIConfigurationError as exc:
                raise PureAIConfigurationError(str(exc)) from exc

        # 开始时间
        start_time = time.time()
        start_datetime = datetime.now()

        # 设置中断信号处理器
        self._setup_interrupt_handler()

        # 创建扫描会话
        session_id = self._start_session(str(target))
        if session_id and self.config.debug:
            console.print(f"[dim][DEBUG] 扫描会话已创建: {session_id}[/dim]")

        # 验证目标路径解析
        resolved_target = Path(target).resolve()
        if self.config.debug:
            console.print(f"[dim][DEBUG] 原始目标路径: {target}[/dim]")
            console.print(f"[dim][DEBUG] 解析后目标路径: {resolved_target}[/dim]")
            console.print(f"[dim][DEBUG] 目标是否存在: {resolved_target.exists()}[/dim]")
            console.print(f"[dim][DEBUG] 目标是否为目录: {resolved_target.is_dir()}[/dim]")

        console.print(
            f"[bold cyan][SCAN] Scanning target:[/bold cyan] [bold green]{target}[/bold green]"
        )
        console.print(
            f"[bold cyan][TIME] Start time:[/bold cyan] [bold]{time.strftime('%Y-%m-%d %H:%M:%S')}[/bold]"
        )

        # [COST] 运行前消费预估 + API 余额自动检查（纯 AI / AI 模式默认开启，可配置关闭）
        if not self.config.quiet:
            self._pre_scan_cost_check(str(target))

        # 纯AI模式下确保分析器已初始化；任何失败都必须中止，不能返回空 AI 结果。
        if self.config.pure_ai:
            from src.ai.pure_ai.configuration import PureAIInitializationError

            if self.pure_ai_analyzer is None:
                raise PureAIInitializationError("Pure-AI analyzer was not created")
            if not self.pure_ai_analyzer.initialized:
                console.print("[cyan]Initializing pure AI analyzer...[/cyan]")
                try:
                    await asyncio.wait_for(self.pure_ai_analyzer._initialize(), timeout=60.0)
                except asyncio.TimeoutError as exc:
                    raise PureAIInitializationError(
                        "Pure-AI analyzer initialization timed out after 60 seconds"
                    ) from exc
            if not self.pure_ai_analyzer.initialized:
                raise PureAIInitializationError("Pure-AI analyzer initialization did not complete")

        # 发现文件
        with console.status("[bold blue]... Discovering files...[/bold blue]", spinner="dots"):
            files = self._discover_files(target)
        console.print(
            f"[bold cyan][OK] Found[/bold cyan] [bold green]{len(files)}[/bold green] files"
        )

        # 分析文件
        console.print("[bold cyan][TOOL] Analyzing files...[/bold cyan]")

        # DYNAMIC模式：跳过静态分析，直接进行AI红队POC测试
        if self.audit_mode and self.audit_mode.value == "dynamic":
            if self.config.debug:
                console.print("[dim][DEBUG] DYNAMIC模式：跳过静态分析，直接进行AI红队POC测试[/dim]")
            findings = []
            analyzed_count = 0

            try:
                from src.sandbox.build_agent.containerized_build_agent import (
                    ContainerizedBuildAgent,
                )

                sandbox_config = getattr(self.config, "sandbox", None)
                if sandbox_config:
                    agent_config = {
                        "auto_pull_images": True,
                        "build_timeout": (
                            getattr(sandbox_config, "timeout", 600) if sandbox_config else 600
                        ),
                        "startup_timeout": (
                            getattr(sandbox_config, "timeout", 60) if sandbox_config else 60
                        ),
                        "build_memory_limit": "2g",
                        "runtime_memory_limit": "1g",
                        "network_name": "hos-ls-network",
                    }

                    if self.config.debug:
                        console.print("[dim][DEBUG] 初始化ContainerizedBuildAgent...[/dim]")

                    agent = ContainerizedBuildAgent(project_root=target, config=agent_config)

                    if not agent.is_docker_available():
                        if self.config.debug:
                            console.print("[dim][DEBUG] Docker不可用，使用本地构建fallback...[/dim]")
                        console.print("[bold yellow][WARN] Docker不可用，尝试本地构建...[/bold yellow]")
                        findings = await self._fallback_local_build(agent, str(target))
                    else:
                        if self.config.debug:
                            console.print("[dim][DEBUG] Docker可用，执行容器化构建...[/dim]")

                        console.print("[bold cyan][TOOL] 执行容器化项目构建...[/bold cyan]")
                        result = agent.run_full_pipeline(skip_build=False, skip_runtime=False)

                        if result.status.value == "completed":
                            console.print("[bold green][OK] 项目构建并启动成功[/bold green]")
                            if result.runtime_info:
                                base_url = result.runtime_info.base_url
                                console.print(f"[bold cyan][INFO] 服务运行地址: {base_url}[/bold cyan]")

                                if self.config.debug:
                                    console.print("[dim][DEBUG] 开始动态POC测试...[/dim]")

                                from src.sandbox.build_agent.dynamic_tester import DynamicTester

                                tester = DynamicTester(base_url=base_url, timeout=10)

                                console.print("[bold cyan][TOOL] 发现API端点...[/bold cyan]")
                                endpoints = tester.discover_endpoints()
                                console.print(
                                    f"[bold cyan][OK] 发现 {len(endpoints)} 个端点[/bold cyan]"
                                )

                                if endpoints:
                                    console.print("[bold cyan][TOOL] 执行动态漏洞测试...[/bold cyan]")
                                    test_report = tester.run_full_test(endpoints)

                                    console.print("[bold cyan][OK] 动态测试完成[/bold cyan]")
                                    console.print(
                                        f"[bold cyan]  - 总测试数: {test_report.total_tests}[/bold cyan]"
                                    )
                                    console.print(
                                        f"[bold cyan]  - 发现漏洞: {test_report.vulnerabilities_found}[/bold cyan]"
                                    )

                                    for test in test_report.tests:
                                        if test.result.value == "vulnerable":
                                            findings.append(
                                                {
                                                    "file": test.endpoint,
                                                    "line": 0,
                                                    "rule_name": test.vuln_type,
                                                    "severity": "high",
                                                    "confidence": test.confidence,
                                                    "message": f"动态测试发现{test.vuln_type}漏洞",
                                                    "evidence": test.evidence or test.payload,
                                                    "dynamic_test": True,
                                                }
                                            )
                        else:
                            console.print(
                                f"[bold red][ERROR] 构建失败: {result.error_message}[/bold red]"
                            )
                            console.print("[bold yellow][WARN] 回退到本地分析...[/bold yellow]")
                            findings = await self._fallback_local_build(agent, str(target))
                else:
                    console.print("[bold yellow][WARN] 沙盒未配置，跳过动态测试[/bold yellow]")

            except ImportError as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 导入错误: {e}[/dim]")
                console.print(f"[bold yellow][WARN] 动态测试组件不可用: {e}[/bold yellow]")
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 动态测试错误: {e}[/dim]")
                console.print(f"[bold yellow][WARN] 动态测试执行失败: {e}[/bold yellow]")

            console.print("[bold cyan][OK] DYNAMIC模式完成[/bold cyan]")
        else:
            # STATIC或HYBRID模式：执行静态分析
            findings, analyzed_count = await self._analyze_files(files)
            console.print(
                f"[bold cyan][OK] Found[/bold cyan] [bold red]{len(findings)}[/bold red] security issues"
            )

            # 沙盒动态验证（HYBRID模式且启用时）
            if (
                self.sandbox_enabled
                and self.audit_mode
                and self.audit_mode.value == "hybrid"
                and findings
            ):
                try:
                    from src.sandbox.dynamic_analyzer import DynamicAnalyzer

                    sandbox_config = getattr(self.config, "sandbox", None)
                    dynamic_timeout = (
                        getattr(sandbox_config, "timeout", 30) if sandbox_config else 30
                    )
                    dynamic_analyzer = DynamicAnalyzer(timeout=dynamic_timeout)

                    high_critical_findings = [
                        f
                        for f in findings
                        if hasattr(f, "severity") and f.severity in ["critical", "high"]
                    ]
                    if high_critical_findings and self.config.debug:
                        console.print(
                            f"[dim][DEBUG] 沙盒验证 {len(high_critical_findings)} 个高危漏洞...[/dim]"
                        )

                    for finding in high_critical_findings:
                        if hasattr(finding, "language") and finding.language:
                            lang = (
                                finding.language.value
                                if hasattr(finding.language, "value")
                                else str(finding.language)
                            )
                            if hasattr(finding, "vulnerable_code") and finding.vulnerable_code:
                                try:
                                    dyn_result = dynamic_analyzer.analyze(
                                        code=finding.vulnerable_code,
                                        language=lang,
                                        vuln_type=getattr(finding, "rule_name", "unknown"),
                                    )
                                    if dyn_result and self.config.debug:
                                        console.print(
                                            f"[dim][DEBUG] 沙盒验证结果: {dyn_result.get('is_exploitable', 'unknown')}[/dim]"
                                        )
                                except Exception as e:
                                    if self.config.debug:
                                        console.print(f"[dim][DEBUG] 沙盒验证失败: {e}[/dim]")
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 沙盒动态验证初始化失败: {e}[/dim]")

        # 创建结果对象（暂时不设置end_time，在最后再设置）
        from src.core.engine import ScanStatus

        result = ScanResult(
            target=str(target), status=ScanStatus.COMPLETED, start_time=start_datetime
        )
        result.metadata["total_files"] = analyzed_count

        # 纯AI模式：跳过所有后处理步骤，直接汇总结果
        if self.config.pure_ai:
            if self.config.debug:
                console.print("[dim][DEBUG] 纯AI模式：跳过所有后处理步骤[/dim]")

            # 直接汇总结果
            console.print("[bold cyan][INFO] Summarizing results...[/bold cyan]")
            from src.core.engine import Finding, Location, Severity

            for finding in findings:
                if not hasattr(finding, "rule_id") or not hasattr(finding, "confidence"):
                    print(f"[WARN] 跳过无效的finding对象: {type(finding)}")
                    continue
                confidence_val = getattr(finding, "confidence", 0.5)
                if confidence_val < 0.3:
                    print(
                        f"[DEBUG] 跳过极低置信度漏洞: {getattr(finding, 'rule_name', 'unknown')}, 置信度: {confidence_val:.4f}"
                    )
                    continue
                # Convert VulnerabilityFinding to Finding
                if hasattr(finding, "severity") and isinstance(finding.severity, str):
                    # Map string severity to Severity enum
                    severity_map = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                        "info": Severity.INFO,
                    }
                    severity = severity_map.get(finding.severity.lower(), Severity.INFO)
                else:
                    severity = Severity.INFO

                # Create Finding object
                def _get_location(obj, default_file="unknown"):
                    """安全获取 location 属性"""
                    if hasattr(obj, "file"):
                        return (
                            obj.file,
                            getattr(obj, "line", 0),
                            getattr(obj, "column", 0),
                            getattr(obj, "end_line", 0),
                        )
                    elif isinstance(obj, dict):
                        return (
                            obj.get("file", default_file),
                            obj.get("line", 0),
                            obj.get("column", 0),
                            obj.get("end_line", 0),
                        )
                    else:
                        return default_file, 0, 0, 0

                loc_file, loc_line, loc_col, loc_end_line = _get_location(finding.location)

                from src.core.engine import extract_code_context

                code_context = (
                    extract_code_context(loc_file, loc_line, end_line=loc_end_line)
                    if loc_file != "unknown"
                    else None
                )

                finding_obj = Finding(
                    rule_id=finding.rule_id,
                    rule_name=finding.rule_name,
                    description=finding.description,
                    severity=severity,
                    location=Location(
                        file=loc_file,
                        line=loc_line,
                        column=loc_col,
                        end_line=loc_end_line if loc_end_line > loc_line else 0,
                    ),
                    confidence=confidence_val,
                    message=finding.description,
                    fix_suggestion=getattr(finding, "fix_suggestion", ""),
                    metadata=getattr(finding, "metadata", {}),
                    code_context=code_context,
                    status=(
                        getattr(finding, "status", "")
                        or (getattr(finding, "metadata", {}) or {}).get("status", "")
                        or (getattr(finding, "metadata", {}) or {}).get("signal_state", "")
                    ),
                )
                result.add_finding(finding_obj)

            # 添加调试日志
            if (
                hasattr(self, "pure_ai_analyzer")
                and self.pure_ai_analyzer
                and hasattr(self.pure_ai_analyzer, "debug_logs")
            ):
                result.debug_logs = self.pure_ai_analyzer.debug_logs

            # 添加Token使用记录（转为纯 dict，保证 JSON 报告可解析）
            if hasattr(self, "pure_ai_analyzer") and self.pure_ai_analyzer:
                token_tracker = (
                    self.pure_ai_analyzer.pipeline.token_tracker
                    if hasattr(self.pure_ai_analyzer, "pipeline") and self.pure_ai_analyzer.pipeline
                    else None
                )
                if token_tracker:
                    result.token_records = [
                        _token_record_to_dict(rec) for rec in token_tracker._token_usage[-100:]
                    ]
                    # 响应缓存命中统计（M6）
                    try:
                        cache_stats = token_tracker.get_cache_stats()
                        if isinstance(result.metadata, dict):
                            result.metadata["llm_cache_stats"] = cache_stats
                    except Exception:
                        pass

        else:
            # 正常模式：执行所有后处理步骤
            # 漏洞优先级评估
            console.print("[bold cyan][INFO] Evaluating vulnerability priority...[/bold cyan]")
            prioritized_findings = self._prioritize_findings(findings, files)

            # 执行多文件漏洞关联分析
            if not self.config.pure_ai:
                console.print(
                    "[bold cyan][INFO] Analyzing cross-file vulnerabilities...[/bold cyan]"
                )
                prioritized_findings = self._analyze_cross_file_vulnerabilities(
                    prioritized_findings, files
                )

            # 汇总结果
            console.print("[bold cyan][INFO] Summarizing results...[/bold cyan]")
            for finding in prioritized_findings:
                result.add_finding(finding)
                self._trigger_preload_for_finding(finding)

            # 执行攻击链路分析（如果启用了AI且不是纯AI模式）
            if (
                self.config.ai.enabled
                and not self.config.pure_ai
                and getattr(self, "attack_chain_builder", None) is not None
                and result.findings
            ):
                if self.config.debug:
                    console.print("[dim][DEBUG] 开始执行攻击链路分析[/dim]")

                try:
                    # 转换ScanResult为SecurityAnalysisResult
                    ai_findings = []
                    for finding in result.findings:
                        # 创建VulnerabilityFinding对象
                        # 处理 severity 可能是字符串或枚举对象的情况
                        if hasattr(finding.severity, "name"):
                            severity_value = finding.severity.name.lower()
                        else:
                            severity_value = str(finding.severity).lower()
                        vuln_finding = VulnerabilityFinding(
                            rule_id=finding.rule_id,
                            rule_name=finding.rule_name,
                            description=finding.description,
                            severity=severity_value,
                            confidence=finding.confidence,
                            location={
                                "file": finding.location.file,
                                "line": finding.location.line,
                                "column": finding.location.column,
                            },
                            code_snippet=finding.code_snippet,
                            fix_suggestion=finding.fix_suggestion,
                            explanation=finding.message,
                            references=finding.references,
                            exploit_scenario="",
                        )
                        ai_findings.append(vuln_finding)

                    # 创建SecurityAnalysisResult
                    security_result = SecurityAnalysisResult(
                        findings=ai_findings,
                        risk_score=0.0,
                        summary=f"Found {len(ai_findings)} potential issues",
                        recommendations=[],
                        metadata={},
                    )

                    # 执行攻击链路分析
                    attack_chain_result = await self.attack_chain_builder.build_attack_chains(
                        security_result
                    )

                    # 生成可视化数据
                    visualization_data = self.attack_chain_builder.get_visualization_data(
                        attack_chain_result
                    )

                    # 将攻击链路分析结果添加到ScanResult中
                    result.metadata["attack_chain"] = {
                        "summary": attack_chain_result.summary,
                        "risk_score": attack_chain_result.risk_score,
                        "paths": attack_chain_result.paths,
                        "visualization": visualization_data,
                    }

                    if self.config.debug:
                        console.print(
                            f"[dim][DEBUG] 攻击链路分析完成，识别出 {len(attack_chain_result.paths)} 条攻击路径[/dim]"
                        )
                        console.print(
                            f"[dim][DEBUG] 总体风险评分: {attack_chain_result.risk_score:.2f}[/dim]"
                        )
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 攻击链路分析失败: {e}[/dim]")

            # 执行本地攻击链分析（纯AI模式下跳过）
            if result.findings and not self.config.pure_ai:
                if self.config.debug:
                    console.print("[dim][DEBUG] 开始执行本地攻击链分析[/dim]")

                try:
                    from src.core.attack_chain_analyzer import AttackChainAnalyzer
                    from src.core.result_aggregator import AggregatedFinding

                    # 转换为AggregatedFinding
                    aggregated_findings = []
                    for finding in result.findings:
                        # 简化的AggregatedFinding创建
                        agg_finding = AggregatedFinding(
                            rule_id=finding.rule_id,
                            rule_name=finding.rule_name,
                            description=finding.description,
                            severity=finding.severity,  # type: ignore[arg-type]
                            file_path=finding.location.file,
                            line=finding.location.line,
                            column=finding.location.column,
                            confidence=finding.confidence,
                            message=finding.message,
                            code_snippet=finding.code_snippet,
                            fix_suggestion=finding.fix_suggestion,
                            references=finding.references,
                            metadata=finding.metadata,
                        )
                        aggregated_findings.append(agg_finding)

                    # 执行攻击链分析
                    analyzer = AttackChainAnalyzer()  # type: ignore[call-arg]
                    chain_result = analyzer.analyze(aggregated_findings)  # type: ignore[attr-defined]

                    # 将攻击链分析结果添加到ScanResult中
                    result.metadata["local_attack_chain"] = {
                        "summary": chain_result.summary,
                        "critical_chains": [
                            {
                                "description": chain.description,
                                "risk_level": chain.risk_level,
                                "status": chain.status,
                                "steps": [
                                    {
                                        "rule_name": step.finding.rule_name,
                                        "description": step.description,
                                    }
                                    for step in chain.steps
                                ],
                            }
                            for chain in chain_result.critical_chains
                        ],
                    }

                    if self.config.debug:
                        console.print(
                            f"[dim][DEBUG] 本地攻击链分析完成，识别出 {len(chain_result.critical_chains)} 条关键攻击链[/dim]"
                        )
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 本地攻击链分析失败: {e}[/dim]")

            # 执行漏洞优先级评估（如果启用了AI且不是纯AI模式）
            if self.config.ai.enabled and self.priority_evaluator is not None and result.findings:
                if self.config.debug:
                    console.print("[dim][DEBUG] 开始执行漏洞优先级评估[/dim]")

                try:
                    # 转换ScanResult为SecurityAnalysisResult
                    ai_findings = []
                    for finding in result.findings:
                        # 创建VulnerabilityFinding对象
                        # 处理 severity 可能是字符串或枚举对象的情况
                        if hasattr(finding.severity, "name"):
                            severity_value = finding.severity.name.lower()
                        else:
                            severity_value = str(finding.severity).lower()
                        vuln_finding = VulnerabilityFinding(
                            rule_id=finding.rule_id,
                            rule_name=finding.rule_name,
                            description=finding.description,
                            severity=severity_value,
                            confidence=finding.confidence,
                            location={
                                "file": finding.location.file,
                                "line": finding.location.line,
                                "column": finding.location.column,
                            },
                            code_snippet=finding.code_snippet,
                            fix_suggestion=finding.fix_suggestion,
                            explanation=finding.message,
                            references=finding.references,
                            exploit_scenario="",
                        )
                        ai_findings.append(vuln_finding)

                    # 创建SecurityAnalysisResult
                    security_result = SecurityAnalysisResult(
                        findings=ai_findings,
                        risk_score=0.0,
                        summary=f"Found {len(ai_findings)} potential issues",
                        recommendations=[],
                        metadata={},
                    )

                    # 执行优先级评估
                    priority_result = await self.priority_evaluator.prioritize_findings(
                        security_result,
                        AnalysisContext(
                            file_path=str(target), code_content="", language="python"  # 默认语言
                        ),
                    )

                    # 将优先级评估结果添加到ScanResult中
                    result.metadata["priority_analysis"] = {
                        "summary": priority_result.summary,
                        "priority_distribution": priority_result.metadata.get(
                            "priority_distribution", {}
                        ),
                        "prioritized_findings": [
                            finding.rule_name for finding in priority_result.prioritized_findings
                        ],
                    }

                    if self.config.debug:
                        console.print("[dim][DEBUG] 优先级评估完成[/dim]")
                        console.print(f"[dim][DEBUG] {priority_result.summary}[/dim]")
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 优先级评估失败: {e}[/dim]")

            # 集成 LangGraph 深度分析（如果启用了 AI 且发现了漏洞，纯AI模式下跳过）
            if self.config.ai.enabled and not self.config.pure_ai and result.findings:
                try:
                    print("🔍 开始执行 LangGraph 深度分析")
                    print("🚀 启动多Agent安全分析流程")

                    # 导入 LangGraph 流程
                    from src.core.langgraph_flow import run_scan

                    # 执行 LangGraph 扫描
                    langgraph_result = await run_scan(str(target), self.config)

                    if langgraph_result and langgraph_result.findings:
                        print(
                            f"[green]OK[/green] LangGraph deep analysis found {len(langgraph_result.findings)} issues"
                        )

                        # 检查是否已经有 LangGraph 深度分析的结果
                        has_langgraph_finding = any(
                            finding.rule_id == "LANGGRAPH-ANALYSIS" for finding in result.findings
                        )

                        # 如果没有，将 LangGraph 分析结果添加到最终结果中
                        if not has_langgraph_finding:
                            for finding in langgraph_result.findings:
                                result.add_finding(finding)

                            # 添加 LangGraph 分析元数据
                            if hasattr(langgraph_result, "metadata"):
                                result.metadata["langgraph_analysis"] = langgraph_result.metadata
                        else:
                            print(
                                "[yellow]! LangGraph analysis result already exists, skipping duplicate[/yellow]"
                            )

                    print("[green]OK[/green] LangGraph deep analysis completed")
                    print(
                        "[cyan]INFO[/cyan] CREWAI multi-expert analysis integrated into scan results"
                    )

                except Exception as e:
                    print(f"[red]X[/red] LangGraph deep analysis failed: {e}")

            # 集成自学习机制
            if self.config.ai.enabled and not self.config.pure_ai:
                try:
                    try:
                        from src.storage.rag_knowledge_base import get_rag_knowledge_base
                    except ImportError:
                        from src.ai.pure_ai.rag.knowledge_base import get_rag_knowledge_base
                    try:
                        from src.learning.self_learning import Knowledge  # noqa: F401
                        from src.learning.self_learning import KnowledgeType  # noqa: F401
                    except ImportError:
                        pass

                    # 获取 RAG 知识库实例
                    rag_kb = get_rag_knowledge_base()

                    # 转换扫描结果为 RAG 知识库所需格式
                    learning_results = []
                    for finding in result.findings:
                        # 过滤掉 LangGraph 深度分析的结果，避免重复判断
                        if finding.rule_id == "LANGGRAPH-ANALYSIS":
                            continue

                        # 创建知识内容
                        content = f"{finding.rule_name}: {finding.description}\n\n严重级别: {finding.severity}\n置信度: {finding.confidence}\n\n修复建议: {finding.fix_suggestion}"

                        learning_results.append(
                            {
                                "content": content,
                                "knowledge_type": "ai_learning",
                                "source": "auto_learning",
                                "confidence": finding.confidence,
                                "tags": [finding.severity, finding.rule_name],
                                "metadata": {
                                    "rule_id": finding.rule_id,
                                    "file_path": finding.location.file,
                                    "line": finding.location.line,
                                    "code_snippet": finding.code_snippet,
                                },
                            }
                        )

                    # 自动记录学习结果到 RAG 知识库
                    rag_kb.auto_record_learning(learning_results)

                    if self.config.debug:
                        console.print("[dim][DEBUG] 自学习完成，已更新 RAG 知识库[/dim]")

                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 自学习集成失败: {e}[/dim]")

        # 计算扫描耗时
        end_time = time.time()
        scan_time = end_time - start_time

        # 统计不同优先级的漏洞数量
        priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in result.findings:
            try:
                # 处理 severity 可能是字符串或枚举对象的情况
                if hasattr(finding.severity, "name"):
                    severity_name = finding.severity.name.lower()
                else:
                    severity_name = str(finding.severity).lower()
                if severity_name in priority_counts:
                    priority_counts[severity_name] += 1
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 处理严重性级别失败: {e}[/dim]")
                continue

        console.print()
        console.print(
            f"[bold cyan][TIME] Scan duration:[/bold cyan] [bold]{scan_time:.2f}[/bold] seconds"
        )
        console.print("[bold cyan][OK] Scan completed[/bold cyan]")

        result.end_time = datetime.now()
        if self.config.debug:
            console.print(f"[dim][DEBUG] 扫描完成，总计发现 {len(result.findings)} 个问题[/dim]")

        if self.tool_orchestrator and self.tool_chain_enabled and not self.config.pure_ai:
            tool_stats = self.tool_orchestrator.get_statistics()
            result.metadata["tool_statistics"] = tool_stats
            if tool_stats.get("total_findings", 0) > 0:
                console.print("[bold cyan][TOOL] Tool execution statistics:[/bold cyan]")
                for tool, stats in tool_stats.get("tool_statistics", {}).items():
                    status = "[OK]" if stats.get("is_available", False) else "[X]"
                    findings_count = stats.get("findings_count", 0)
                    exec_time = stats.get("execution_time", 0)
                    console.print(f"  {status} {tool}: {findings_count} findings, {exec_time:.2f}s")

        # 添加扫描会话信息到结果元数据
        if session_id:
            result.metadata["scan_session_id"] = session_id
            result.metadata["scan_cache_path"] = (
                str(self.scan_cache_manager.cache_dir / f"{session_id}.json")
                if self.scan_cache_manager
                else None
            )
            if not self._scan_interrupted:
                console.print(f"[bold cyan][CACHE] 扫描缓存已保存: {session_id}[/bold cyan]")

        # 清理资源
        self._restore_interrupt_handler()
        self._end_session()

        return result

    def _pre_scan_cost_check(self, target: str) -> None:
        """[COST] 运行前消费预估 + API 余额自动检查。

        纯 AI / AI 模式下扫描开始前执行：
            1. 估算目标文件数与预计 token/费用（基于历史均值或默认均值 × 模型单价）；
            2. 自动查询 API 账户余额（DeepSeek /user/balance 等），余额过低时告警；
            3. 任何查询失败均不阻塞扫描（best-effort）。
        """
        try:
            from src.ai.balance import check_balance
            from src.ai.cost_estimator import get_cost_estimator

            # 余额检查（仅 AI 模式；查询失败/不可用自动跳过）
            if getattr(self.config.ai, "balance_check_enabled", True):
                try:
                    provider = (
                        self.pure_ai_analyzer.ai_provider
                        if self.pure_ai_analyzer
                        else (self.config.ai.provider or "deepseek")
                    )
                    info = check_balance(self.config, provider=provider)
                    if info.available and info.low_balance and not self.config.quiet:
                        console.print(
                            f"[bold red]⚠ 账户余额不足（{info.total_balance:.2f} {info.currency}），"
                            f"低于阈值 {getattr(self.config.ai, 'min_balance_cny', 5.0)} CNY，建议先充值[/bold red]"
                        )
                except Exception as exc:  # pragma: no cover - 余额失败不阻塞预估
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 余额检查失败: {exc}[/dim]")

            # 运行前消费预估（默认开启；pure_ai 单文件不重复估算）
            if getattr(self.config.ai, "cost_estimate_enabled", True) and (
                self.config.pure_ai or getattr(self.config, "scan_mode", "") == "pure-ai"
            ):
                target_path = Path(target)
                if target_path.is_dir():
                    from src.utils.file_discovery import FileDiscoveryEngine

                    engine = FileDiscoveryEngine()
                    files = engine.discover_files(str(target_path))
                    file_count = len(files)
                else:
                    file_count = 1

                if file_count > 0:
                    provider = (
                        self.pure_ai_analyzer.ai_provider
                        if self.pure_ai_analyzer
                        else (self.config.ai.provider or "deepseek")
                    )
                    model = (
                        self.pure_ai_analyzer.ai_model
                        if self.pure_ai_analyzer
                        else self.config.ai.get_model("pure_ai")
                    )
                    est = get_cost_estimator().estimate(file_count, provider, model)
                    console.print(
                        f"[bold yellow][COST] 预估: {file_count} 文件 × {est.avg_tokens_per_file:,} token/文件 "
                        f"≈ {est.estimated_total_tokens:,} tokens | "
                        f"≈ ${est.estimated_total_cost_usd:.4f} (¥{est.estimated_cost_cny:.2f})[/bold yellow]"
                    )
                    console.print(f"[dim]  定价来源: {est.pricing_source}[/dim]")
        except Exception as exc:  # pragma: no cover - 预估/余额检查失败不阻塞扫描
            if self.config.debug:
                console.print(f"[dim][DEBUG] 运行前成本检查跳过: {exc}[/dim]")

    def scan_sync(self, target: Union[str, Path]) -> ScanResult:
        """执行同步扫描

        Args:
            target: 扫描目标

        Returns:
            扫描结果
        """
        return asyncio.run(self.scan(target))

    def _discover_files(self, target: Union[str, Path]) -> List[FileInfo]:
        """发现文件

        Args:
            target: 扫描目标

        Returns:
            发现的文件信息列表
        """
        target_path = Path(target)

        if target_path.is_file():
            # 单个文件
            file_info = self.file_discovery.get_file_metadata(target_path)
            return [file_info]
        else:
            # 目录
            return self.file_discovery.discover_files(target_path)

    async def _fallback_local_build(self, agent, target: str) -> List:
        """本地构建fallback（当Docker不可用时）"""
        from src.core.scanner_tools import fallback_local_build as _fallback_local_build_impl

        return await _fallback_local_build_impl(
            agent=agent,
            target=target,
            config_debug=self.config.debug,
        )

    async def _analyze_files(self, files: List[FileInfo]) -> Tuple[List, int]:
        """分析文件（委托给 analyze_files.analyze_files）"""
        from src.core.analyze_files import analyze_files as _analyze_files_impl

        return await _analyze_files_impl(self, files)

    def _static_analyze(self, file_info: FileInfo) -> List:
        """静态分析文件

        Args:
            file_info: 文件信息

        Returns:
            发现的安全问题列表
        """
        findings = []

        try:
            # 读取文件内容
            with open(file_info.path, "r", encoding="utf-8") as f:
                file_content = f.read()

            # 创建分析上下文
            from src.analyzers.base import AnalysisContext

            context = AnalysisContext(
                file_path=file_info.path,
                file_content=file_content,
                language=file_info.language.value,
            )

            # 检查 AST 分析器是否初始化成功
            if not hasattr(self.ast_analyzer, "_parsers") or not self.ast_analyzer._parsers:
                if self.config.debug:
                    console.print("[dim][DEBUG] AST 分析器未初始化，可能缺少 tree-sitter 库[/dim]")
                # 尝试初始化分析器
                try:
                    self.ast_analyzer.initialize()
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 初始化 AST 分析器失败: {e}[/dim]")

            # 使用 AST 分析器
            try:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 使用 AST 分析器分析: {file_info.path}[/dim]")

                ast_result = self.ast_analyzer.analyze(context)

                if ast_result.issues:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] AST 分析发现 {len(ast_result.issues)} 个问题[/dim]")

                    for issue in ast_result.issues:
                        converted = convert_to_finding(issue)
                        if converted:
                            findings.append(converted)
                else:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] AST 分析未发现问题: {file_info.path}[/dim]")

            except Exception as e:
                error_msg = f"AST 分析失败: {e}"
                if self.config.debug:
                    console.print(f"[dim][DEBUG] {error_msg}[/dim]")
                # 添加错误信息到结果中，让用户知道静态分析失败
                from src.core.engine import Finding, Location, Severity

                error_finding = Finding(
                    rule_id="STATIC-ANALYSIS-ERROR",
                    rule_name="静态分析失败",
                    description=error_msg,
                    severity=Severity.INFO,
                    location=Location(file=str(file_info.path), line=1, column=0),
                    confidence=0.5,
                    message=error_msg,
                    code_snippet="",
                    fix_suggestion="请确保安装了 tree-sitter 相关依赖",
                    references=[],
                    metadata={"error": str(e)},
                )
                findings.append(error_finding)

            # 使用 CST 分析器（仅 Python）
            if file_info.language.value == "python":
                try:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 使用 CST 分析器分析: {file_info.path}[/dim]")

                    cst_result = self.cst_analyzer.analyze(context)

                    if cst_result.issues:
                        if self.config.debug:
                            console.print(
                                f"[dim][DEBUG] CST 分析发现 {len(cst_result.issues)} 个问题[/dim]"
                            )

                        for issue in cst_result.issues:
                            converted = convert_to_finding(issue)
                            if converted:
                                findings.append(converted)
                    else:
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] CST 分析未发现问题: {file_info.path}[/dim]")

                except Exception as e:
                    error_msg = f"CST 分析失败: {e}"
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] {error_msg}[/dim]")
                    # 添加错误信息到结果中
                    from src.core.engine import Finding, Location, Severity

                    error_finding = Finding(
                        rule_id="CST-ANALYSIS-ERROR",
                        rule_name="CST 分析失败",
                        description=error_msg,
                        severity=Severity.INFO,
                        location=Location(file=str(file_info.path), line=1, column=0),
                        confidence=0.5,
                        message=error_msg,
                        code_snippet="",
                        fix_suggestion="请确保安装了 tree-sitter 相关依赖",
                        references=[],
                        metadata={"error": str(e)},
                    )
                    findings.append(error_finding)

            # 去重静态分析结果
            findings = deduplicate_findings(findings)

        except Exception as e:
            error_msg = f"静态分析失败: {e}"
            if self.config.debug:
                console.print(f"[dim][DEBUG] {error_msg}[/dim]")
            # 添加错误信息到结果中
            from src.core.engine import Finding, Location, Severity

            error_finding = Finding(
                rule_id="STATIC-ANALYSIS-ERROR",
                rule_name="静态分析失败",
                description=error_msg,
                severity=Severity.INFO,
                location=Location(file=str(file_info.path), line=1, column=0),
                confidence=0.5,
                message=error_msg,
                code_snippet="",
                fix_suggestion="请检查文件是否可读取",
                references=[],
                metadata={"error": str(e)},
            )
            findings.append(error_finding)

        return findings

    def _rule_analyze(self, file_info: FileInfo, ai_findings: Optional[List] = None) -> List:
        """基于 RAG 知识库检索的漏洞检测"""
        from src.core.scanner_rules import rule_analyze as _rule_analyze_func

        return _rule_analyze_func(
            file_info=file_info,
            ai_findings=ai_findings,
            config_debug=self.config.debug,
            config_pure_ai=self.config.pure_ai,
        )

    def _semantic_analyze(self, file_info: FileInfo) -> List:
        """本地语义分析文件 (委托给 scanner_analyze.semantic_analyze)

        Args:
            file_info: 文件信息

        Returns:
            发现的安全问题列表
        """
        try:
            from src.core.scanner_analyze import semantic_analyze as _semantic_analyze
        except (ImportError, SyntaxError) as exc:
            logger.warning("Local semantic analysis is unavailable: %s", exc)
            return []

        return _semantic_analyze(
            file_info=file_info,
            local_analyzer=self.local_analyzer,
            config_debug=self.config.debug,
        )

    def _library_analyze(self, file_info: FileInfo) -> List:
        """库匹配分析文件

        Args:
            file_info: 文件信息

        Returns:
            发现的安全问题列表
        """
        findings = []

        try:
            # 读取文件内容
            with open(file_info.path, "r", encoding="utf-8") as f:
                code_content = f.read()

            if self.config.debug:
                console.print(f"[dim][DEBUG] 执行库匹配分析: {file_info.path}[/dim]")

            # 检测代码中使用的库
            libraries = self.library_matcher.detect_libraries(
                code_content, file_info.language.value
            )

            if libraries:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 检测到 {len(libraries)} 个库[/dim]")

                # 匹配库漏洞
                vulnerabilities = self.library_matcher.match_vulnerabilities(libraries)

                if vulnerabilities:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 发现 {len(vulnerabilities)} 个库漏洞[/dim]")

                    # 转换为 Finding 对象
                    from src.core.engine import Finding, Location, Severity

                    for vuln in vulnerabilities:
                        cvss_score = vuln.metadata.get("cvss_score", 0)
                        kev_exploited = vuln.metadata.get("kev_exploited", False)
                        exploit_count = vuln.metadata.get("exploit_count", 0)
                        poc_stars = vuln.metadata.get("poc_stars", 0)

                        severity_map = {
                            "critical": Severity.CRITICAL,
                            "high": Severity.HIGH,
                            "medium": Severity.MEDIUM,
                            "low": Severity.LOW,
                            "info": Severity.INFO,
                        }
                        severity = severity_map.get(vuln.severity, Severity.MEDIUM)

                        nvd_info = ""
                        if cvss_score > 0:
                            nvd_info = f"CVSS: {cvss_score}"
                        if kev_exploited:
                            nvd_info += " | KEV: 是"
                        if exploit_count > 0:
                            nvd_info += f" | Exploit: {exploit_count}"
                        if poc_stars > 0:
                            nvd_info += f" | PoC Stars: {poc_stars}"

                        finding = Finding(
                            rule_id=f"NVD-{vuln.cve_id}",
                            rule_name=f"库漏洞: {vuln.library_name} ({vuln.cve_id})",
                            description=vuln.description,
                            severity=severity,
                            location=Location(file=str(file_info.path), line=1, column=0),
                            confidence=min(1.0, (cvss_score or 0) / 10.0 + 0.3),
                            message=f"{vuln.library_name} 库存在漏洞 {vuln.cve_id}，受影响版本: {', '.join(vuln.affected_versions) if vuln.affected_versions else '未知'} | {nvd_info}",
                            code_snippet=(
                                code_content[:200] + "..."
                                if len(code_content) > 200
                                else code_content
                            ),
                            fix_suggestion=(
                                f"升级到版本 {vuln.fix_version}" if vuln.fix_version else "请查看官方安全公告"
                            ),
                            references=[
                                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve_id}"
                            ],
                        )
                        findings.append(finding)

        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 库匹配分析失败: {e}[/dim]")

        findings = self._apply_nvd_fallback(file_info, findings, context_type="library")

        return findings

    async def _dependency_cve_scan(self, prioritized_files: List) -> List:
        """依赖声明文件库版本CVE匹配扫描

        对pom.xml, build.gradle, package.json等依赖声明文件进行：
        1. 提取依赖库和版本
        2. 通过NVD数据库匹配已知CVE漏洞

        Args:
            prioritized_files: 优先级排序后的文件列表

        Returns:
            发现的安全问题列表
        """
        findings: list = []

        DEPENDENCY_FILES = {
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "package.json",
            "requirements.txt",
            "Pipfile",
            "Pipfile.lock",
            "Gemfile",
            "Gemfile.lock",
            "go.mod",
            "go.sum",
            "Cargo.toml",
            "composer.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
        }

        DEPENDENCY_EXTENSIONS = {".yml", ".yaml", ".properties", ".xml"}

        dependency_files = []
        for file_info, _, _ in prioritized_files:
            file_name = Path(file_info.path).name
            file_ext = Path(file_info.path).suffix.lower()

            if file_name in DEPENDENCY_FILES or file_ext in DEPENDENCY_EXTENSIONS:
                dependency_files.append(file_info)

        if not dependency_files:
            if self.config.debug:
                console.print("[dim][DEBUG] 未发现依赖声明文件，跳过库CVE匹配[/dim]")
            return findings

        if self.config.debug:
            console.print(f"[dim][DEBUG] 发现 {len(dependency_files)} 个依赖声明文件[/dim]")

        try:
            from src.vuln_data.library_matcher import get_library_matcher

            library_matcher = get_library_matcher()

            if not library_matcher._nvd_available:
                if self.config.debug:
                    console.print("[dim][DEBUG] NVD数据库不可用，跳过库CVE匹配[/dim]")
                return findings

            for file_info in dependency_files:
                try:
                    with open(file_info.path, "r", encoding="utf-8") as f:
                        content = f.read()

                    file_name = Path(file_info.path).name.lower()

                    language = "java"
                    if (
                        file_name == "package.json"
                        or file_name == "package-lock.json"
                        or file_name == "yarn.lock"
                        or file_name == "pnpm-lock.yaml"
                    ):
                        language = "javascript"
                    elif file_name in ("requirements.txt", "Pipfile", "Pipfile.lock"):
                        language = "python"
                    elif file_name in ("Gemfile", "Gemfile.lock", "composer.json"):
                        language = "ruby" if file_name.startswith("Gemfile") else "php"
                    elif file_name in ("go.mod", "go.sum"):
                        language = "go"
                    elif file_name == "Cargo.toml":
                        language = "rust"

                    libraries = library_matcher.detect_libraries(content, language)

                    if libraries:
                        if self.config.debug:
                            console.print(
                                f"[dim][DEBUG] {file_name} 检测到 {len(libraries)} 个依赖库[/dim]"
                            )

                        vulnerabilities = library_matcher.match_vulnerabilities(libraries)

                        if vulnerabilities:
                            from src.core.engine import Finding, Location, Severity

                            for vuln in vulnerabilities:
                                cvss_score = vuln.metadata.get("cvss_score", 0)
                                kev_exploited = vuln.metadata.get("kev_exploited", False)
                                exploit_count = vuln.metadata.get("exploit_count", 0)
                                poc_stars = vuln.metadata.get("poc_stars", 0)

                                severity_map = {
                                    "CRITICAL": Severity.CRITICAL,
                                    "HIGH": Severity.HIGH,
                                    "MEDIUM": Severity.MEDIUM,
                                    "LOW": Severity.LOW,
                                }
                                severity = severity_map.get(vuln.severity.upper(), Severity.MEDIUM)

                                nvd_info = f"CVSS: {cvss_score}" if cvss_score > 0 else ""
                                if kev_exploited:
                                    nvd_info += " | KEV: 已遭利用"
                                if exploit_count > 0:
                                    nvd_info += f" | Exploit: {exploit_count}"
                                if poc_stars > 0:
                                    nvd_info += f" | PoC: {poc_stars}★"

                                affected_versions_str = (
                                    ", ".join(vuln.affected_versions[:5])
                                    if vuln.affected_versions
                                    else "未知"
                                )
                                if len(vuln.affected_versions) > 5:
                                    affected_versions_str += f" 等{len(vuln.affected_versions)}个版本"

                                finding = Finding(
                                    rule_id=f"NVD-{vuln.cve_id}",
                                    rule_name=f"{vuln.library_name} 存在已知漏洞",
                                    description=f"{vuln.library_name} 版本 {vuln.affected_versions[0] if vuln.affected_versions else '未知'} 存在CVE漏洞",
                                    severity=severity,
                                    location=Location(file=str(file_info.path), line=1, column=0),
                                    confidence=min(1.0, (cvss_score or 0) / 10.0 + 0.3),
                                    message=f"{vuln.library_name} 存在 {vuln.cve_id}，受影响版本: {affected_versions_str} | {nvd_info}",
                                    code_snippet=f"检测到库: {vuln.library_name}",
                                    fix_suggestion=(
                                        f"升级到安全版本: {vuln.fix_version}"
                                        if vuln.fix_version
                                        else "请查看官方安全公告并升级"
                                    ),
                                    references=[
                                        f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve_id}"
                                    ],
                                    metadata={
                                        "source": "nvd_library_matcher",
                                        "cve_id": vuln.cve_id,
                                        "library_name": vuln.library_name,
                                        "affected_versions": vuln.affected_versions,
                                        "fix_version": vuln.fix_version,
                                        "verified": True,
                                        "cvss_score": cvss_score,
                                        "kev_exploited": kev_exploited,
                                        "exploit_count": exploit_count,
                                        "poc_stars": poc_stars,
                                    },
                                )
                                findings.append(finding)

                            console.print(
                                f"[yellow]! Found {len(vulnerabilities)} dependency vulnerabilities in {file_name} (CVSS>=5.0)[/yellow]"
                            )

                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 分析依赖文件 {file_info.path} 失败: {e}[/dim]")

        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 库CVE匹配扫描失败: {e}[/dim]")

        return findings

    async def _web_search_analyze(self, file_info: FileInfo, library_findings: List) -> List:
        """网络搜索分析

        Args:
            file_info: 文件信息
            library_findings: 库匹配分析结果

        Returns:
            发现的安全问题列表
        """
        findings = []

        try:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 执行网络搜索分析: {file_info.path}[/dim]")

            # 读取文件内容
            with open(file_info.path, "r", encoding="utf-8") as f:
                code_content = f.read()

            # 分析文件内容，提取可能的漏洞类型
            potential_vulnerabilities = self._extract_potential_vulnerabilities(
                code_content, file_info
            )

            # 对每个潜在漏洞类型进行网络搜索
            for vulnerability_type in potential_vulnerabilities:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 搜索漏洞信息: {vulnerability_type}[/dim]")

                # search_vulnerability_info is not available
                search_results: list = []

                if search_results:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 网络搜索发现 {len(search_results)} 个相关结果[/dim]")

                    # 过滤低相关性结果
                    relevant_results = [
                        result for result in search_results if result.relevance >= 0.7
                    ]

                    if relevant_results:
                        if self.config.debug:
                            console.print(
                                f"[dim][DEBUG] 过滤后保留 {len(relevant_results)} 个高相关性结果[/dim]"
                            )

                        # 转换搜索结果为 Finding 对象
                        from src.core.engine import Finding, Location, Severity

                        for result in relevant_results:
                            # 根据相关性调整严重级别
                            if result.relevance >= 0.9:
                                severity = Severity.HIGH
                            elif result.relevance >= 0.8:
                                severity = Severity.MEDIUM
                            else:
                                severity = Severity.LOW

                            finding = Finding(
                                rule_id=f"WEB-SEARCH-{vulnerability_type[:10].upper()}",
                                rule_name=f"网络搜索: {vulnerability_type}",
                                description=f"网络搜索发现相关安全信息: {result.title}",
                                severity=severity,
                                location=Location(file=str(file_info.path), line=1, column=0),
                                confidence=result.relevance,
                                message=result.snippet,
                                code_snippet=(
                                    code_content[:200] + "..."
                                    if len(code_content) > 200
                                    else code_content
                                ),
                                fix_suggestion=f"参考: {result.url}",
                                references=[result.url],
                                metadata={
                                    "search_query": vulnerability_type,
                                    "search_title": result.title,
                                    "search_url": result.url,
                                    "search_relevance": result.relevance,
                                },
                            )
                            findings.append(finding)

            # 对库漏洞进行网络搜索
            for library_finding in library_findings:
                if "LIBRARY-VULN" in library_finding.rule_id:
                    library_name = library_finding.rule_name.split(": ")[1].split(" (")[0]
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 搜索库漏洞信息: {library_name}[/dim]")

                    # search_library_info is not available
                    search_results = []

                    if search_results:
                        if self.config.debug:
                            console.print(
                                f"[dim][DEBUG] 网络搜索发现 {len(search_results)} 个库漏洞相关结果[/dim]"
                            )

                        # 过滤低相关性结果
                        relevant_results = [
                            result for result in search_results if result.relevance >= 0.7
                        ]

                        if relevant_results:
                            if self.config.debug:
                                console.print(
                                    f"[dim][DEBUG] 过滤后保留 {len(relevant_results)} 个高相关性结果[/dim]"
                                )

                            # 转换搜索结果为 Finding 对象
                            from src.core.engine import Finding, Location, Severity

                            for result in relevant_results:
                                # 根据相关性调整严重级别
                                if result.relevance >= 0.9:
                                    severity = Severity.HIGH
                                elif result.relevance >= 0.8:
                                    severity = Severity.MEDIUM
                                else:
                                    severity = Severity.LOW

                                finding = Finding(
                                    rule_id=f"WEB-SEARCH-LIBRARY-{library_name[:10].upper()}",
                                    rule_name=f"网络搜索: {library_name} 漏洞",
                                    description=f"网络搜索发现库安全信息: {result.title}",
                                    severity=severity,
                                    location=library_finding.location,
                                    confidence=result.relevance,
                                    message=result.snippet,
                                    code_snippet=library_finding.code_snippet,
                                    fix_suggestion=f"参考: {result.url}",
                                    references=[result.url],
                                    metadata={
                                        "library_name": library_name,
                                        "search_title": result.title,
                                        "search_url": result.url,
                                        "search_relevance": result.relevance,
                                    },
                                )
                                findings.append(finding)

            # 去重网络搜索结果
            unique_findings = []
            seen = set()
            for finding in findings:
                # 基于漏洞类型和URL去重
                key = (finding.rule_name, finding.references[0] if finding.references else "")
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(finding)
            findings = unique_findings

            # 限制每个文件的网络搜索结果数量
            max_findings = 5  # 减少最大结果数量，避免过多重复
            if len(findings) > max_findings:
                # 按置信度排序，保留高置信度的结果
                findings.sort(key=lambda x: x.confidence, reverse=True)
                findings = findings[:max_findings]
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 限制网络搜索结果数量为 {max_findings}[/dim]")

        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 网络搜索分析失败: {e}[/dim]")

        return findings

    def _extract_potential_vulnerabilities(
        self, code: str, file_info: Optional[FileInfo] = None
    ) -> List[str]:
        """从代码中提取潜在的漏洞类型

        Args:
            code: 代码内容
            file_info: 文件信息，用于根据文件类型过滤漏洞类型

        Returns:
            潜在漏洞类型列表
        """
        potential_vulnerabilities = []

        # 基于文件类型的漏洞类型映射
        file_type_vulnerabilities = {
            "python": [
                "command_injection",
                "hardcoded_credentials",
                "insecure_random",
                "weak_crypto",
            ],
            "javascript": ["xss", "csr", "command_injection", "hardcoded_credentials"],
            "html": ["xss", "csrf"],
            "css": [],
            "json": ["hardcoded_credentials"],
            "markdown": [],
            "txt": [],
        }

        # 基础漏洞类型模式
        vulnerability_patterns = {
            "sql_injection": ["sql", "query", "execute", "cursor", "dbapi", "psycopg2", "sqlite3"],
            "xss": [
                "html",
                "render",
                "template",
                "escape",
                "innerHTML",
                "outerHTML",
                "document.write",
            ],
            "command_injection": [
                "subprocess",
                "os.system",
                "exec",
                "eval",
                "popen",
                "spawn",
                "shell",
            ],
            "hardcoded_credentials": [
                "password",
                "api_key",
                "secret",
                "token",
                "key",
                "auth",
                "credential",
            ],
            "insecure_random": ["random", "randint", "randrange", "rand", "choice"],
            "weak_crypto": ["md5", "sha1", "des", "rc4", "3des", "md4"],
            "sensitive_data_exposure": [
                "personal",
                "credit card",
                "ssn",
                "pii",
                "private",
                "confidential",
            ],
            "csr": ["csr", "token", "session", "anti-forgery", "xsrf"],
            "ssr": ["request", "url", "fetch", "get", "post", "http", "https", "curl"],
        }

        # 根据文件类型过滤漏洞类型
        allowed_vulnerabilities = []
        if file_info and file_info.language:
            language = file_info.language.value.lower()
            allowed_vulnerabilities = file_type_vulnerabilities.get(
                language, list(vulnerability_patterns.keys())
            )
        else:
            # 对于未知类型的文件，只检查基本的漏洞类型，避免误报
            allowed_vulnerabilities = ["hardcoded_credentials"]

        code_lower = code.lower()

        # 计算代码长度，用于过滤小型文件
        code_length = len(code)

        for vuln_type, keywords in vulnerability_patterns.items():
            # 检查是否在允许的漏洞类型列表中
            if vuln_type not in allowed_vulnerabilities:
                continue

            # 增加关键词匹配阈值，减少误报
            match_count = 0
            for keyword in keywords:
                if keyword in code_lower:
                    match_count += 1

            # 根据漏洞类型设置不同的匹配阈值
            if vuln_type == "command_injection":
                # command_injection 需要至少2个关键词匹配，因为其关键词如 'exec'、'eval' 太常见
                if match_count >= 2:
                    potential_vulnerabilities.append(vuln_type)
            elif vuln_type == "hardcoded_credentials":
                # hardcoded_credentials 需要至少2个关键词匹配
                if match_count >= 2:
                    potential_vulnerabilities.append(vuln_type)
            elif code_length < 100:
                # 小型文件需要至少2个关键词匹配
                if match_count >= 2:
                    potential_vulnerabilities.append(vuln_type)
            else:
                # 正常文件需要至少1个关键词匹配
                if match_count >= 1:
                    potential_vulnerabilities.append(vuln_type)

        # 去重
        return list(set(potential_vulnerabilities))

    async def _ai_analyze(self, file_info: FileInfo) -> List:
        """AI 分析文件

        Args:
            file_info: 文件信息

        Returns:
            发现的安全问题列表
        """
        findings = []

        try:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 开始执行完整 AI 分析: {file_info.path}[/dim]")

            # 读取文件内容
            with open(file_info.path, "r", encoding="utf-8") as f:
                code_content = f.read()

            # 创建分析上下文
            context = AnalysisContext(
                file_path=str(file_info.path),
                code_content=code_content,
                language=file_info.language.value,
                analysis_level=AnalysisLevel.FILE,
            )

            if self.config.debug:
                console.print("[dim][DEBUG] 调用 AI 分析器...[/dim]")

            # 执行 AI 分析
            assert self.ai_analyzer is not None
            ai_result = await self.ai_analyzer.analyze(context)

            if self.config.debug:
                console.print(f"[dim][DEBUG] AI 分析完成，发现 {len(ai_result.findings)} 个问题[/dim]")

            # 转换 AI 结果为标准格式
            for finding in ai_result.findings:
                converted = convert_to_finding(finding)
                if converted:
                    findings.append(converted)
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] AI 发现: {converted.rule_name}[/dim]")

        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] AI 分析失败: {e}[/dim]")

        return findings

    def _prioritize_findings(self, findings: List, files: List[FileInfo]) -> List:
        """评估漏洞优先级

        Args:
            findings: 发现的漏洞列表
            files: 文件信息列表

        Returns:
            按优先级排序的漏洞列表
        """
        from src.analyzers.unified_finding_validator import UnifiedFindingValidator

        project_root = (
            getattr(self.config, "project_root", "") or str(files[0].path.parent) if files else ""
        )
        validator = UnifiedFindingValidator(project_root)

        validated_findings = []
        hallucinations_filtered = 0

        for finding in findings:
            metadata = getattr(finding, "metadata", {})
            verification_level = metadata.get("verification_level", "unknown")
            is_hallucination = metadata.get("is_hallucination", False)

            if verification_level == "unknown" and project_root:
                verification = validator.validate_finding(finding, project_root)
                verification_level = verification.get("verification_level", "unknown")
                is_hallucination = verification.get("is_hallucination", False)
                metadata["verification_level"] = verification_level
                metadata["is_hallucination"] = is_hallucination
                metadata["confidence_score"] = verification.get("confidence", 0.0)
                finding.metadata = metadata

            if is_hallucination and getattr(self.config, "filter_hallucinations", True):
                hallucinations_filtered += 1
                continue

            validated_findings.append(finding)

        if hallucinations_filtered > 0:
            console.print(f"[dim][DEBUG] 过滤了 {hallucinations_filtered} 个幻觉发现[/dim]")

        file_info_map = {file_info.path: file_info for file_info in files}

        vulnerability_priority = {
            "sql_injection": 5,
            "command_injection": 5,
            "ssrf": 4,
            "xss": 3,
            "csrf": 3,
            "hardcoded_credentials": 4,
            "weak_crypto": 4,
            "insecure_random": 3,
            "sensitive_data_exposure": 4,
        }

        file_type_priority = {
            "python": 3,
            "javascript": 3,
            "html": 2,
            "css": 1,
            "json": 2,
            "markdown": 0,
            "txt": 0,
        }

        prioritized_findings = []
        for finding in validated_findings:
            score = 0

            severity_score = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3, "INFO": 1}
            if hasattr(finding.severity, "name"):
                severity_key = finding.severity.name
            else:
                severity_key = str(finding.severity).upper()
            score += severity_score.get(severity_key, 3)

            score += finding.confidence * 2

            for vuln_type, vuln_score in vulnerability_priority.items():
                if (
                    vuln_type in finding.rule_name.lower()
                    or vuln_type in finding.description.lower()
                ):
                    score += vuln_score
                    break

            file_path = finding.location.file
            if file_path in file_info_map:
                file_info = file_info_map[file_path]
                if file_info.language:
                    file_type = file_info.language.value
                    score += file_type_priority.get(file_type, 2)

            if "AI" in finding.rule_id:
                score += 2
            elif "RAG" in finding.rule_id:
                score += 1

            verification_level = getattr(finding, "metadata", {}).get(
                "verification_level", "unknown"
            )
            verification_multiplier = 1.0
            if verification_level == "triple_verified":
                verification_multiplier = 1.2
            elif verification_level == "double_verified":
                verification_multiplier = 1.1
            elif verification_level == "needs_review":
                verification_multiplier = 0.8

            score *= verification_multiplier

            is_multi_file = (
                getattr(finding, "is_multi_file", False) or len(getattr(finding, "files", [])) > 1
            )
            if is_multi_file:
                score += 2
                if len(getattr(finding, "files", [])) > 2:
                    score += 1

            finding.metadata["priority_score"] = score
            prioritized_findings.append(finding)

        # Sort by: hallucination (asc), multi-file (desc), priority_score (desc)
        prioritized_findings.sort(
            key=lambda x: (
                x.metadata.get("is_hallucination", False),
                not (getattr(x, "is_multi_file", False) or len(getattr(x, "files", [])) > 1),
                -x.metadata.get("priority_score", 0),
            ),
        )

        return prioritized_findings

    def _analyze_cross_file_vulnerabilities(self, findings: List, files: List[FileInfo]) -> List:
        """多文件漏洞关联分析

        分析跨多个文件的漏洞信号组合，识别多文件漏洞模式，
        并为每个多文件漏洞生成攻击链和 Mermaid 图表数据。

        Args:
            findings: 发现的漏洞列表
            files: 文件信息列表

        Returns:
            添加了多文件漏洞信息的漏洞列表
        """
        if not findings:
            return findings

        try:
            from src.analysis.cross_file_analyzer import CrossFileVulnerabilityAnalyzer
            from src.analysis.file_dependency_graph import FileDependencyGraph

            project_root = str(files[0].path.parent) if files else ""

            if self.config.debug:
                console.print(f"[dim][DEBUG] 开始多文件漏洞分析, 项目根目录: {project_root}[/dim]")

            dependency_graph = FileDependencyGraph(project_root)

            for file_info in files:
                if hasattr(file_info, "content") and file_info.content:
                    dependency_graph.add_file(file_info.path, file_info.content)
                elif hasattr(file_info, "path") and Path(file_info.path).exists():
                    try:
                        with open(file_info.path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        dependency_graph.add_file(file_info.path, content)
                    except Exception as e:
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] 无法读取文件 {file_info.path}: {e}[/dim]")

            analyzer = CrossFileVulnerabilityAnalyzer(dependency_graph)
            analyzer.add_findings(findings)

            if self.config.debug:
                console.print(f"[dim][DEBUG] 发现了 {len(findings)} 个漏洞，开始跨文件分析[/dim]")

            cross_file_vulns = analyzer.analyze()

            if cross_file_vulns:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 发现 {len(cross_file_vulns)} 个跨文件漏洞[/dim]")

                finding_map = {
                    f"{f.location.file}:{f.location.line}:{f.rule_id}": f for f in findings
                }

                for cfv in cross_file_vulns:
                    main_key = f"{cfv.main_finding.file_path}:{cfv.main_finding.line}:{cfv.main_finding.rule_id}"
                    if main_key in finding_map:
                        main_finding = finding_map[main_key]
                        main_finding.files = cfv.files
                        main_finding.snippets = cfv.snippets
                        main_finding.chain = cfv.chain
                        main_finding.is_multi_file = True
                        main_finding.cross_file_vulnerability = cfv

                        if self.config.debug:
                            console.print(
                                f"[dim][DEBUG] 多文件漏洞: {cfv.vuln_id}, 文件数: {len(cfv.files)}[/dim]"
                            )

                        for step in cfv.chain:
                            if hasattr(step, "code_snippet") and step.code_snippet:
                                pass
            else:
                if self.config.debug:
                    console.print("[dim][DEBUG] 未发现跨文件漏洞[/dim]")

        except ImportError as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 多文件分析模块导入失败: {e}[/dim]")
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 多文件漏洞分析失败: {e}[/dim]")

        return findings

    def _filter_web_findings_by_ai(self, web_findings: List, ai_findings: List) -> List:
        """利用AI分析结果过滤网络搜索结果

        Args:
            web_findings: 网络搜索结果
            ai_findings: AI分析结果

        Returns:
            过滤后的网络搜索结果
        """
        if not ai_findings:
            return web_findings

        # 提取AI发现的漏洞类型
        ai_vulnerability_types = set()
        for ai_finding in ai_findings:
            # 从AI分析结果中提取漏洞类型
            for vuln_type in [
                "sql_injection",
                "command_injection",
                "ssrf",
                "xss",
                "csrf",
                "hardcoded_credentials",
                "weak_crypto",
                "insecure_random",
                "sensitive_data_exposure",
            ]:
                if (
                    vuln_type in ai_finding.rule_name.lower()
                    or vuln_type in ai_finding.description.lower()
                ):
                    ai_vulnerability_types.add(vuln_type)

        # 过滤网络搜索结果
        filtered_findings = []
        for web_finding in web_findings:
            # 检查网络搜索结果是否与AI发现的漏洞类型相关
            is_relevant = False
            for vuln_type in ai_vulnerability_types:
                if (
                    vuln_type in web_finding.rule_name.lower()
                    or vuln_type in web_finding.description.lower()
                ):
                    is_relevant = True
                    # 提高与AI发现相关的网络搜索结果的置信度
                    web_finding.confidence = min(1.0, web_finding.confidence + 0.1)
                    break

            # 如果没有AI发现的漏洞类型，保留高置信度的网络搜索结果
            if is_relevant or web_finding.confidence >= 0.8:
                filtered_findings.append(web_finding)

        return filtered_findings
