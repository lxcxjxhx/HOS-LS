"""外部工具集成模块

提供与 Semgrep、CodeAudit、pip-audit、OWASP ZAP、HTTP拦截器、API安全测试、模糊测试、AI自适应调度等的集成接口
"""
from .semgrep_runner import SemgrepRunner, run_semgrep_scan
from .codeaudit_runner import CodeAuditRunner, verify_with_codeaudit
from .pip_audit_runner import PipAuditRunner, run_pip_audit
from .zap_runner import ZAPRunner, ZAPScanConfig, run_zap_scan, check_zap_status
from .http_interceptor import (
    HTTPInterceptor,
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
    SecurityTestResult,
    run_http_security_scan,
    check_interceptor_status,
)
from .api_security_tester import (
    APISecurityTester,
    RESTAPITester,
    GraphQLTester,
    OpenAPIParser,
    SecurityFinding,
    run_api_security_scan,
    check_api_security_tools,
)
from .fuzzing_engine import (
    FuzzingEngine,
    WordlistLoader,
    FuzzResult,
    DiscoveredItem,
    run_fuzzing_scan,
    check_fuzzing_tools,
)
from .ai_decision_engine import (
    AIDecisionEngine,
    LLMProvider,
    ToolsRegistry,
    TargetProfile,
    ScanStrategy,
    AnalysisReport as AIAnalysisReport,
    create_ai_decision_engine,
)
from .target_analyzer import TargetAnalyzer, TargetProfile as TATargetProfile
from .strategy_planner import StrategyPlanner, plan_scan_strategy
from .result_analyzer import (
    ResultAnalyzer,
    AggregatedFinding,
    AnalysisReport as RAAnalysisReport,
    analyze_results,
)
from .adaptive_executor import (
    AdaptiveExecutor,
    ExecutionResult,
    ProgressCallback,
    create_adaptive_executor,
)
from .ai_tool_orchestrator import (
    AIToolOrchestrator,
    ScanReport,
    create_ai_tool_orchestrator,
)

__all__ = [
    # Semgrep
    "SemgrepRunner",
    "run_semgrep_scan",
    # CodeAudit
    "CodeAuditRunner",
    "verify_with_codeaudit",
    # Pip Audit
    "PipAuditRunner",
    "run_pip_audit",
    # ZAP
    "ZAPRunner",
    "ZAPScanConfig",
    "run_zap_scan",
    "check_zap_status",
    # HTTP Interceptor
    "HTTPInterceptor",
    "HTTPRequest",
    "HTTPResponse",
    "HTTPTransaction",
    "SecurityTestResult",
    "run_http_security_scan",
    "check_interceptor_status",
    # API Security
    "APISecurityTester",
    "RESTAPITester",
    "GraphQLTester",
    "OpenAPIParser",
    "SecurityFinding",
    "run_api_security_scan",
    "check_api_security_tools",
    # Fuzzing
    "FuzzingEngine",
    "WordlistLoader",
    "FuzzResult",
    "DiscoveredItem",
    "run_fuzzing_scan",
    "check_fuzzing_tools",
    # AI Decision Engine
    "AIDecisionEngine",
    "LLMProvider",
    "ToolsRegistry",
    "TargetProfile",
    "ScanStrategy",
    "AIAnalysisReport",
    "create_ai_decision_engine",
    # Target Analyzer
    "TargetAnalyzer",
    "TATargetProfile",
    # Strategy Planner
    "StrategyPlanner",
    "plan_scan_strategy",
    # Result Analyzer
    "ResultAnalyzer",
    "AggregatedFinding",
    "RAAnalysisReport",
    "analyze_results",
    # Adaptive Executor
    "AdaptiveExecutor",
    "ExecutionResult",
    "ProgressCallback",
    "create_adaptive_executor",
    # AI Tool Orchestrator
    "AIToolOrchestrator",
    "ScanReport",
    "create_ai_tool_orchestrator",
]
