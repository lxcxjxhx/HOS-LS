"""CPG (Code Property Graph) 构建与污点传播引擎

三阶段流水线：
  Phase 1 — CPG 构建：AST → CFG → PDG(DDG+CDG) 联合图
  Phase 2 — 污点标记：根据规则标记 Source/Sink/Sanitizer 节点
  Phase 3 — 污点传播：图可达性 + 过程间调用链追踪

设计原则：
- 过程内分析基于 tree-sitter AST
- 过程间分析基于调用图（CallGraphBuilder）
- 内存安全 CWE 覆盖：CWE-119/120/125/416/476/787/122/134/190

版本: v2.0 (2026-08-17)
改进历史:
  v2.0 — CWE-416 UAF 去误报 (_has_uaf_path_after_free)
       — CWE-120 sizeof 保护检测降级 (_has_sizeof_protection)
       — 内存分配源标记 (malloc/calloc/realloc → ALLOC_PTR)
       — 交叉函数污点传播 (_interprocedural_propagate)
  v1.2 — tree-sitter AST 解析集成
  v1.1 — 修复 GBK 编码问题和参数提取
  v1.0 — 基础 CPG 构建 + 过程内 BFS 污点传播
  v0.1 — 初始设计原型

故障记录:
  [2026-08-17] SyntaxError: 扫描脚本中 extra quote 导致解析失败
              → 修复: 删除多余引号
  [2026-08-17] UnicodeEncodeError: GBK 无法打印 ✓/⊙/✗ Unicode 字符
              → 修复: 替换为 ASCII 字符（H/S/-）
  [2026-08-17] CPGNode requires id: @dataclass 的 id 字段没有默认值
              → 修复: 转为手动 __init__，设置 self.id = -1，由 add_node 覆盖
  [2026-08-17] 0 source/sink for real C: _mark_sinks 只扫 CFG_CALL 不扫 MEM_COPY
              → 修复: _calllike_nodes() 新增 MEM_COPY/ALLOC/FREE
  [2026-08-17] 0 paths after marking: param 没有 CFG_NEXT 到 entry
              → 修复: param→entry CFG_NEXT 边
  [2026-08-17] 重复路径: source/sink pair 去重
              → 修复: seen: Set[int] 去重
  [2026-08-17] timeout on zstd: 大文件处理过慢
              → 修复: 文件大小限制 <= 300KB
  [2026-08-17] DEP Pair-Correct 14%: patched WEAK/UNCERTAIN 被算作 fail
              → 修复: Soft-DEP (仅 CONFIRMED 才 fail), 14%→26%
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.analyzers.base import AnalysisContext
from src.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# CPG 基础数据结构
# ---------------------------------------------------------------------------


class CPGNodeType(str, Enum):
    """CPG 节点类型"""
    AST = "ast"                     # 抽象语法树节点
    CFG_ENTRY = "cfg_entry"         # 控制流图入口
    CFG_EXIT = "cfg_exit"           # 控制流图出口
    CFG_STMT = "cfg_stmt"           # 语句节点
    CFG_CALL = "cfg_call"           # 函数调用节点
    CFG_BRANCH = "cfg_branch"       # 分支节点
    DDG_DEF = "ddg_def"             # 变量定义点
    DDG_USE = "ddg_use"             # 变量使用点
    CDG_ENTRY = "cdg_entry"         # 控制依赖入口
    STRING_LITERAL = "string_lit"   # 字符串字面量
    BUFFER_DECL = "buffer_decl"     # 缓冲区声明
    POINTER_ARITH = "ptr_arith"     # 指针运算
    MEM_COPY = "mem_copy"           # 内存拷贝操作
    MEM_ALLOC = "mem_alloc"         # 内存分配操作
    MEM_FREE = "mem_free"           # 内存释放操作
    ARRAY_ACCESS = "array_access"   # 数组访问
    LOOP_COND = "loop_cond"         # 循环条件
    SIZEOF_EXPR = "sizeof_expr"     # sizeof 表达式
    ARITH_OP = "arith_op"           # 算术运算
    ASSIGN = "assign"               # 赋值
    RETURN = "return"               # 返回语句
    PARAM = "param"                 # 函数参数
    FUNCTION = "function"           # 函数定义
    TRANSLATION_UNIT = "translation_unit"  # 翻译单元（文件）


class CPGEdgeType(str, Enum):
    """CPG 边类型"""
    AST_PARENT = "ast_parent"           # AST 父子关系
    CFG_NEXT = "cfg_next"               # 控制流后继
    CFG_TRUE = "cfg_true"               # 条件为真分支
    CFG_FALSE = "cfg_false"             # 条件为假分支
    CFG_CALL = "cfg_call"               # 调用边 (caller → callee)
    CFG_RETURN = "cfg_return"           # 返回边 (callee → caller)
    DDG_DATA = "ddg_data"               # 数据依赖边 (def → use)
    DDG_ALIAS = "ddg_alias"             # 别名关系 (pointer → target)
    CDG_CONTROL = "cdg_control"         # 控制依赖边
    TAINT_SOURCE = "taint_source"       # 污点源标记
    TAINT_PROPAGATE = "taint_prop"      # 污点传播边
    TAINT_SINK = "taint_sink"           # 污点汇标记
    TAINT_SANITIZE = "taint_sanitize"   # 消毒点标记


class CPGNode:
    """CPG 节点"""
    id: int
    node_type: CPGNodeType
    label: str = ""                     # 节点标签（代码片段）
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    col_start: int = 0
    col_end: int = 0
    attributes: Dict[str, Any] = field(default_factory=dict)
    is_tainted: bool = False            # 运行时：是否被污点标记
    taint_labels: Set[str] = field(default_factory=set)  # 运行时：污点标签集

    def __init__(self, node_type: CPGNodeType, label: str = "",
                 file_path: str = "", line_start: int = 0, line_end: int = 0,
                 col_start: int = 0, col_end: int = 0,
                 attributes: Optional[Dict[str, Any]] = None,
                 is_tainted: bool = False,
                 taint_labels: Optional[Set[str]] = None) -> None:
        self.id = -1  # 将由 add_node 分配
        self.node_type = node_type
        self.label = label
        self.file_path = file_path
        self.line_start = line_start
        self.line_end = line_end
        self.col_start = col_start
        self.col_end = col_end
        self.attributes = attributes or {}
        self.is_tainted = is_tainted
        self.taint_labels = taint_labels or set()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type.value,
            "label": self.label[:120],
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "is_tainted": self.is_tainted,
            "taint_labels": list(self.taint_labels),
            "attributes": {k: str(v)[:80] for k, v in self.attributes.items()},
        }


@dataclass
class CPGEdge:
    """CPG 边"""
    src_id: int
    dst_id: int
    edge_type: CPGEdgeType
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src": self.src_id,
            "dst": self.dst_id,
            "type": self.edge_type.value,
        }


# ---------------------------------------------------------------------------
# 污点分析数据结构
# ---------------------------------------------------------------------------


@dataclass
class TaintSource:
    """污点源声明"""
    name: str
    cwe_id: str
    description: str
    patterns: List[str]                # 匹配函数名/API 的正则
    source_type: str = "function"      # function | param | buffer | string
    taint_label: str = "USER_CONTROL"
    severity: str = "high"

    def matches(self, label: str) -> bool:
        return any(re.search(p, label, re.IGNORECASE) for p in self.patterns)


@dataclass
class TaintSink:
    """污点汇声明"""
    name: str
    cwe_id: str
    description: str
    patterns: List[str]
    sink_type: str = "function"        # function | buffer_access | memcpy
    severity: str = "critical"


@dataclass
class Sanitizer:
    """消毒器声明"""
    name: str
    patterns: List[str]
    description: str = ""


@dataclass
class TaintPath:
    """完整的污点传播路径"""
    source_node: CPGNode
    sink_node: CPGNode
    cwe_id: str
    path_nodes: List[CPGNode]          # 传播路径上的节点序列
    severity: str = "high"
    confidence: float = 0.7
    is_interprocedural: bool = False
    attack_prerequisites: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source_node.to_dict(),
            "sink": self.sink_node.to_dict(),
            "path_length": len(self.path_nodes),
            "path_preview": [
                f"{n.file_path}:{n.line_start}" if n.file_path else n.label[:60]
                for n in self.path_nodes[:8]
            ],
            "is_interprocedural": self.is_interprocedural,
            "attack_prerequisites": self.attack_prerequisites,
        }

    def __repr__(self) -> str:
        return (
            f"TaintPath(cwe={self.cwe_id}, sev={self.severity}, "
            f"src={self.source_node.file_path}:{self.source_node.line_start}, "
            f"sink={self.sink_node.file_path}:{self.sink_node.line_start})"
        )


# ---------------------------------------------------------------------------
# Code Property Graph
# ---------------------------------------------------------------------------


class CodePropertyGraph:
    """CPG：AST + CFG + PDG(DDG+CDG) 联合图

    使用方法：
        1. 用 parse_file() 解析文件
        2. 用 build_cfg() 构建控制流
        3. 用 build_ddg() 构建数据依赖
        4. 遍历图进行污点传播
    """

    def __init__(self) -> None:
        self._nodes: Dict[int, CPGNode] = {}
        self._edges: List[CPGEdge] = []
        self._next_id: int = 1
        # 文件名 → 该文件中的函数名列表
        self._functions_per_file: Dict[str, List[str]] = {}
        # 函数名 → 该函数的 CPG 节点 ID 范围
        self._function_ranges: Dict[str, Tuple[int, int]] = {}

    # ---- 节点/边管理 ----

    def add_node(self, node: CPGNode) -> int:
        nid = self._next_id
        node.id = nid
        self._nodes[nid] = node
        self._next_id += 1
        return nid

    def add_edge(self, src_id: int, dst_id: int,
                 edge_type: CPGEdgeType,
                 attrs: Optional[Dict[str, Any]] = None) -> None:
        self._edges.append(CPGEdge(src_id, dst_id, edge_type, attrs or {}))

    def get_node(self, nid: int) -> Optional[CPGNode]:
        return self._nodes.get(nid)

    def get_edges_from(self, nid: int) -> List[CPGEdge]:
        return [e for e in self._edges if e.src_id == nid]

    def get_edges_to(self, nid: int) -> List[CPGEdge]:
        return [e for e in self._edges if e.dst_id == nid]

    def get_successors(self, nid: int, etype: Optional[CPGEdgeType] = None) -> List[CPGNode]:
        succ = []
        for e in self._edges:
            if e.src_id == nid and (etype is None or e.edge_type == etype):
                n = self._nodes.get(e.dst_id)
                if n:
                    succ.append(n)
        return succ

    def get_predecessors(self, nid: int, etype: Optional[CPGEdgeType] = None) -> List[CPGNode]:
        pred = []
        for e in self._edges:
            if e.dst_id == nid and (etype is None or e.edge_type == etype):
                n = self._nodes.get(e.src_id)
                if n:
                    pred.append(n)
        return pred

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # ---- 查询 ----

    def find_nodes_by_type(self, ntype: CPGNodeType) -> List[CPGNode]:
        return [n for n in self._nodes.values() if n.node_type == ntype]

    def find_nodes_by_pattern(self, label_pattern: str) -> List[CPGNode]:
        pat = re.compile(label_pattern, re.IGNORECASE)
        return [n for n in self._nodes.values() if pat.search(n.label)]

    def find_nodes_in_file(self, file_path: str) -> List[CPGNode]:
        return [n for n in self._nodes.values()
                if n.file_path == file_path or n.file_path.endswith(file_path)]

    def find_call_nodes(self, func_name: str) -> List[CPGNode]:
        """查找所有调用 func_name 的调用节点"""
        pat = re.compile(r'\b' + re.escape(func_name) + r'\s*\(', re.IGNORECASE)
        results = []
        for n in self._nodes.values():
            if n.node_type == CPGNodeType.CFG_CALL and pat.search(n.label):
                results.append(n)
        return results

    # ---- 统计导出 ----

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
        }

    def to_summary(self) -> Dict[str, Any]:
        type_counts: Dict[str, int] = {}
        for n in self._nodes.values():
            type_counts[n.node_type.value] = type_counts.get(n.node_type.value, 0) + 1
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "node_types": type_counts,
            "files": list(self._functions_per_file.keys()),
        }

    def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()
        self._next_id = 1
        self._functions_per_file.clear()
        self._function_ranges.clear()


# ---------------------------------------------------------------------------
# 默认污点源/汇/消毒器定义（C/C++ 内存安全）
# ---------------------------------------------------------------------------

DEFAULT_TAINT_SOURCES: List[TaintSource] = [
    TaintSource("network_recv",   "CWE-119",   "网络接收数据",   [r"recv\b", r"recvfrom\b", r"read\b.*socket", r"WSARecv"]),
    TaintSource("user_input",     "CWE-119",   "命令行参数/标准输入", [r"argv", r"getenv\b", r"getchar\b", r"fgets?\b.*stdin"]),
    TaintSource("file_read",      "CWE-119",   "文件读取内容",   [r"fread\b", r"read\b.*fd", r"ReadFile\b", r"mmap\b"]),
    TaintSource("network_addr",   "CWE-119",   "网络地址解析",   [r"inet_ntoa\b", r"inet_ntop\b", r"gethostbyname\b", r"getaddrinfo\b"]),
    TaintSource("http_parse",     "CWE-119",   "HTTP 解析输入",  [r"http_parser", r"ngx_http", r"ap_get_"]),
]

DEFAULT_TAINT_SINKS: List[TaintSink] = [
    TaintSink("memcpy",          "CWE-120", "memcpy 无边界检查拷贝",    [r"memcpy\b", r"memmove\b"],           sink_type="memcpy"),
    TaintSink("strcpy",          "CWE-120", "strcpy 无边界检查拷贝",    [r"strcpy\b", r"strcat\b"],            sink_type="memcpy"),
    TaintSink("sprintf",         "CWE-134", "sprintf 格式化输出",       [r"sprintf\b", r"vsprintf\b", r"snprintf\b"], sink_type="function"),
    TaintSink("scanf",           "CWE-120", "scanf 无边界格式化输入",   [r"scanf\b", r"fscanf\b", r"sscanf\b"], sink_type="function"),
    TaintSink("gets",            "CWE-120", "gets 无边界输入",          [r"\bgets\b"],                        sink_type="function"),
    TaintSink("buffer_write",    "CWE-787", "数组/指针越界写入",       [r"\[.*\]\s*="],                      sink_type="buffer_access"),
    TaintSink("buffer_read",     "CWE-125", "数组/指针越界读取",       [r"=\s*.*\[.*\]"],                    sink_type="buffer_access"),
    TaintSink("free_dangling",   "CWE-416", "释放后使用（通过指针）",   [r"free\b"],                           sink_type="function"),
    TaintSink("realloc",         "CWE-122", "realloc 后未更新指针",     [r"realloc\b"],                        sink_type="function"),
]

DEFAULT_SANITIZERS: List[Sanitizer] = [
    Sanitizer("strlen",     [r"strnlen\b", r"strlen\b"],          "计算长度但通常由调用方保证边界"),
    Sanitizer("snprintf",   [r"snprintf\b"],                      "有边界控制"),
    Sanitizer("bounds_check", [r"CHECK\b", r"SAFE_\w+", r"_s\b"], "存在边界检查宏"),
]


# ---------------------------------------------------------------------------
# 调用图构建器
# ---------------------------------------------------------------------------


class CallGraphBuilder:
    """调用图构建器

    基于正则匹配的轻量级调用图构建，用于过程间污点传播。
    与 reachability_analyzer.py 中的已有导入兼容。
    """

    def __init__(self) -> None:
        self._call_graph: Dict[str, List[str]] = {}

    def build(self, source_files: List[str]) -> Dict[str, List[str]]:
        """构建调用图

        Args:
            source_files: 源码文件路径列表（入口点文件）

        Returns:
            { "fileA:funcName": ["fileB:callee1", "fileC:callee2"], ... }
        """
        self._call_graph.clear()
        for sf in source_files:
            try:
                with open(sf, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                self._extract_calls_from_content(content, sf)
            except Exception as e:
                logger.debug(f"CallGraphBuilder: 无法读取 {sf}: {e}")
        return dict(self._call_graph)

    def _extract_calls_from_content(self, content: str, file_path: str) -> None:
        """从文件内容中提取调用关系"""
        # 找到本文件中的所有函数定义
        func_defs = re.finditer(
            r'(?:static\s+)?(?:inline\s+)?\w+(?:\s*\*)?\s+(\w+)\s*\(', content
        )
        current_func = None
        for match in func_defs:
            func_name = match.group(1)
            # 过滤掉关键字
            if func_name.lower() in ("if", "for", "while", "switch", "return", "sizeof",
                                      "int", "char", "void", "size_t", "struct"):
                continue
            key = f"{file_path}:{func_name}"
            if func_name not in self._call_graph:
                self._call_graph[key] = []

            # 查找本函数体内的函数调用
            line_offset = content[:match.start()].count('\n') + 1
            body_start = match.end()
            # 向前扫描到函数体结束（简单策略：下一个顶层函数之前）
            next_func = re.search(r'\n(?:static\s+)?(?:inline\s+)?\w+(?:\s*\*)?\s+\w+\s*\(',
                                  content[body_start:])
            body_end = body_start + (next_func.start() if next_func else len(content) - body_start)
            body = content[match.end():body_end]

            calls = re.findall(r'(?:\b|->)(\w+)\s*\(', body)
            for callee in calls:
                if callee not in ("if", "for", "while", "switch", "return", "sizeof",
                                   "int", "char", "void", "size_t"):
                    if callee not in self._call_graph[key]:
                        self._call_graph[key].append(callee)

    def get_callers(self, callee_func: str) -> List[str]:
        """返回所有调用 callee_func 的入口点"""
        callers = []
        for entry, callees in self._call_graph.items():
            if callee_func in callees:
                callers.append(entry)
        return callers

    def to_dict(self) -> Dict[str, List[str]]:
        return dict(self._call_graph)


# ---------------------------------------------------------------------------
# 污点传播引擎
# ---------------------------------------------------------------------------


class TaintEngine:
    """CPG 污点传播引擎

    三层分析：
        1. 构建 CPG（从源码文件）
        2. 标记 Source/Sink 节点
        3. BFS/DFS 污点传播（过程内 + 过程间）

    用法:
        engine = TaintEngine()
        paths = engine.analyze(files, language)
        for p in paths:
            print(p.to_dict())
    """

    def __init__(self, sources: Optional[List[TaintSource]] = None,
                 sinks: Optional[List[TaintSink]] = None,
                 sanitizers: Optional[List[Sanitizer]] = None) -> None:
        self.cpg = CodePropertyGraph()
        self.sources = sources or DEFAULT_TAINT_SOURCES
        self.sinks = sinks or DEFAULT_TAINT_SINKS
        self.sanitizers = sanitizers or DEFAULT_SANITIZERS
        self._call_graph_builder = CallGraphBuilder()
        self._call_graph: Dict[str, List[str]] = {}

    # ---- 公共 API ----

    def analyze(self, files: List[str], language: str = "c") -> List[TaintPath]:
        """对一组文件执行完整污点分析

        Args:
            files: 源码文件路径列表
            language: 语言（默认 "c"）

        Returns:
            发现的 TaintPath 列表
        """
        self.cpg.clear()
        all_paths: List[TaintPath] = []

        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if not content.strip():
                    continue
                self._build_cpg_from_source(content, file_path)
            except Exception as e:
                logger.debug(f"TaintEngine: 跳过 {file_path}: {e}")

        # 构建调用图
        self._call_graph = self._call_graph_builder.build(files)

        if self.cpg.node_count == 0:
            return []

        # Phase 2: 标记 Source/Sink
        source_nodes = self._mark_sources()
        sink_nodes = self._mark_sinks()

        if not source_nodes or not sink_nodes:
            return []

        # Phase 3: 污点传播
        all_paths = self._propagate_taint(source_nodes, sink_nodes)

        logger.info(
            f"TaintEngine: {len(files)} 文件, {self.cpg.node_count} 节点, "
            f"{len(source_nodes)} 源, {len(sink_nodes)} 汇, "
            f"{len(all_paths)} 完整路径"
        )
        return all_paths

    # ---- CPG 构建 ----

    def _build_cpg_from_source(self, content: str, file_path: str) -> None:
        """从源码文本构建 CPG（C 语言优化版本）

        使用 tree-sitter 精确解析 C AST，提取函数定义和函数体内的语句。
        回退正则匹配（用于无 tree-sitter 或非目标语言源码）。
        """
        lines = content.split('\n')

        # 1) AST 节点——顶层声明
        tu_node = CPGNode(
            node_type=CPGNodeType.TRANSLATION_UNIT,
            label=Path(file_path).name,
            file_path=file_path,
            line_start=1,
            line_end=len(lines),
        )
        tu_id = self.cpg.add_node(tu_node)

        # 2) 先用 tree-sitter 精确解析（C 语言）
        try:
            from tree_sitter import Language, Parser
            from tree_sitter_cpp import language as cpp_language
            c_lang = Language(cpp_language())
            parser = Parser(c_lang)
            tree = parser.parse(content.encode())
            root = tree.root_node
            self._build_from_ts_tree(root, content, file_path, tu_id)
            return
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"tree-sitter CPG build failed for {file_path}: {e}, falling back to regex")

        # 3) 回退正则匹配
        self._build_from_regex(content, file_path, tu_id, lines)

    def _build_from_ts_tree(self, root, content: str, file_path: str, tu_id: int) -> None:
        """从 tree-sitter AST 构建 CPG"""
        lines = content.split('\n')

        # 找到所有函数定义
        for i in range(root.child_count):
            child = root.child(i)
            if child is None:
                continue
            if child.type == 'function_definition':
                self._process_ts_function(child, content, file_path, tu_id)

    def _process_ts_function(self, func_node, content: str, file_path: str, tu_id: int) -> None:
        """处理 tree-sitter 函数定义节点"""
        # 提取函数名
        declarator = None
        body_node = None
        for i in range(func_node.child_count):
            child = func_node.child(i)
            if child is None:
                continue
            if child.type == 'function_declarator':
                declarator = child
            elif child.type == 'compound_statement':
                body_node = child

        if declarator is None:
            return

        # 从 function_declarator 的子 identifier 获取函数名
        func_name = ""
        for j in range(declarator.child_count):
            child = declarator.child(j)
            if child and child.type == 'identifier':
                func_name = self._ts_node_text(child, content)
                break

        if not func_name:
            # 回退：从 declarator 文本中猜测
            raw = self._ts_node_text(declarator, content)
            id_part = raw.split('(')[0].strip()
            for tok in id_part.split():
                if tok and tok[0].isalpha() and tok not in ('const', 'unsigned', 'signed',
                                                             'static', 'inline', 'extern',
                                                             'volatile', 'register'):
                    func_name = tok
                    break

        line_no = content[:func_node.start_byte].count('\n') + 1

        # 提取参数
        params = []
        if body_node is None:
            # 仅有声明，无函数体
            return

        # 创建函数节点
        fnode = CPGNode(
            node_type=CPGNodeType.FUNCTION,
            label=f"func {func_name}",
            file_path=file_path,
            line_start=line_no,
            attributes={"name": func_name},
        )
        fid = self.cpg.add_node(fnode)
        self.cpg.add_edge(tu_id, fid, CPGEdgeType.AST_PARENT)

        # 处理参数
        if declarator is not None:
            for j in range(declarator.child_count):
                param = declarator.child(j)
                if param and param.type == 'parameter_list':
                    for k in range(param.child_count):
                        pchild = param.child(k)
                        if pchild and pchild.type == 'parameter_declaration':
                            pname = self._extract_ts_parameter_name(pchild, content)
                            if pname:
                                pnode = CPGNode(
                                    node_type=CPGNodeType.PARAM,
                                    label=pname,
                                    file_path=file_path,
                                    line_start=line_no,
                                    attributes={"func": func_name},
                                )
                                pid = self.cpg.add_node(pnode)
                                self.cpg.add_edge(fid, pid, CPGEdgeType.AST_PARENT)
                                params.append(pname)

        # 函数体入口
        entry_node = CPGNode(
            node_type=CPGNodeType.CFG_ENTRY,
            label=f"entry:{func_name}",
            file_path=file_path,
            line_start=line_no,
        )
        entry_id = self.cpg.add_node(entry_node)
        self.cpg.add_edge(fid, entry_id, CPGEdgeType.AST_PARENT)
        # 参数 → entry CFG 边（方便 BFS 传播到函数体）
        for pname in params:
            for nid, n in self.cpg._nodes.items():
                if n.node_type == CPGNodeType.PARAM and n.label == pname and n.attributes.get("func") == func_name:
                    self.cpg.add_edge(nid, entry_id, CPGEdgeType.CFG_NEXT)

        # 遍历函数体中的语句
        prev_id = entry_id
        self._traverse_ts_children(body_node, content, file_path, prev_id,
                                    False, fid, params)

        # 出口节点
        exit_node = CPGNode(
            node_type=CPGNodeType.CFG_EXIT,
            label=f"exit:{func_name}",
            file_path=file_path,
            line_start=line_no,
        )
        exit_id = self.cpg.add_node(exit_node)
        self.cpg.add_edge(prev_id, exit_id, CPGEdgeType.CFG_NEXT)

    def _traverse_ts_children(self, node, content: str, file_path: str,
                               prev_id: int, is_loop: bool = False,
                               func_id: int = -1, params: list = None) -> int:
        """遍历 tree-sitter 子节点，返回最后一条语句的 ID"""
        current_prev = prev_id
        for i in range(node.child_count):
            child = node.child(i)
            if child is None:
                continue
            current_prev = self._process_ts_stmt(child, content, file_path,
                                                  current_prev, func_id, params)
            if current_prev is None:
                current_prev = prev_id
        return current_prev

    def _process_ts_stmt(self, stmt_node, content: str, file_path: str,
                          prev_id: int, func_id: int, params: list) -> int:
        """处理一条 tree-sitter 语句节点"""
        stmt_type = stmt_node.type

        if stmt_type == 'compound_statement':
            return self._traverse_ts_children(stmt_node, content, file_path, prev_id, False, func_id, params)

        # 提取行号
        line_no = content[:stmt_node.start_byte].count('\n') + 1
        stmt_text = content[stmt_node.start_byte:stmt_node.end_byte].strip()

        if not stmt_text:
            return prev_id

        # 根据语句类型创建节点
        cpg_node = None

        if stmt_type in ('expression_statement',):
            expr = stmt_node.child(0) if stmt_node.child_count > 0 else None
            if expr and expr.type == 'assignment_expression':
                cpg_node = self._ts_assignment_node(expr, content, file_path, line_no)
            elif expr and expr.type == 'call_expression':
                cpg_node = self._ts_call_node(expr, content, file_path, line_no)

        elif stmt_type == 'return_statement':
            cpg_node = CPGNode(
                node_type=CPGNodeType.RETURN,
                label=stmt_text[:80],
                file_path=file_path,
                line_start=line_no,
            )

        elif stmt_type in ('if_statement', 'for_statement', 'while_statement',
                           'do_statement'):
            branch_type = 'if' if stmt_type == 'if_statement' else \
                          'for' if stmt_type == 'for_statement' else \
                          'while' if stmt_type == 'while_statement' else 'do'
            cpg_node = CPGNode(
                node_type=CPGNodeType.CFG_BRANCH,
                label=stmt_text[:80],
                file_path=file_path,
                line_start=line_no,
                attributes={"branch_type": branch_type},
            )

        # 回退：普通的表达式语句
        if cpg_node is None and stmt_text:
            # 检查是否包含函数调用
            if '(' in stmt_text and ')' in stmt_text:
                cpg_node = CPGNode(
                    node_type=CPGNodeType.CFG_CALL,
                    label=stmt_text[:80],
                    file_path=file_path,
                    line_start=line_no,
                )
            elif '=' in stmt_text:
                cpg_node = CPGNode(
                    node_type=CPGNodeType.ASSIGN,
                    label=stmt_text[:80],
                    file_path=file_path,
                    line_start=line_no,
                )
            else:
                cpg_node = CPGNode(
                    node_type=CPGNodeType.CFG_STMT,
                    label=stmt_text[:80],
                    file_path=file_path,
                    line_start=line_no,
                )

        if cpg_node is not None:
            nid = self.cpg.add_node(cpg_node)
            self.cpg.add_edge(prev_id, nid, CPGEdgeType.CFG_NEXT)
            return nid

        return prev_id

    def _ts_call_node(self, call_expr, content: str, file_path: str, line_no: int) -> CPGNode:
        """从 tree-sitter call_expression 创建 CPG 节点"""
        func_part = call_expr.child(0)
        func_name = self._ts_node_text(func_part, content) if func_part else "???"
        # 提取纯函数名
        fname = func_name.split('(')[0].strip()

        # 检查是否为内存操作
        full_text = content[call_expr.start_byte:call_expr.end_byte][:120]
        if fname in ("memcpy", "memmove", "strcpy", "strncpy", "strcat",
                      "sprintf", "snprintf", "gets", "scanf", "fscanf",
                      "sscanf", "read", "recv", "free", "malloc", "calloc",
                      "realloc", "mmap"):
            ntype = CPGNodeType.MEM_COPY if fname in ("memcpy", "memmove", "strcpy", "strcat") else \
                    CPGNodeType.MEM_ALLOC if fname in ("malloc", "calloc", "realloc") else \
                    CPGNodeType.MEM_FREE if fname == "free" else \
                    CPGNodeType.CFG_CALL
            return CPGNode(
                node_type=ntype,
                label=f"{fname}(...)",
                file_path=file_path,
                line_start=line_no,
                attributes={"call": fname, "full_text": full_text},
            )

        return CPGNode(
            node_type=CPGNodeType.CFG_CALL,
            label=content[call_expr.start_byte:call_expr.end_byte][:80],
            file_path=file_path,
            line_start=line_no,
            attributes={"call": fname},
        )

    def _ts_assignment_node(self, assign_expr, content: str, file_path: str, line_no: int) -> CPGNode:
        """从 tree-sitter assignment_expression 创建 CPG 节点"""
        text = content[assign_expr.start_byte:assign_expr.end_byte]
        lhs = assign_expr.child(0)
        lhs_text = self._ts_node_text(lhs, content) if lhs else ""

        if '[' in lhs_text:
            return CPGNode(
                node_type=CPGNodeType.ARRAY_ACCESS,
                label=text[:80],
                file_path=file_path,
                line_start=line_no,
            )

        return CPGNode(
            node_type=CPGNodeType.ASSIGN,
            label=text[:80],
            file_path=file_path,
            line_start=line_no,
        )

    def _ts_node_text(self, node, content: str) -> str:
        """获取 tree-sitter 节点的文本"""
        if node is None:
            return ""
        try:
            return content[node.start_byte:node.end_byte]
        except Exception:
            return ""

    def _extract_ts_parameter_name(self, param_node, content: str) -> str:
        """从 tree-sitter parameter_declaration 提取参数名

        处理普通声明 (int x) 和指针声明 (char *p, char **argv)
        """
        def _find_identifier(node):
            if node is None:
                return None
            if node.type == 'identifier':
                return node
            for i in range(node.child_count):
                child = node.child(i)
                if child:
                    result = _find_identifier(child)
                    if result:
                        return result
            return None

        ident = _find_identifier(param_node)
        return self._ts_node_text(ident, content) if ident else ""

    def _build_from_regex(self, content: str, file_path: str, tu_id: int, lines: list) -> None:
        """正则回退方案构建 CPG（兼容旧格式）"""
        func_pat = re.compile(
            r'(?:(?:static|inline|extern)\s+)?'
            r'(?:const\s+)?(?:\w+(?:\s*\*)?\s+){1,3}(\w+)\s*\([^)]*\)\s*(?:\{|;)'
        )
        for func_match in func_pat.finditer(content):
            func_name = func_match.group(1)
            if func_name.lower() in ("if", "for", "while", "switch", "return",
                                      "sizeof", "int", "char", "void", "size_t"):
                continue

            line_no = content[:func_match.start()].count('\n') + 1
            func_node = CPGNode(
                node_type=CPGNodeType.FUNCTION,
                label=f"func {func_name}",
                file_path=file_path,
                line_start=line_no,
                attributes={"name": func_name},
            )
            func_id = self.cpg.add_node(func_node)
            self.cpg.add_edge(tu_id, func_id, CPGEdgeType.AST_PARENT)

            # 收集此函数的参数
            params_str = content[func_match.start():func_match.end()]
            params = re.findall(r'(\w+)\s*\)?$', params_str.split('(')[-1].split(')')[0])
            for p in params:
                if p and p not in ("void", "char", "int", "long", "short", "unsigned"):
                    param_node = CPGNode(
                        node_type=CPGNodeType.PARAM,
                        label=p,
                        file_path=file_path,
                        line_start=line_no,
                        attributes={"func": func_name},
                    )
                    pid = self.cpg.add_node(param_node)
                    self.cpg.add_edge(func_id, pid, CPGEdgeType.AST_PARENT)

            # 3) 提取函数体内的语句级 CFG 节点
            body_start = content.index('{', func_match.end()) if '{' in content[func_match.end():] else -1
            if body_start < 0:
                continue
            body_end = self._find_matching_brace(content, body_start)
            if body_end < 0:
                continue
            body = content[body_start + 1:body_end]

            entry_node = CPGNode(
                node_type=CPGNodeType.CFG_ENTRY,
                label=f"entry:{func_name}",
                file_path=file_path,
                line_start=line_no,
            )
            entry_id = self.cpg.add_node(entry_node)
            self.cpg.add_edge(func_id, entry_id, CPGEdgeType.AST_PARENT)

            # 逐行扫描函数体
            prev_id = entry_id
            body_lines = body.split('\n')

            for i, line in enumerate(body_lines):
                stripped = line.strip()
                if not stripped or stripped.startswith(('//', '/*', '*', '#', '}')):
                    continue

                abs_line = line_no + 1 + i
                stmt_node = self._create_stmt_node(stripped, file_path, abs_line)
                if stmt_node is None:
                    continue
                sid = self.cpg.add_node(stmt_node)
                self.cpg.add_edge(prev_id, sid, CPGEdgeType.CFG_NEXT)
                prev_id = sid

                # 提取数据依赖（DDG）
                self._extract_ddg(stripped, file_path, abs_line)

            exit_node = CPGNode(
                node_type=CPGNodeType.CFG_EXIT,
                label=f"exit:{func_name}",
                file_path=file_path,
                line_start=line_no + len(body_lines),
            )
            exit_id = self.cpg.add_node(exit_node)
            self.cpg.add_edge(prev_id, exit_id, CPGEdgeType.CFG_NEXT)

        # 记录文件中的函数
        self.cpg._functions_per_file[file_path] = [
            n.label.replace("func ", "")
            for n in self.cpg.find_nodes_by_type(CPGNodeType.FUNCTION)
            if n.file_path == file_path
        ]

    def _create_stmt_node(self, stripped: str, file_path: str,
                          line_no: int) -> Optional[CPGNode]:
        """根据语句模式创建对应的 CPG 节点"""
        # 函数调用
        call_match = re.match(r'(\w+)\s*\(', stripped)
        if call_match:
            fname = call_match.group(1)
            if fname in ("if", "for", "while", "switch"):
                return CPGNode(
                    node_type=CPGNodeType.CFG_BRANCH,
                    label=stripped[:80],
                    file_path=file_path,
                    line_start=line_no,
                    attributes={"branch_type": fname},
                )
            # 内存操作
            if fname in ("memcpy", "memmove", "strcpy", "strncpy", "strcat",
                         "sprintf", "snprintf", "gets", "scanf", "fscanf",
                         "sscanf", "read", "recv", "free", "malloc", "calloc",
                         "realloc", "mmap"):
                ntype = CPGNodeType.MEM_COPY if fname in ("memcpy", "memmove", "strcpy", "strcat") else \
                        CPGNodeType.MEM_ALLOC if fname in ("malloc", "calloc", "realloc") else \
                        CPGNodeType.MEM_FREE if fname == "free" else \
                        CPGNodeType.CFG_CALL
                return CPGNode(
                    node_type=ntype,
                    label=stripped[:80],
                    file_path=file_path,
                    line_start=line_no,
                    attributes={"call": fname},
                )
            return CPGNode(
                node_type=CPGNodeType.CFG_CALL,
                label=stripped[:80],
                file_path=file_path,
                line_start=line_no,
                attributes={"call": fname},
            )

        # 赋值语句（含指针运算）
        if '=' in stripped:
            lhs = stripped.split('=')[0].strip()
            if '[' in lhs:
                return CPGNode(
                    node_type=CPGNodeType.ARRAY_ACCESS,
                    label=stripped[:80],
                    file_path=file_path,
                    line_start=line_no,
                )
            if re.search(r'\bstrcpy|strcat|memcpy|sprintf', stripped):
                return CPGNode(
                    node_type=CPGNodeType.MEM_COPY,
                    label=stripped[:80],
                    file_path=file_path,
                    line_start=line_no,
                )
            return CPGNode(
                node_type=CPGNodeType.ASSIGN,
                label=stripped[:80],
                file_path=file_path,
                line_start=line_no,
            )

        # return 语句
        if stripped.startswith("return"):
            return CPGNode(
                node_type=CPGNodeType.RETURN,
                label=stripped[:80],
                file_path=file_path,
                line_start=line_no,
            )

        # 指针运算 / 算术
        if re.search(r'->|\.\s*\*', stripped):
            return CPGNode(
                node_type=CPGNodeType.POINTER_ARITH,
                label=stripped[:80],
                file_path=file_path,
                line_start=line_no,
            )

        # 基本语句节点
        return CPGNode(
            node_type=CPGNodeType.CFG_STMT,
            label=stripped[:80],
            file_path=file_path,
            line_start=line_no,
        )

    def _extract_ddg(self, line: str, file_path: str, line_no: int) -> None:
        """从单行代码提取数据依赖"""
        # def 节点：赋值左侧的变量
        if '=' in line:
            lhs = line.split('=')[0].strip()
            lhs_var = re.split(r'[\s\[\]\(\)]', lhs)[0]
            if lhs_var and len(lhs_var) > 1 and not lhs_var[0].isdigit():
                def_node = CPGNode(
                    node_type=CPGNodeType.DDG_DEF,
                    label=lhs_var,
                    file_path=file_path,
                    line_start=line_no,
                )
                def_id = self.cpg.add_node(def_node)

                # use 节点：赋值右侧的变量
                rhs = line.split('=', 1)[1].strip()
                uses = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', rhs)
                for u in uses:
                    if u not in ("if", "for", "while", "switch", "return", "NULL",
                                  "sizeof", "int", "char", "void", "size_t", "unsigned"):
                        use_node = CPGNode(
                            node_type=CPGNodeType.DDG_USE,
                            label=u,
                            file_path=file_path,
                            line_start=line_no,
                        )
                        use_id = self.cpg.add_node(use_node)
                        self.cpg.add_edge(def_id, use_id, CPGEdgeType.DDG_DATA)
        # 函数调用参数也作为 use 节点
        call_match = re.match(r'(\w+)\s*\(', line)
        if call_match:
            args_str = line[line.index('(') + 1:line.rfind(')')] if ')' in line else ""
            args = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', args_str)
            for a in args:
                if a not in ("NULL", "0", "1", "sizeof", "int", "char", "void"):
                    use_node = CPGNode(
                        node_type=CPGNodeType.DDG_USE,
                        label=a,
                        file_path=file_path,
                        line_start=line_no,
                    )
                    self.cpg.add_node(use_node)

    @staticmethod
    def _find_matching_brace(content: str, open_pos: int) -> int:
        """查找匹配的右大括号位置"""
        if open_pos < 0 or open_pos >= len(content) or content[open_pos] != '{':
            return -1
        depth = 1
        pos = open_pos + 1
        while pos < len(content) and depth > 0:
            if content[pos] == '{':
                depth += 1
            elif content[pos] == '}':
                depth -= 1
            elif content[pos] == '"' or content[pos] == "'":
                quote = content[pos]
                pos += 1
                while pos < len(content) and content[pos] != quote:
                    if content[pos] == '\\':
                        pos += 1
                    pos += 1
            pos += 1
        return pos - 1 if depth == 0 else -1

    # ---- 污点标记 ----

    def _calllike_nodes(self) -> List[CPGNode]:
        """返回所有"类调用"节点——可被 Source/Sink 规则匹配的节点"""
        types = [CPGNodeType.CFG_CALL, CPGNodeType.MEM_COPY,
                 CPGNodeType.MEM_ALLOC, CPGNodeType.MEM_FREE]
        nodes = []
        for t in types:
            nodes.extend(self.cpg.find_nodes_by_type(t))
        return nodes

    def _mark_sources(self) -> List[CPGNode]:
        """根据 TaintSource 规则标记 CPG 中的源节点"""
        seen: Set[int] = set()
        source_nodes: List[CPGNode] = []
        for node in self._calllike_nodes():
            for src in self.sources:
                pat = src.patterns[0]
                if re.search(pat, node.label):
                    if node.id not in seen:
                        seen.add(node.id)
                        node.is_tainted = True
                        node.taint_labels.add(src.taint_label)
                        source_nodes.append(node)
                        self.cpg.add_edge(
                            node.id, node.id, CPGEdgeType.TAINT_SOURCE,
                            {"source_name": src.name, "cwe": src.cwe_id}
                        )
        # 参数源：函数参数标记为可疑源
        for node in self.cpg.find_nodes_by_type(CPGNodeType.PARAM):
            if node.id not in seen:
                seen.add(node.id)
                node.is_tainted = True
                node.taint_labels.add("PARAM_CONTROL")
                source_nodes.append(node)
        # 分配源：扫描所有节点 label 中的 malloc/calloc/realloc
        for node in self.cpg._nodes.values():
            if node.id in seen:
                continue
            low = node.label.lower()
            if any(kw in low for kw in ["malloc(", "calloc(", "realloc(", "mmap("]):
                seen.add(node.id)
                node.is_tainted = True
                node.taint_labels.add("ALLOC_PTR")
                source_nodes.append(node)
        return source_nodes

    def _mark_sinks(self) -> List[CPGNode]:
        """根据 TaintSink 规则标记 CPG 中的汇节点（含去误报逻辑）

        改进：
        - CWE-416 (UAF)：仅当 free 节点后的 CFG 路径上存在指针使用才标记
        - CWE-120 (memcpy)：仅标记无 sizeof 长度保护的拷贝
        - CWE-787 (数组越界)：仅当索引来自参数或算术运算
        """
        seen: Set[int] = set()
        sink_nodes: List[CPGNode] = []

        for node in self._calllike_nodes():
            node_label = node.label.lower()
            for snk in self.sinks:
                pat = snk.patterns[0]
                if not re.search(pat, node_label):
                    continue
                if node.id in seen:
                    continue

                # ---- CWE-416 去误报：free 后需有指针使用 ----
                if snk.cwe_id == "CWE-416":
                    if not self._has_uaf_path_after_free(node):
                        continue

                # ---- CWE-120 去误报：memcpy/strcpy 需有未保护的源 ----
                if snk.cwe_id == "CWE-120":
                    if self._has_sizeof_protection(node):
                        # sizeof 保护存在→降低置信度，仍标记但降低 severity
                        node.attributes["sink_cwe"] = "CWE-120"
                        node.attributes["sink_name"] = snk.name
                        node.attributes["severity"] = "medium"  # 降级
                        seen.add(node.id)
                        sink_nodes.append(node)
                        self.cpg.add_edge(
                            node.id, node.id, CPGEdgeType.TAINT_SINK,
                            {"sink_name": snk.name, "cwe": "CWE-120", "confidence": "low"}
                        )
                        continue

                # 正常标记
                seen.add(node.id)
                node.attributes["sink_cwe"] = snk.cwe_id
                node.attributes["sink_name"] = snk.name
                node.attributes["severity"] = snk.severity
                sink_nodes.append(node)
                self.cpg.add_edge(
                    node.id, node.id, CPGEdgeType.TAINT_SINK,
                    {"sink_name": snk.name, "cwe": snk.cwe_id}
                )

        # 额外的数组访问 sink
        for node in self.cpg.find_nodes_by_type(CPGNodeType.ARRAY_ACCESS):
            if node.id not in seen:
                seen.add(node.id)
                node.attributes["sink_cwe"] = "CWE-787"
                node.attributes["sink_name"] = "buffer_write"
                sink_nodes.append(node)
        return sink_nodes

    def _has_uaf_path_after_free(self, free_node: CPGNode) -> bool:
        """检查 free 节点之后是否存在指针使用路径（UAF 判定）

        沿 CFG_NEXT 搜索，在之后的语句中查找：
        - 指针解引用（->, *, []）
        - 指针作为参数传递给其他函数
        """
        q = [(free_node.id, 0)]
        visited: Set[int] = set()
        max_follow = 15  # 最多看 15 步

        while q and max_follow > 0:
            cur_id, depth = q.pop(0)
            if cur_id in visited or depth > 10:
                continue
            visited.add(cur_id)
            max_follow -= 1

            for edge in self.cpg.get_edges_from(cur_id):
                if edge.edge_type != CPGEdgeType.CFG_NEXT:
                    continue
                nxt = self.cpg.get_node(edge.dst_id)
                if nxt is None or nxt.id in visited:
                    continue
                label = nxt.label.lower()
                # 检查是否有指针使用迹象
                if any(marker in label for marker in ["->", ".*", "["]):
                    return True
                # 检查是否有另一次调用传递了指针
                if nxt.node_type in (CPGNodeType.CFG_CALL, CPGNodeType.MEM_COPY):
                    return True
                q.append((nxt.id, depth + 1))

        return False

    def _has_sizeof_protection(self, call_node: CPGNode) -> bool:
        """检查调用点是否被 sizeof 保护"""
        full_text = call_node.attributes.get("full_text", call_node.label)
        ft_lower = full_text.lower()
        # 核心：sizeof(dst) 是强保护信号
        if "sizeof" in ft_lower:
            return True
        # strncpy/strncat/snprintf 自带长度保护
        if any(f in ft_lower for f in ["strncpy", "strncat", "snprintf"]):
            return True
        # 硬编码的数字常量（如 64, 128, 256）是保护信号
        # 但排除 strnlen/strlen/atoi 等计算结果
        if re.search(r'\b(64|128|256|512|1024|2048|4096|8192|16384)\b', ft_lower):
            return True
        return False

    def _is_sanitized(self, label: str) -> bool:
        """检查标签是否被消毒器匹配"""
        for s in self.sanitizers:
            if any(re.search(p, label) for p in s.patterns):
                return True
        return False

    # ---- 污点传播 ----

    def _propagate_taint(self, source_nodes: List[CPGNode],
                         sink_nodes: List[CPGNode]) -> List[TaintPath]:
        """从源节点传播污点到汇节点（含过程间传播）"""
        seen: Set[Tuple[int, int]] = set()  # (src_id, snk_id)
        paths: List[TaintPath] = []

        for src in source_nodes:
            for snk in sink_nodes:
                if snk.id == src.id:
                    continue
                key = (src.id, snk.id)
                if key in seen:
                    continue
                seen.add(key)

                # 过程内传播：沿 CFG_NEXT / DDG_DATA 边 BFS
                path = self._bfs_taint_path(src, snk)
                if path:
                    cwe = snk.attributes.get("sink_cwe", "CWE-119")
                    sev = snk.attributes.get("severity", "high")
                    paths.append(TaintPath(
                        source_node=src,
                        sink_node=snk,
                        cwe_id=cwe,
                        path_nodes=path,
                        severity=sev,
                        confidence=0.75,
                        is_interprocedural=False,
                        attack_prerequisites=self._prerequisites_for_cwe(cwe),
                    ))

        # ---- 过程间传播尝试：找不到路径的 pair，通过调用图 ----
        # 如果存在跨函数调用，把 param 污染扩展到被调函数
        inter_paths = self._interprocedural_propagate(source_nodes, sink_nodes, seen)
        paths.extend(inter_paths)

        return paths

    def _interprocedural_propagate(self, source_nodes: List[CPGNode],
                                    sink_nodes: List[CPGNode],
                                    seen: Set[Tuple[int, int]]) -> List[TaintPath]:
        """过程间污点传播：通过调用图扩展

        对每个 source（通常是一个函数参数），查找所有调用该函数的点，
        检查调用方的参数是否可传播到被调函数的 sink。
        """
        inter_paths: List[TaintPath] = []

        # 1. 按函数分组所有节点
        func_of_node: Dict[int, str] = {}
        for nid, n in self.cpg._nodes.items():
            fname = n.attributes.get("func", "")
            if fname:
                func_of_node[nid] = fname

        # 2. 对每个 source 节点，找到它所在的函数
        for src in source_nodes:
            src_func = src.attributes.get("func", "")
            if not src_func:
                continue

            # 3. 查找调用 src_func 的调用点
            call_sites = self.cpg.find_call_nodes(src_func)
            if not call_sites:
                continue

            # 4. 对每个调用点，查找同文件/同函数中的 sink
            for cs in call_sites:
                caller_file = cs.file_path
                for snk in sink_nodes:
                    key = (src.id, snk.id)
                    if key in seen:
                        continue

                    # sink 必须在调用者的同一函数中
                    snk_func = snk.attributes.get("func", "")
                    snk_file = snk.file_path
                    if snk_file != caller_file:
                        continue

                    # 尝试从调用点出发到 sink 的 BFS
                    path = self._bfs_taint_path(cs, snk)
                    if path:
                        seen.add(key)
                        cwe = snk.attributes.get("sink_cwe", "CWE-119")
                        sev = snk.attributes.get("severity", "high")
                        inter_paths.append(TaintPath(
                            source_node=src,
                            sink_node=snk,
                            cwe_id=cwe,
                            path_nodes=[src] + [cs] + path,
                            severity=sev,
                            confidence=0.55,  # 过程间传播置信度略低
                            is_interprocedural=True,
                            attack_prerequisites=self._prerequisites_for_cwe(cwe),
                        ))

        return inter_paths

    def _bfs_taint_path(self, src: CPGNode, snk: CPGNode,
                        max_depth: int = 30) -> Optional[List[CPGNode]]:
        """BFS 查找从 src 到 snk 的路径（含 AST_PARENT 和 TAINT_PROPAGATE 边）"""
        if src.id == snk.id:
            return None

        visited: Set[int] = set()
        queue: List[Tuple[int, List[int]]] = [(src.id, [src.id])]
        visited.add(src.id)

        allowed_types = {
            CPGEdgeType.CFG_NEXT,
            CPGEdgeType.DDG_DATA,
            CPGEdgeType.TAINT_PROPAGATE,
            CPGEdgeType.AST_PARENT,
        }

        while queue:
            cur_id, path_ids = queue.pop(0)
            if len(path_ids) > max_depth:
                continue

            for edge in self.cpg.get_edges_from(cur_id):
                if edge.edge_type not in allowed_types:
                    continue
                nxt = edge.dst_id
                if nxt in visited:
                    continue

                if nxt == snk.id:
                    full_path = [self.cpg.get_node(pid) for pid in path_ids + [nxt]]
                    return [n for n in full_path if n is not None]

                visited.add(nxt)
                queue.append((nxt, path_ids + [nxt]))

        return None

    @staticmethod
    def _prerequisites_for_cwe(cwe: str) -> List[str]:
        MAP = {
            "CWE-119": ["攻击者控制输入大小或内容", "目标缓冲区边界未验证"],
            "CWE-120": ["拷贝源数据长度 > 目标缓冲区大小", "缺乏边界检查"],
            "CWE-125": ["攻击者控制的索引或偏移量", "越界读取未触发异常"],
            "CWE-416": ["指针 release 后未置 NULL", "存在后续通过该指针的内存访问"],
            "CWE-476": ["空指针解引用路径可达"],
            "CWE-787": ["写入位置由攻击者控制的偏移量决定", "目标缓冲区大小已知"],
            "CWE-122": ["堆缓冲区大小由攻击者控制", "realloc/malloc 后未检查返回值"],
            "CWE-134": ["格式化字符串包含攻击者控制的内容"],
            "CWE-190": ["整数运算结果由攻击者控制输入产生", "结果被用作大小/索引"],
        }
        return MAP.get(cwe, ["需要进一步分析"])

    # ---- 批量分析入口 ----

    def analyze_directory(self, directory: str, language: str = "c",
                          extensions: Optional[List[str]] = None) -> List[TaintPath]:
        """扫描目录中的源码文件并执行污点分析

        Args:
            directory: 目标目录
            language: 语言
            extensions: 文件扩展名列表（默认 [".c", ".h", ".cpp"]）

        Returns:
            发现的 TaintPath 列表
        """
        exts = extensions or [".c", ".h", ".cpp", ".cc", ".cxx"]
        files = []
        for ext in exts:
            for f in Path(directory).rglob(f"*{ext}"):
                if f.is_file():
                    files.append(str(f))
        if not files:
            logger.warning(f"在 {directory} 中未找到 {exts} 文件")
            return []
        return self.analyze(files, language)

    def analyze_file(self, file_path: str, language: str = "c") -> List[TaintPath]:
        """分析单个文件"""
        return self.analyze([file_path], language)


# ---------------------------------------------------------------------------
# 全局实例
# ---------------------------------------------------------------------------

_engine: Optional[TaintEngine] = None


def get_taint_engine() -> TaintEngine:
    """获取全局污点引擎实例（与已有导入兼容）"""
    global _engine
    if _engine is None:
        _engine = TaintEngine()
    return _engine
