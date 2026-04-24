from langgraph.graph import StateGraph, END
from typing import Dict, Any, Optional, List
from pathlib import Path
import hashlib
import functools

from src.core.langgraph_state import ScanState, AgentState, evaluate_complexity, should_use_rag, should_use_graph
from src.core.engine import ScanResult, Finding, Severity, Location
from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.cst_analyzer import CSTAnalyzer
from src.taint.analyzer import TaintAnalyzer
from src.storage.rag_knowledge_base import RAGKnowledgeBase
from src.db.neo4j_connection import Neo4jManager
from src.cache.manager import CacheManager
from src.core.rag_graph_integrator import get_rag_graph_integrator
from src.ai.evaluation import get_evaluator
from src.security.security_checker import get_security_checker
from src.ai.reasoning.semantic_agent import SemanticAgent
from src.ai.reasoning.attack_agent import AttackAgent
from src.ai.reasoning.validation_agent import ValidationAgent
from src.core.fusion_agent import FusionAgent
from src.core.chunk_processor import ChunkProcessor

# 缓存管理器
cache_manager = CacheManager()

# 分块处理器
chunk_processor = ChunkProcessor()

# 缓存装饰器
def cache_result(func):
    """缓存函数结果"""
    @functools.wraps(func)
    async def wrapper(state: ScanState):
        # 生成缓存键
        cache_key = hashlib.md5(f"{func.__name__}:{state.target}".encode()).hexdigest()
        
        # 跳过缓存，因为ScanState对象可能无法序列化
        # 后续可以实现更复杂的缓存策略
        # cached_result = cache_manager.get(cache_key)
        # if cached_result:
        #     return cached_result
        
        # 执行函数
        result = await func(state)
        
        # 跳过缓存，因为ScanState对象可能无法序列化
        # cache_manager.set(cache_key, result, expire=3600)  # 缓存1小时
        
        return result
    return wrapper


@cache_result
async def analyze_code(state: ScanState) -> ScanState:
    """代码分析节点
    
    分析代码复杂度和风险，判断是否需要RAG检索
    """
    try:
        target_path = Path(state.target)
        
        # 检查是否需要分块
        needs_chunking = False
        chunks = []
        code = ""
        
        if target_path.is_file():
            # 检查是否需要分块
            needs_chunking = chunk_processor.should_chunk(str(target_path))
            
            if needs_chunking:
                # 分块处理
                chunks = chunk_processor.chunk_file(str(target_path))
                # 读取第一块用于复杂度评估
                if chunks:
                    code = chunks[0]['content']
            else:
                # 直接读取文件
                with open(target_path, 'r', encoding='utf-8') as f:
                    code = f.read()
        else:
            # 如果是目录，简单判断
            code = """
            # 目录扫描
            # 包含多个文件
            """
        
        # 评估代码复杂度
        complexity = evaluate_complexity(code)
        is_simple = complexity < 0.5
        
        # 代码分析结果
        code_analysis = {
            'complexity': 'low' if is_simple else 'high',
            'file_size': len(code),
            'lines': len(code.split('\n')),
            'has_eval': 'eval(' in code,
            'has_sql': 'SQL' in code or 'database' in code,
            'has_xss': 'xss' in code.lower() or 'cross-site' in code.lower(),
            'has_deserialization': 'pickle' in code or 'unpickle' in code,
            'needs_chunking': needs_chunking,
            'chunk_count': len(chunks) if needs_chunking else 0
        }
        
        # 判断是否需要RAG
        needs_rag = not is_simple or code_analysis.get('has_eval') or code_analysis.get('has_sql')
        
        return state.update(
            code_analysis_result=code_analysis,
            is_simple=is_simple,
            needs_rag=needs_rag,
            chunks=chunks if needs_chunking else []
        )
        
    except Exception as e:
        # 出错时默认认为需要完整扫描
        return state.update(
            code_analysis_result={'error': str(e)},
            is_simple=False,
            needs_rag=True
        )


@cache_result
async def retrieve_cve(state: ScanState) -> ScanState:
    """RAG检索节点
    
    检索CVE漏洞信息
    """
    try:
        if not state.needs_rag:
            return state.update(rag_results=[])
        
        # 使用RAG知识库检索
        rag_base = RAGKnowledgeBase()
        
        # 构建检索查询
        query = f"分析以下代码的安全漏洞: {state.target}"
        if state.code_analysis_result:
            query += f"\n代码分析结果: {state.code_analysis_result}"
        
        # 执行检索
        results = rag_base.search_knowledge(query, top_k=5)
        
        # 处理检索结果
        rag_results = []
        for result in results:
            rag_results.append({
                'title': result.content[:100] + '...' if len(result.content) > 100 else result.content,
                'content': result.content,
                'score': result.confidence
            })
        
        # 判断是否需要图谱查询
        needs_graph = should_use_graph(rag_results)
        
        return state.update(
            rag_results=rag_results,
            needs_graph=needs_graph
        )
        
    except Exception as e:
        # 出错时继续流程
        return state.update(
            rag_results=[],
            needs_graph=False
        )


@cache_result
async def query_graph(state: ScanState) -> ScanState:
    """图谱查询节点
    
    查询Neo4j攻击链图谱
    """
    try:
        if not state.needs_graph:
            return state.update(graph_query_results=[])
        
        # 连接Neo4j
        from src.db import get_neo4j_manager
        neo4j_manager = get_neo4j_manager(state.config)
        
        # 构建查询
        queries = []
        if state.rag_results:
            for rag_result in state.rag_results:
                if 'CVE' in rag_result.get('title', ''):
                    # 提取CVE ID
                    cve_id = rag_result['title'].split(' ')[0]
                    queries.append(f"MATCH (c:CVE {{id: '{cve_id}'}})-[r]->(s) RETURN c, r, s")
        
        # 执行查询
        graph_results = []
        for query in queries:
            try:
                result = neo4j_manager.execute_cypher(query)
                graph_results.extend(result)
            except Exception:
                pass
        
        return state.update(graph_query_results=graph_results)
        
    except Exception as e:
        # 出错时继续流程
        return state.update(graph_query_results=[])


@cache_result
async def fast_path(state: ScanState) -> ScanState:
    """快速路径节点
    
    直接规则扫描，适用于简单代码
    """
    try:
        # 创建扫描结果
        scan_result = ScanResult(
            target=state.target,
            status='running'
        )
        
        # 简单规则检查
        target_path = Path(state.target)
        if target_path.is_file():
            with open(target_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # 简单规则检查
            if 'eval(' in code:
                finding = Finding(
                    rule_id='RCE-001',
                    rule_name='Remote Code Execution',
                    description='使用了eval函数，可能导致远程代码执行',
                    severity=Severity.HIGH,
                    location=Location(file=str(target_path), line=code.find('eval(') // code[:code.find('eval(')].count('\n') + 1),
                    message='发现eval函数使用'
                )
                scan_result.add_finding(finding)
            
            if 'os.system(' in code:
                finding = Finding(
                    rule_id='CMD-001',
                    rule_name='Command Injection',
                    description='使用了os.system，可能导致命令注入',
                    severity=Severity.HIGH,
                    location=Location(file=str(target_path), line=code.find('os.system(') // code[:code.find('os.system(')].count('\n') + 1),
                    message='发现os.system使用'
                )
                scan_result.add_finding(finding)
        
        scan_result.complete()
        return state.update(scan_result=scan_result)
        
    except Exception as e:
        scan_result = ScanResult(
            target=state.target,
            status='failed'
        )
        scan_result.fail(str(e))
        return state.update(scan_result=scan_result)


@cache_result
async def cst_analysis_node(state: ScanState) -> ScanState:
    """CST 分析节点
    
    执行 CST 分析，提供代码结构精度分析
    """
    try:
        from src.analyzers.base import AnalysisContext
        
        target_path = Path(state.target)
        if target_path.is_file():
            with open(target_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # 创建分析上下文
            context = AnalysisContext(
                file_path=str(target_path),
                file_content=code,
                language="python"
            )
            
            # 执行 CST 分析
            cst_analyzer = CSTAnalyzer()
            result = cst_analyzer.analyze(context)
            
            # 获取标准化输出
            cst_results = cst_analyzer.get_standardized_output(result)
            
            return state.update(cst=cst_results)
        
        return state.update(cst=[])
        
    except Exception as e:
        print(f"[DEBUG] CST 分析节点出错: {e}")
        return state.update(cst=[])


@cache_result
async def ast_analysis_node(state: ScanState) -> ScanState:
    """AST 分析节点
    
    执行 AST 分析，提供逻辑结构分析
    """
    try:
        from src.analyzers.base import AnalysisContext
        
        target_path = Path(state.target)
        if target_path.is_file():
            with open(target_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # 创建分析上下文
            context = AnalysisContext(
                file_path=str(target_path),
                file_content=code,
                language="python"
            )
            
            # 执行 AST 分析
            ast_analyzer = ASTAnalyzer()
            result = ast_analyzer.analyze(context)
            
            # 获取标准化输出
            ast_results = ast_analyzer.get_standardized_output(result)
            
            return state.update(ast=ast_results)
        
        return state.update(ast=[])
        
    except Exception as e:
        print(f"[DEBUG] AST 分析节点出错: {e}")
        return state.update(ast=[])


@cache_result
async def taint_analysis_node(state: ScanState) -> ScanState:
    """污点分析节点
    
    执行污点分析，提供数据流分析
    """
    try:
        from src.analyzers.base import AnalysisContext
        
        target_path = Path(state.target)
        if target_path.is_file():
            with open(target_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # 创建分析上下文
            context = AnalysisContext(
                file_path=str(target_path),
                file_content=code,
                language="python"
            )
            
            # 执行污点分析
            taint_analyzer = TaintAnalyzer()
            paths = taint_analyzer.analyze(context)
            
            # 获取标准化输出
            taint_results = taint_analyzer.get_standardized_output(paths)
            
            return state.update(taint=taint_results)
        
        return state.update(taint=[])
        
    except Exception as e:
        print(f"[DEBUG] 污点分析节点出错: {e}")
        return state.update(taint=[])


@cache_result
async def rag_analysis_node(state: ScanState) -> ScanState:
    """RAG 分析节点
    
    执行 RAG 检索，提供漏洞模式/CVE 信息
    """
    try:
        target_path = Path(state.target)
        if target_path.is_file():
            with open(target_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # 执行 RAG 检索
            rag_base = RAGKnowledgeBase()
            rag_results = rag_base.get_standardized_output(code, top_k=5)
            
            return state.update(rag=rag_results)
        
        return state.update(rag=[])
        
    except Exception as e:
        print(f"[DEBUG] RAG 分析节点出错: {e}")
        return state.update(rag=[])


@cache_result
async def fusion_node(state: ScanState) -> ScanState:
    """Fusion 节点
    
    融合所有 Agent 的输出，生成统一的证据格式
    """
    try:
        # 执行证据融合
        fusion_agent = FusionAgent()
        fused_evidence = fusion_agent.fuse_evidence(
            cst_results=state.cst,
            ast_results=state.ast,
            taint_results=state.taint,
            rag_results=state.rag,
            semantic_results=state.semantic
        )
        
        return state.update(evidence=fused_evidence)
        
    except Exception as e:
        print(f"[DEBUG] Fusion 节点出错: {e}")
        return state.update(evidence=[])


@cache_result
async def semantic_analysis_node(state: ScanState) -> ScanState:
    """语义分析节点
    
    基于融合证据进行语义分析，提供 AI 增强的漏洞评估
    """
    try:
        target_path = Path(state.target)
        if target_path.is_file():
            with open(target_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # 执行语义分析
            semantic_agent = SemanticAgent()
            semantic_results = semantic_agent.analyze(
                code=code,
                evidence=state.evidence,
                taint_paths=state.taint,
                cve_patterns=state.rag
            )
            
            return state.update(semantic=semantic_results)
        
        return state.update(semantic=[])
        
    except Exception as e:
        print(f"[DEBUG] 语义分析节点出错: {e}")
        return state.update(semantic=[])


@cache_result
async def attack_analysis_node(state: ScanState) -> ScanState:
    """攻击链分析节点
    
    基于融合证据和污点路径生成攻击链
    """
    try:
        # 执行攻击链分析
        attack_agent = AttackAgent()
        attack_chains = attack_agent.generate_attack_chains(
            taint_paths=state.taint,
            evidence=state.evidence
        )
        
        return state.update(attack_paths=attack_chains)
        
    except Exception as e:
        print(f"[DEBUG] 攻击链分析节点出错: {e}")
        return state.update(attack_paths=[])


@cache_result
async def validation_node(state: ScanState) -> ScanState:
    """验证节点
    
    对分析结果进行校验，支持回流机制
    """
    try:
        # 收集所有发现
        all_findings = []
        all_findings.extend(state.cst)
        all_findings.extend(state.ast)
        all_findings.extend(state.taint)
        all_findings.extend(state.rag)
        all_findings.extend(state.semantic)
        
        # 执行验证
        validation_agent = ValidationAgent()
        validated_findings, needs_reflow, reflow_info = validation_agent.validate(
            findings=all_findings,
            attack_chains=state.attack_paths
        )
        
        # 计算整体置信度
        confidence = sum(f.get('confidence', 0.0) for f in validated_findings) / len(validated_findings) if validated_findings else 0.0
        
        return state.update(
            scan_result=ScanResult(
                target=state.target,
                status='completed'
            ),
            confidence=confidence,
            flags={
                'needs_reflow': needs_reflow,
                'reflow_info': reflow_info
            }
        )
        
    except Exception as e:
        print(f"[DEBUG] 验证节点出错: {e}")
        return state.update(
            scan_result=ScanResult(
                target=state.target,
                status='failed'
            )
        )


@cache_result
async def generate_report(state: ScanState) -> ScanState:
    """报告生成节点
    
    生成最终扫描报告
    """
    try:
        # 如果已经有扫描结果（快速路径或验证节点），直接返回
        if state.scan_result:
            return state
        
        # 创建扫描结果
        scan_result = ScanResult(
            target=state.target,
            status='running'
        )
        
        # 处理融合的证据
        if state.evidence:
            for evidence_item in state.evidence:
                finding = Finding(
                    rule_id=f"EVIDENCE-{evidence_item.get('type', '001')}",
                    rule_name='Fusion Evidence',
                    description=f"{evidence_item.get('message', '发现潜在漏洞')} - 来自 {', '.join(evidence_item.get('sources', ['Unknown']))}",
                    severity=getattr(Severity, evidence_item.get('severity', 'MEDIUM').upper(), Severity.MEDIUM),
                    location=Location(
                        file=state.target,
                        line=evidence_item.get('location', {}).get('line', 1) if isinstance(evidence_item.get('location'), dict) else 1
                    ),
                    confidence=evidence_item.get('confidence', 0.0),
                    message=f"发现潜在漏洞: {evidence_item.get('vulnerability_types', ['Unknown'])[0]}",
                    metadata={
                        'evidence_count': len(evidence_item.get('evidence', [])),
                        'sources': evidence_item.get('sources', []),
                        'vulnerability_types': evidence_item.get('vulnerability_types', [])
                    }
                )
                scan_result.add_finding(finding)
        
        # 处理攻击链
        if state.attack_paths:
            for attack_chain in state.attack_paths:
                finding = Finding(
                    rule_id='ATTACK-001',
                    rule_name='Attack Chain Detected',
                    description=f"发现攻击链: {attack_chain.get('impact', 'Unknown Impact')}",
                    severity=getattr(Severity, attack_chain.get('metadata', {}).get('severity', 'MEDIUM').upper(), Severity.MEDIUM),
                    location=Location(file=state.target),
                    confidence=attack_chain.get('confidence', 0.0),
                    message=f"检测到攻击链: {attack_chain.get('vulnerability_type', 'Unknown')}",
                    metadata={
                        'path': attack_chain.get('path', []),
                        'source': attack_chain.get('metadata', {}).get('source', 'Unknown'),
                        'sink': attack_chain.get('metadata', {}).get('sink', 'Unknown')
                    }
                )
                scan_result.add_finding(finding)
        
        # 处理语义分析结果
        if state.semantic:
            for semantic_result in state.semantic:
                finding = Finding(
                    rule_id=semantic_result.get('rule_id', 'SEMANTIC-001'),
                    rule_name='Semantic Analysis',
                    description=semantic_result.get('message', '语义分析发现潜在漏洞'),
                    severity=getattr(Severity, semantic_result.get('severity', 'MEDIUM').upper(), Severity.MEDIUM),
                    location=Location(
                        file=state.target,
                        line=semantic_result.get('location', {}).get('line', 1) if isinstance(semantic_result.get('location'), dict) else 1
                    ),
                    confidence=semantic_result.get('confidence', 0.0),
                    message=semantic_result.get('message', '语义分析发现潜在漏洞'),
                    metadata=semantic_result.get('metadata', {})
                )
                scan_result.add_finding(finding)
        
        scan_result.complete()
        return state.update(scan_result=scan_result)
        
    except Exception as e:
        scan_result = ScanResult(
            target=state.target,
            status='failed'
        )
        scan_result.fail(str(e))
        return state.update(scan_result=scan_result)


def create_scan_graph():
    """创建扫描流程图
    
    Returns:
        StateGraph: LangGraph状态图
    """
    # 创建状态图
    graph = StateGraph(ScanState)
    
    # 添加节点
    graph.add_node("analyze_code", analyze_code)
    graph.add_node("fast_path", fast_path)
    
    # 分析类 Agent 节点
    graph.add_node("cst_analysis", cst_analysis_node)
    graph.add_node("ast_analysis", ast_analysis_node)
    graph.add_node("taint_analysis", taint_analysis_node)
    
    # 知识类 Agent 节点
    graph.add_node("rag_analysis", rag_analysis_node)
    
    # 证据融合节点
    graph.add_node("fusion", fusion_node)
    
    # 推理类 Agent 节点
    graph.add_node("semantic_analysis", semantic_analysis_node)
    graph.add_node("attack_analysis", attack_analysis_node)
    
    # 验证节点
    graph.add_node("validation", validation_node)
    
    # 报告生成节点
    graph.add_node("generate_report", generate_report)
    
    # 设置入口点
    graph.set_entry_point("analyze_code")
    
    # 添加条件边
    graph.add_conditional_edges(
        "analyze_code",
        lambda state: "fast_path" if state.is_simple else "cst_analysis",
        {"fast_path": "fast_path", "cst_analysis": "cst_analysis"}
    )
    
    # 并行执行分析节点
    graph.add_edge("cst_analysis", "ast_analysis")
    graph.add_edge("ast_analysis", "taint_analysis")
    graph.add_edge("taint_analysis", "rag_analysis")
    graph.add_edge("rag_analysis", "fusion")
    
    # 证据融合后执行推理分析
    graph.add_edge("fusion", "semantic_analysis")
    graph.add_edge("semantic_analysis", "attack_analysis")
    graph.add_edge("attack_analysis", "validation")
    
    # 验证后生成报告
    graph.add_edge("validation", "generate_report")
    graph.add_edge("fast_path", "generate_report")
    graph.add_edge("generate_report", END)
    
    return graph


def compile_graph():
    """编译流程图
    
    Returns:
        CompiledGraph: 编译后的流程图
    """
    graph = create_scan_graph()
    return graph.compile()


async def run_scan(target: str, config: Any) -> ScanResult:
    """运行扫描流程
    
    Args:
        target: 扫描目标
        config: 扫描配置
        
    Returns:
        ScanResult: 扫描结果
    """
    from src.core.engine import ScanResult
    
    try:
        print("📊 LangGraph 扫描流程启动")
        print(f"🎯 扫描目标: {target}")
        
        # 读取代码内容
        from pathlib import Path
        target_path = Path(target)
        input_code = ""
        if target_path.is_file():
            try:
                with open(target_path, 'r', encoding='utf-8') as f:
                    input_code = f.read()
            except Exception as e:
                print(f"⚠️  读取文件失败: {e}")
                input_code = f"# 文件: {target}"
        else:
            input_code = f"# 目录: {target}"
        
        # 创建 AgentState 初始状态
        initial_state: AgentState = {
            'input_code': input_code,
            'cve_candidates': [],
            'graph_subgraph': {},
            'analysis_result': '',
            'final_report': {},
            'iteration': 0
        }
        print("✅ 初始状态创建完成")
        
        # 编译多Agent图
        print("🔧 编译 LangGraph 多Agent状态图")
        app = compile_agent_graph()
        print("✅ LangGraph 多Agent状态图编译完成")
        
        # 运行流程
        print("🚀 执行 LangGraph 扫描流程")
        result = await app.ainvoke(initial_state)
        print("✅ LangGraph 扫描流程执行完成")
        
        # 创建扫描结果
        scan_result = ScanResult(
            target=target,
            status='completed'
        )
        
        # 处理分析结果
        if 'final_report' in result:
            final_report = result['final_report']
            print(f"📋 扫描结果: 分析完成")
            
            # 添加分析结果到扫描结果中
            from src.core.engine import Finding, Location, Severity
            finding = Finding(
                rule_id='LANGGRAPH-ANALYSIS',
                rule_name='LangGraph 深度分析',
                description=final_report.get('analysis', ''),
                severity=Severity.MEDIUM,
                location=Location(file=target, line=1, column=0),
                confidence=0.8,
                message='LangGraph 深度分析完成',
                code_snippet=input_code[:200] + '...' if len(input_code) > 200 else input_code,
                fix_suggestion=final_report.get('fix_suggestions', ''),
                references=[],
                metadata=final_report
            )
            scan_result.add_finding(finding)
        else:
            print("⚠️  未生成最终报告")
        
        return scan_result
            
    except Exception as e:
        # 创建失败结果
        error_result = ScanResult(target=target, status='failed')
        error_result.fail(str(e))
        print(f"❌ LangGraph 扫描流程失败: {e}")
        return error_result


# 新的多Agent流程
async def retrieval_node(state: AgentState) -> AgentState:
    """Retrieval Agent节点
    
    集成FAISS和Neo4j检索功能，返回Top-K CVE列表
    """
    try:
        # 安全检查
        security_checker = get_security_checker()
        security_result = security_checker.run_all_checks(state['input_code'])
        
        # 如果安全风险高，拒绝处理
        if security_result['overall_risk'] == 'high':
            return {
                **state,
                'cve_candidates': [],
                'security_alert': {
                    'risk': security_result['overall_risk'],
                    'message': '输入代码存在高安全风险，拒绝处理',
                    'details': security_checker.generate_security_report(state['input_code'])
                }
            }
        
        # 使用RAG Graph Integrator进行混合检索
        rag_integrator = get_rag_graph_integrator()
        
        # 构建检索查询
        query = f"分析以下代码的安全漏洞: {state['input_code']}"
        
        # 执行混合检索
        results = rag_integrator.search_vulnerabilities(query, top_k=10)
        
        # 处理检索结果
        cve_candidates = []
        for result in results:
            cve_candidates.append({
                'title': result.get('metadata', {}).get('title', '') or result.get('content', '')[:100] + '...' if len(result.get('content', '')) > 100 else result.get('content', ''),
                'content': result.get('content', ''),
                'score': result.get('similarity', 0.0),
                'metadata': result.get('metadata', {})
            })
        
        return {
            **state,
            'cve_candidates': cve_candidates
        }
        
    except Exception as e:
        # 出错时返回空列表
        return {
            **state,
            'cve_candidates': []
        }


def should_build_graph(state: AgentState) -> str:
    """判断是否需要构建攻击链
    
    Args:
        state: Agent状态
        
    Returns:
        str: 'yes' 或 'no'
    """
    if not state.get('cve_candidates'):
        return 'no'
    
    # 检查是否存在CVE
    for candidate in state['cve_candidates']:
        if 'CVE' in candidate.get('title', ''):
            return 'yes'
    
    return 'no'


async def graph_node(state: AgentState) -> AgentState:
    """Graph Agent节点
    
    构建局部攻击链
    """
    try:
        # 连接Neo4j
        from src.db import get_neo4j_manager
        neo4j_manager = get_neo4j_manager({})
        
        # 构建攻击链
        attack_chain = {
            'chains': [],
            'statistics': {}
        }
        
        if state.get('cve_candidates'):
            for candidate in state['cve_candidates']:
                metadata = candidate.get('metadata', {})
                cve_id = metadata.get('cve_id') or candidate.get('title', '').split(' ')[0]
                
                if 'CVE' in cve_id:
                    # 生成攻击链
                    try:
                        chain_info = neo4j_manager.generate_attack_chain(cve_id)
                        if chain_info and 'attack_chain' in chain_info:
                            attack_chain['chains'].append({
                                'cve_id': cve_id,
                                'chain': chain_info['attack_chain'],
                                'score': candidate.get('score', 0.0)
                            })
                    except Exception:
                        pass
        
        # 统计攻击链信息
        attack_chain['statistics'] = {
            'total_chains': len(attack_chain['chains']),
            'average_score': sum(chain['score'] for chain in attack_chain['chains']) / len(attack_chain['chains']) if attack_chain['chains'] else 0
        }
        
        return {
            **state,
            'graph_subgraph': attack_chain
        }
        
    except Exception as e:
        # 出错时返回空字典
        return {
            **state,
            'graph_subgraph': {'chains': [], 'statistics': {'total_chains': 0, 'average_score': 0}}
        }


async def reasoning_node(state: AgentState) -> AgentState:
    """Reasoning Agent节点
    
    核心漏洞分析和利用方式分析
    """
    try:
        # 评估代码复杂度
        complexity = evaluate_complexity(state['input_code'])
        print(f"[DEBUG] 代码复杂度评估: {complexity:.2f}")
        
        # 使用强化的 DSPy 分析逻辑
        print("[DEBUG] 使用强化的 DSPy 分析")
        # 构建分析输入
        cve_context = "\n".join([candidate['content'] for candidate in state.get('cve_candidates', [])])
        
        # 处理攻击链信息
        graph_subgraph = state.get('graph_subgraph', {})
        attack_chain_info = []
        if 'chains' in graph_subgraph:
            for chain in graph_subgraph['chains'][:3]:  # 只使用前3条攻击链
                attack_chain_info.append(f"CVE: {chain['cve_id']}\n{chain['chain'][:200]}...")
        attack_chain = "\n".join(attack_chain_info) or str(graph_subgraph)
        
        # 集成DSPy优化
        print("[DEBUG] 集成 DSPy 优化...")
        from src.ai.dspy_optimization import get_dspy_programs, _optimized_programs
        # 重置缓存，确保获取最新的程序
        _optimized_programs.clear()
        programs = get_dspy_programs()
        
        # 使用DSPy进行漏洞分析
        print("[DEBUG] 使用 DSPy 进行漏洞分析...")
        result = programs['vulnerability_analysis'](
            code=state['input_code'],
            cve_context=cve_context,
            attack_chain=attack_chain
        )
        print("[DEBUG] DSPy 漏洞分析完成")
        
        # 构建分析结果
        analysis_result = f"# 漏洞分析结果\n\n"
        analysis_result += f"## 基础信息\n"
        analysis_result += f"- 代码复杂度: {complexity:.2f}\n"
        analysis_result += f"- CVE候选数量: {len(state.get('cve_candidates', []))}\n"
        analysis_result += f"- 攻击链数量: {graph_subgraph.get('statistics', {}).get('total_chains', 0)}\n"
        analysis_result += f"- 平均相似度: {graph_subgraph.get('statistics', {}).get('average_score', 0):.2f}\n\n"
        
        analysis_result += f"## 漏洞分析\n"
        analysis_result += f"{result.vulnerabilities}\n\n"
        
        analysis_result += f"## 利用方式\n"
        analysis_result += f"{result.exploitation}\n\n"
        
        analysis_result += f"## 修复建议\n"
        analysis_result += f"{result.fix_suggestions}\n"
        
        return {
            **state,
            'analysis_result': analysis_result
        }
        
    except Exception as e:
        print(f"[DEBUG] 推理节点出错: {e}")
        # 出错时使用默认逻辑
        analysis_result = f"# 漏洞分析结果\n\n"
        analysis_result += f"## 基础信息\n"
        analysis_result += f"- CVE候选数量: {len(state.get('cve_candidates', []))}\n"
        analysis_result += f"- 攻击链数量: {state.get('graph_subgraph', {}).get('statistics', {}).get('total_chains', 0)}\n\n"
        analysis_result += "## 详细分析\n"
        analysis_result += "基于检索结果和攻击链分析，发现潜在的安全漏洞\n"
        analysis_result += "建议进一步深入分析以确定具体的漏洞类型和修复方案\n"
        
        return {
            **state,
            'analysis_result': analysis_result
        }


async def critic_node(state: AgentState) -> AgentState:
    """Critic Agent节点
    
    质量检查，支持循环重试
    """
    try:
        print("[DEBUG] 开始执行 Critic Agent 质量评估...")
        # 集成DSPy优化
        print("[DEBUG] 集成 DSPy 优化...")
        from src.ai.dspy_optimization import get_dspy_programs, _optimized_programs
        # 重置缓存，确保获取最新的程序
        _optimized_programs.clear()
        programs = get_dspy_programs()
        
        # 使用DSPy进行质量评估
        print("[DEBUG] 使用 DSPy 进行质量评估...")
        result = programs['critic_evaluation'](
            analysis_result=state.get('analysis_result', '')
        )
        print(f"[DEBUG] DSPy 质量评估结果: {result.quality}")
        
        # 质量评估
        iteration = state.get('iteration', 0)
        analysis_result = state.get('analysis_result', '')
        
        # 综合评估质量
        quality_score = 0
        
        # 1. 分析结果长度
        if len(analysis_result) > 500:
            quality_score += 30
        elif len(analysis_result) > 200:
            quality_score += 20
        elif len(analysis_result) > 100:
            quality_score += 10
        
        # 2. DSPy评估结果
        if result.quality == 'pass':
            quality_score += 40
        elif result.quality == 'warning':
            quality_score += 20
        
        # 3. 内容完整性
        if '漏洞分析' in analysis_result and '利用方式' in analysis_result and '修复建议' in analysis_result:
            quality_score += 30
        
        # 4. 使用LangSmith + DeepEval进行评估
        print("[DEBUG] 使用 LangSmith + DeepEval 进行评估...")
        evaluator = get_evaluator()
        evaluation_report = evaluator.evaluate_analysis(
            state.get('input_code', ''),
            analysis_result
        )
        print(f"[DEBUG] LangSmith + DeepEval 评估结果: {evaluation_report['evaluation']['overall']:.2f}")
        
        # 生成反馈
        feedback = evaluator.generate_feedback(evaluation_report['evaluation'])
        print("[DEBUG] 生成评估反馈")
        
        # 判断是否需要重试
        if quality_score < 60 or evaluation_report['evaluation']['overall'] < 0.6:
            # 质量不达标，需要重试
            if iteration < 3:
                print(f"[DEBUG] 质量不达标，需要重试 (迭代 {iteration + 1}/3)")
                return {
                    **state,
                    'iteration': iteration + 1,
                    'quality_score': quality_score,
                    'evaluation': evaluation_report['evaluation'],
                    'feedback': feedback,
                    'improvement_suggestions': result.improvements if hasattr(result, 'improvements') else "分析结果不够详细，请提供更全面的漏洞分析"
                }
        
        # 质量达标，生成最终报告
        print("[DEBUG] 质量达标，生成最终报告")
        final_report = {
            'analysis': analysis_result,
            'cve_candidates': state.get('cve_candidates', []),
            'attack_chain': state.get('graph_subgraph', {}),
            'quality': result.quality,
            'quality_score': quality_score,
            'evaluation': evaluation_report['evaluation'],
            'feedback': feedback,
            'improvements': result.improvements if hasattr(result, 'improvements') else [],
            'iteration': iteration
        }
        
        return {
            **state,
            'final_report': final_report
        }
        
    except Exception as e:
        print(f"[DEBUG] Critic 节点出错: {e}")
        # 出错时使用默认逻辑
        iteration = state.get('iteration', 0)
        analysis_result = state.get('analysis_result', '')
        
        # 简单的质量评估
        quality_score = 0
        if len(analysis_result) > 300:
            quality_score = 70
        elif len(analysis_result) > 100:
            quality_score = 50
        
        # 尝试使用评估器
        evaluation = {'overall': 0.5}
        feedback = "分析结果需要改进"
        try:
            print("[DEBUG] 尝试使用评估器...")
            evaluator = get_evaluator()
            evaluation_report = evaluator.evaluate_analysis(
                state.get('input_code', ''),
                analysis_result
            )
            evaluation = evaluation_report['evaluation']
            feedback = evaluator.generate_feedback(evaluation)
            print(f"[DEBUG] 评估器执行成功: {evaluation['overall']:.2f}")
        except Exception as eval_error:
            print(f"[DEBUG] 评估器执行失败: {eval_error}")
            pass
        
        if quality_score < 60 or evaluation['overall'] < 0.6:
            # 质量不达标，需要重试
            if iteration < 3:
                print(f"[DEBUG] 质量不达标，需要重试 (迭代 {iteration + 1}/3)")
                return {
                    **state,
                    'iteration': iteration + 1,
                    'quality_score': quality_score,
                    'evaluation': evaluation,
                    'feedback': feedback,
                    'improvement_suggestions': "分析结果不够详细，请提供更全面的漏洞分析"
                }
        
        # 质量达标，生成最终报告
        print("[DEBUG] 质量达标，生成最终报告")
        final_report = {
            'analysis': analysis_result,
            'cve_candidates': state.get('cve_candidates', []),
            'attack_chain': state.get('graph_subgraph', {}),
            'quality': 'pass',
            'quality_score': quality_score,
            'evaluation': evaluation,
            'feedback': feedback,
            'iteration': iteration
        }
        
        return {
            **state,
            'final_report': final_report
        }


async def repair_node(state: AgentState) -> AgentState:
    """Repair Agent节点
    
    生成修复建议
    """
    try:
        # 集成DSPy优化
        from src.ai.dspy_optimization import get_dspy_programs
        programs = get_dspy_programs()
        
        # 使用DSPy生成修复建议
        result = programs['repair_suggestion'](
            vulnerability_details=state.get('analysis_result', '')
        )
        
        # 更新最终报告
        final_report = state.get('final_report', {})
        
        # 生成详细的修复建议
        fix_suggestions = f"# 详细修复建议\n\n"
        fix_suggestions += f"## 具体修复方案\n"
        fix_suggestions += f"{result.fix_suggestions}\n\n"
        
        # 添加代码示例（如果可能）
        fix_suggestions += "## 代码修复示例\n"
        fix_suggestions += "```python\n"
        fix_suggestions += "# 修复前\n"
        fix_suggestions += state.get('input_code', '')[:200] + '...\n\n'
        fix_suggestions += "# 修复后\n"
        fix_suggestions += "# TODO: 根据具体漏洞类型生成修复后的代码示例\n"
        fix_suggestions += "```\n\n"
        
        # 添加修复注意事项
        fix_suggestions += "## 修复注意事项\n"
        fix_suggestions += "1. 修复时请确保不破坏现有功能\n"
        fix_suggestions += "2. 修复后请进行充分的测试\n"
        fix_suggestions += "3. 定期更新依赖库以避免已知漏洞\n"
        fix_suggestions += "4. 考虑添加安全测试用例\n"
        
        final_report['fix_suggestions'] = fix_suggestions
        
        return {
            **state,
            'final_report': final_report
        }
        
    except Exception as e:
        # 出错时使用默认逻辑
        final_report = state.get('final_report', {})
        
        # 生成默认修复建议
        fix_suggestions = "# 详细修复建议\n\n"
        fix_suggestions += "## 具体修复方案\n"
        fix_suggestions += "根据漏洞分析结果进行修复\n\n"
        
        fix_suggestions += "## 代码修复示例\n"
        fix_suggestions += "```python\n"
        fix_suggestions += "# 修复前\n"
        fix_suggestions += state.get('input_code', '')[:200] + '...\n\n'
        fix_suggestions += "# 修复后\n"
        fix_suggestions += "# TODO: 根据具体漏洞类型生成修复后的代码示例\n"
        fix_suggestions += "```\n\n"
        
        fix_suggestions += "## 修复注意事项\n"
        fix_suggestions += "1. 修复时请确保不破坏现有功能\n"
        fix_suggestions += "2. 修复后请进行充分的测试\n"
        fix_suggestions += "3. 定期更新依赖库以避免已知漏洞\n"
        
        final_report['fix_suggestions'] = fix_suggestions
        
        return {
            **state,
            'final_report': final_report
        }


def create_agent_graph():
    """创建多Agent流程图
    
    Returns:
        StateGraph: LangGraph状态图
    """
    # 创建状态图
    graph = StateGraph(AgentState)
    
    # 添加节点
    graph.add_node("retrieve", retrieval_node)
    graph.add_node("build_graph", graph_node)
    graph.add_node("reason", reasoning_node)
    graph.add_node("critic", critic_node)
    graph.add_node("repair", repair_node)
    
    # 设置入口点
    graph.set_entry_point("retrieve")
    
    # 添加条件边
    graph.add_conditional_edges(
        "retrieve",
        should_build_graph,
        {"yes": "build_graph", "no": "reason"}
    )
    
    graph.add_edge("build_graph", "reason")
    graph.add_edge("reason", "critic")
    
    # Critic循环
    graph.add_conditional_edges(
        "critic",
        lambda state: "reason" if state.get('final_report') is None else "repair",
        {"reason": "reason", "repair": "repair"}
    )
    
    graph.add_edge("repair", END)
    
    return graph


def compile_agent_graph():
    """编译多Agent流程图
    
    Returns:
        CompiledGraph: 编译后的流程图
    """
    graph = create_agent_graph()
    return graph.compile()


async def analyze_code(code: str) -> Dict[str, Any]:
    """分析代码
    
    Args:
        code: 代码内容
        
    Returns:
        Dict[str, Any]: 分析结果
    """
    try:
        # 创建初始状态
        initial_state: AgentState = {
            'input_code': code,
            'cve_candidates': [],
            'graph_subgraph': {},
            'analysis_result': '',
            'final_report': {},
            'iteration': 0
        }
        
        # 编译图
        app = compile_agent_graph()
        
        # 运行流程
        result = await app.ainvoke(initial_state)
        
        return result
        
    except Exception as e:
        return {'error': str(e)}