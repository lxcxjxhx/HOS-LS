"""污点分析模块

实现数据流分析，识别从输入源到危险函数的传播路径。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any

from tree_sitter import Language, Parser, Node, Tree

from src.analyzers.base import AnalysisContext
from src.ai.risk_scorer import HybridRiskScorer
from src.ai.models import VulnerabilityFinding


@dataclass
class TaintSource:
    """污点源"""
    name: str
    node: Node
    file_path: str
    line: int
    description: str


@dataclass
class TaintSink:
    """污点汇"""
    name: str
    node: Node
    file_path: str
    line: int
    description: str
    vulnerability_type: str


@dataclass
class TaintPath:
    """污点传播路径"""
    source: TaintSource
    sink: TaintSink
    path: List[str]  # 变量传播链
    confidence: float = 0.0
    poc: Optional[str] = None
    severity: str = "medium"  # 严重程度: critical, high, medium, low, info
    
    def evaluate_severity(self) -> str:
        """评估漏洞严重程度
        
        Returns:
            严重程度级别
        """
        # 基于漏洞类型的基础严重程度
        severity_map = {
            "SQL Injection": "high",
            "Command Injection": "high",
            "Code Injection": "high",
            "XSS": "medium",
        }
        base_severity = severity_map.get(self.sink.vulnerability_type, "medium")
        
        # 创建VulnerabilityFinding对象用于风险评分
        finding = VulnerabilityFinding(
            rule_id=self.sink.vulnerability_type,
            rule_name=self.sink.vulnerability_type,
            description=f"{self.sink.description} - {self.source.description}",
            severity=base_severity,  # 使用基于漏洞类型的基础严重程度
            confidence=self.confidence,
            location={
                "file": self.sink.file_path,
                "line": self.sink.line
            },
            code_snippet="",
            fix_suggestion="",
            explanation="",
            references=[]
        )
        
        # 使用HybridRiskScorer计算风险评分
        scorer = HybridRiskScorer()
        risk_score = scorer.calculate_score(finding)
        
        # 根据风险评分映射到严重程度
        score = risk_score.overall_score
        if score >= 8.0:
            return "critical"
        elif score >= 6.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 2.0:
            return "low"
        else:
            return "info"
    
    def is_high_risk(self) -> bool:
        """判断是否为高危及以上漏洞
        
        Returns:
            是否为高危及以上
        """
        severity = self.evaluate_severity()
        return severity in ["critical", "high"]


class TaintAnalyzer:
    """污点分析器

    识别从输入源到危险函数的数据流路径。
    """

    def __init__(self):
        self._sources: List[TaintSource] = []
        self._sinks: List[TaintSink] = []
        self._paths: List[TaintPath] = []
        self._variable_taint: Dict[str, bool] = {}
        self._languages: Dict[str, Language] = {}
        self._initialize_languages()

    def _initialize_languages(self):
        """初始化 tree-sitter 语言"""
        try:
            # Python
            from tree_sitter_python import language as python_language
            self._languages["python"] = Language(python_language())
        except ImportError:
            pass

        try:
            # JavaScript
            from tree_sitter_javascript import language as js_language
            self._languages["javascript"] = Language(js_language())
            self._languages["typescript"] = Language(js_language())
        except ImportError:
            pass

    def analyze(self, context: AnalysisContext) -> List[TaintPath]:
        """执行污点分析

        Args:
            context: 分析上下文

        Returns:
            污点传播路径列表
        """
        self._sources = []
        self._sinks = []
        self._paths = []
        self._variable_taint = {}

        # 解析 AST
        language = self._languages.get(context.language)
        if not language:
            return []

        # 创建解析器并解析代码
        parser = Parser(language)
        tree = parser.parse(context.file_content.encode())
        if not tree:
            return []

        # 识别输入源和危险函数
        self._identify_sources_and_sinks(tree, context)

        # 构建数据流路径
        self._build_data_flow_paths()

        return self._paths

    def _identify_sources_and_sinks(self, tree: Node, context: AnalysisContext) -> None:
        """识别输入源和危险函数

        Args:
            tree: AST 树
            context: 分析上下文
        """
        # 简化实现：直接遍历所有节点，寻找输入函数和危险函数
        code = context.file_content
        lines = code.split('\n')
        
        # 查找输入源
        for i, line in enumerate(lines):
            line = line.strip()
            # 查找 input() 调用
            if 'input(' in line and '=' in line:
                # 提取变量名
                var_name = line.split('=')[0].strip()
                if var_name:
                    self._sources.append(TaintSource(
                        name=var_name,
                        node=None,
                        file_path=context.file_path,
                        line=i + 1,
                        description=f"用户输入: input()"
                    ))
                    self._variable_taint[var_name] = True
        
        # 查找危险函数
        for i, line in enumerate(lines):
            line = line.strip()
            # 查找危险函数调用
            if "eval(" in line:
                self._sinks.append(TaintSink(
                    name="eval",
                    node=None,
                    file_path=context.file_path,
                    line=i + 1,
                    description="危险函数: eval()",
                    vulnerability_type="Code Injection"
                ))
            elif "exec(" in line:
                self._sinks.append(TaintSink(
                    name="exec",
                    node=None,
                    file_path=context.file_path,
                    line=i + 1,
                    description="危险函数: exec()",
                    vulnerability_type="Code Injection"
                ))
            elif "os.system(" in line:
                self._sinks.append(TaintSink(
                    name="os.system",
                    node=None,
                    file_path=context.file_path,
                    line=i + 1,
                    description="危险函数: os.system()",
                    vulnerability_type="Command Injection"
                ))
            elif "execute(" in line:
                self._sinks.append(TaintSink(
                    name="execute",
                    node=None,
                    file_path=context.file_path,
                    line=i + 1,
                    description="危险函数: execute()",
                    vulnerability_type="SQL Injection"
                ))

    def _check_source(self, node: Node, context: AnalysisContext) -> None:
        """检查输入源

        Args:
            node: AST 节点
            context: 分析上下文
        """
        if node.type == "call":
            # 检查输入函数调用
            func_name = self._get_function_name(node)
            if func_name:
                # Python 输入源
                if context.language == "python" and func_name in ["input", "raw_input"]:
                    # 查找变量赋值
                    parent = self._get_parent_node(node, 1)
                    if parent and parent.type == "expression_statement":
                        grandparent = self._get_parent_node(parent, 1)
                        if grandparent and grandparent.type == "assignment_expression":
                            var_name = self._get_assignment_variable(grandparent)
                            if var_name:
                                self._sources.append(TaintSource(
                                    name=var_name,
                                    node=node,
                                    file_path=context.file_path,
                                    line=node.start_point[0] + 1,
                                    description=f"用户输入: {func_name}()"
                                ))
                                self._variable_taint[var_name] = True

                # 文件读取
                elif func_name in ["open", "file"]:
                    # 查找变量赋值
                    parent = self._get_parent_node(node, 1)
                    if parent and parent.type == "expression_statement":
                        grandparent = self._get_parent_node(parent, 1)
                        if grandparent and grandparent.type == "assignment_expression":
                            var_name = self._get_assignment_variable(grandparent)
                            if var_name:
                                self._sources.append(TaintSource(
                                    name=var_name,
                                    node=node,
                                    file_path=context.file_path,
                                    line=node.start_point[0] + 1,
                                    description=f"文件读取: {func_name}()"
                                ))
                                self._variable_taint[var_name] = True

    def _check_sink(self, node: Node, context: AnalysisContext) -> None:
        """检查危险函数

        Args:
            node: AST 节点
            context: 分析上下文
        """
        if node.type == "call":
            func_name = self._get_function_name(node)
            if func_name:
                # 检查危险函数
                sink_info = self._is_dangerous_function(func_name, context.language)
                if sink_info:
                    self._sinks.append(TaintSink(
                        name=func_name,
                        node=node,
                        file_path=context.file_path,
                        line=node.start_point[0] + 1,
                        description=f"危险函数: {func_name}()",
                        vulnerability_type=sink_info["type"]
                    ))

    def _is_dangerous_function(self, func_name: str, language: str) -> Optional[Dict[str, str]]:
        """检查是否为危险函数

        Args:
            func_name: 函数名
            language: 语言

        Returns:
            危险函数信息
        """
        dangerous_functions = {
            "python": {
                "eval": {"type": "Code Injection"},
                "exec": {"type": "Code Injection"},
                "execfile": {"type": "Code Injection"},
                "os.system": {"type": "Command Injection"},
                "os.popen": {"type": "Command Injection"},
                "subprocess.Popen": {"type": "Command Injection"},
                "subprocess.call": {"type": "Command Injection"},
                "subprocess.run": {"type": "Command Injection"},
                "execute": {"type": "SQL Injection"},
                "executemany": {"type": "SQL Injection"},
                "query": {"type": "SQL Injection"},
                "raw": {"type": "SQL Injection"},
            },
            "javascript": {
                "eval": {"type": "Code Injection"},
                "new Function": {"type": "Code Injection"},
                "Function": {"type": "Code Injection"},
                "exec": {"type": "Command Injection"},
                "spawn": {"type": "Command Injection"},
                "execFile": {"type": "Command Injection"},
                "document.write": {"type": "XSS"},
                "innerHTML": {"type": "XSS"},
            }
        }

        language_functions = dangerous_functions.get(language, {})
        return language_functions.get(func_name)

    def _build_data_flow_paths(self) -> None:
        """构建数据流路径

        识别从输入源到危险函数的传播路径。
        """
        # 简化版实现：基于变量传播
        # 实际实现需要更复杂的数据流分析
        for sink in self._sinks:
            # 检查危险函数调用中是否使用了受污染的变量
            # 简化实现：假设危险函数调用中包含受污染的变量
            for source in self._sources:
                # 构建路径
                path = [source.name, sink.name]
                self._paths.append(TaintPath(
                    source=source,
                    sink=sink,
                    path=path,
                    confidence=0.8
                ))

    def _get_function_name(self, node: Node) -> Optional[str]:
        """获取函数名

        Args:
            node: 函数调用节点

        Returns:
            函数名
        """
        for child in node.children:
            if child.type in ["identifier", "attribute"]:
                return self._get_node_text(child)
        return None

    def _get_node_text(self, node: Node) -> str:
        """获取节点文本

        Args:
            node: AST 节点

        Returns:
            节点文本
        """
        if node.text:
            return node.text.decode()
        return ""

    def _get_parent_node(self, node: Node, levels: int = 1) -> Optional[Node]:
        """获取父节点

        Args:
            node: AST 节点
            levels: 向上查找的层级

        Returns:
            父节点
        """
        current = node
        for _ in range(levels):
            # 检查节点是否有父节点
            if hasattr(current, "parent") and current.parent:
                current = current.parent
            else:
                return None
        return current

    def _get_assignment_variable(self, node: Node) -> Optional[str]:
        """获取赋值变量名

        Args:
            node: 赋值表达式节点

        Returns:
            变量名
        """
        for child in node.children:
            if child.type in ["identifier", "pattern"]:
                return self._get_node_text(child)
        return None

    def _get_function_arguments(self, node: Node) -> List[Node]:
        """获取函数参数

        Args:
            node: 函数调用节点

        Returns:
            参数节点列表
        """
        args = []
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type not in [",", "(", ")"]:
                        args.append(arg)
        return args

    def _get_variable_name(self, node: Node) -> Optional[str]:
        """获取变量名

        Args:
            node: AST 节点

        Returns:
            变量名
        """
        if node.type == "identifier":
            return self._get_node_text(node)
        elif node.type == "string_literal":
            # 检查字符串拼接
            parent = self._get_parent_node(node, 1)
            if parent and parent.type == "binary_expression":
                # 检查是否包含变量
                for child in parent.children:
                    if child.type == "identifier":
                        return self._get_node_text(child)
        return None

    def get_standardized_output(self, paths: List[TaintPath]) -> List[Dict[str, Any]]:
        """获取标准化的输出格式

        Args:
            paths: 污点传播路径列表

        Returns:
            标准化的输出列表
        """
        output = []
        
        for path in paths:
            output.append({
                "type": "sink",
                "function": path.sink.name,
                "source": path.source.name,
                "location": f"{path.sink.file_path}:{path.sink.line}",
                "evidence": [
                    f"Taint: {path.source.description} → {path.sink.description}",
                    f"Path: {path.path}"
                ],
                "source_agent": "Taint-Agent",
                "confidence": path.confidence,
                "metadata": {
                    "vulnerability_type": path.sink.vulnerability_type,
                    "severity": path.evaluate_severity(),
                    "poc": path.poc
                }
            })

        return output

    async def analyze_with_ai(self, context: Any, ai_client: Any) -> List[TaintPath]:
        """AI 增强的污点分析

        结合规则快速标记和 AI 推理传播路径。

        Args:
            context: 分析上下文
            ai_client: AI 客户端

        Returns:
            污点传播路径列表
        """
        import json

        paths = self.analyze(context)

        if not paths:
            return paths

        for path in paths:
            prompt = self._build_ai_enhancement_prompt(context, path)
            try:
                response = await ai_client.generate(prompt)
                enhanced_info = json.loads(response)

                if enhanced_info.get('is_exploitable'):
                    path.confidence = enhanced_info.get('confidence', path.confidence)
                    path.poc = enhanced_info.get('payload', path.poc)

                    if enhanced_info.get('attack_path'):
                        path.path = enhanced_info['attack_path']
            except Exception:
                pass

        return paths

    def _build_ai_enhancement_prompt(self, context: Any, path: TaintPath) -> str:
        """构建 AI 增强提示词

        Args:
            context: 分析上下文
            path: 污点路径

        Returns:
            提示词
        """
        prompt = f"""你是污点传播分析专家，请分析以下数据流路径：

源代码：
{context.file_content}

污点源：{path.source.name} (行 {path.source.line})
危险函数：{path.sink.name} (行 {path.sink.line})
漏洞类型：{path.sink.vulnerability_type}

请分析：
1. 变量是否真的从源传播到汇？
2. 是否存在过滤或验证？
3. 是否可以利用？

输出 JSON：
{{"is_exploitable": true/false, "confidence": 0.0-1.0, "payload": "...", "attack_path": ["step1", "step2", ...]}}
"""
        return prompt