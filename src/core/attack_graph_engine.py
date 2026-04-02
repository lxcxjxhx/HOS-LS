import networkx as nx
from typing import List, Dict, Any, Optional
from .context_builder import ContextBuilder

class AttackGraphEngine:
    def __init__(self):
        """
        初始化攻击链分析引擎
        """
        self.graph = nx.DiGraph()
        self.context_builder = ContextBuilder()
    
    def build_attack_graph(self, files: List[str]) -> nx.DiGraph:
        """
        构建攻击图
        
        Args:
            files: 要分析的文件列表
            
        Returns:
            攻击图
        """
        # 构建上下文
        context = self.context_builder.build(files)
        
        # 添加节点和边
        self._add_nodes(context)
        self._add_edges(context)
        
        return self.graph
    
    def analyze_attack_chains(self, files: List[str]) -> List[Dict[str, Any]]:
        """
        分析攻击链
        
        Args:
            files: 要分析的文件列表
            
        Returns:
            攻击链分析结果
        """
        # 构建攻击图
        self.build_attack_graph(files)
        
        # 识别攻击链
        attack_chains = self._identify_attack_chains()
        
        # 分析每个攻击链的风险
        analyzed_chains = []
        for chain in attack_chains:
            risk = self._calculate_chain_risk(chain)
            steps = self._generate_attack_steps(chain)
            
            analyzed_chains.append({
                "chain": chain,
                "risk": risk,
                "steps": steps
            })
        
        return analyzed_chains
    
    def _add_nodes(self, context: Dict[str, Any]):
        """
        添加节点到攻击图
        """
        # 添加入口点节点
        for entry_point in context.get("entry_points", []):
            node_id = f"entry_{entry_point['name']}_{entry_point['file']}"
            self.graph.add_node(node_id, 
                              type="entry_point", 
                              name=entry_point['name'],
                              file=entry_point['file'],
                              line=entry_point.get('line', 0))
        
        # 添加危险调用节点
        for danger_call in context.get("danger_calls", []):
            node_id = f"danger_{danger_call['function']}_{danger_call['file']}_{danger_call.get('line', 0)}"
            self.graph.add_node(node_id, 
                              type="danger_call", 
                              function=danger_call['function'],
                              file=danger_call['file'],
                              line=danger_call.get('line', 0),
                              in_function=danger_call.get('in_function', ''))
        
        # 添加数据流节点
        for data_flow in context.get("data_flow", []):
            node_id = f"dataflow_{data_flow['source']}_{data_flow['sink']}_{data_flow['file']}"
            self.graph.add_node(node_id, 
                              type="data_flow", 
                              source=data_flow['source'],
                              sink=data_flow['sink'],
                              file=data_flow['file'])
    
    def _add_edges(self, context: Dict[str, Any]):
        """
        添加边到攻击图
        """
        # 连接入口点到危险调用
        entry_points = context.get("entry_points", [])
        danger_calls = context.get("danger_calls", [])
        
        # 简单的连接逻辑：同一文件中的入口点和危险调用
        for entry_point in entry_points:
            entry_file = entry_point['file']
            entry_node_id = f"entry_{entry_point['name']}_{entry_file}"
            
            for danger_call in danger_calls:
                if danger_call['file'] == entry_file:
                    danger_node_id = f"danger_{danger_call['function']}_{danger_call['file']}_{danger_call.get('line', 0)}"
                    self.graph.add_edge(entry_node_id, danger_node_id, type="potential_attack")
        
        # 连接数据流
        data_flows = context.get("data_flow", [])
        for data_flow in data_flows:
            source_node_id = f"entry_{data_flow['source']}_{data_flow['file']}"
            sink_node_id = f"danger_{data_flow['sink']}_{data_flow['file']}_0"
            
            if source_node_id in self.graph.nodes and sink_node_id in self.graph.nodes:
                self.graph.add_edge(source_node_id, sink_node_id, type="data_flow")
    
    def _identify_attack_chains(self) -> List[List[str]]:
        """
        识别攻击链
        """
        attack_chains = []
        
        # 找到所有入口点节点
        entry_nodes = [node for node, attrs in self.graph.nodes(data=True) if attrs.get('type') == 'entry_point']
        
        # 找到所有危险调用节点
        danger_nodes = [node for node, attrs in self.graph.nodes(data=True) if attrs.get('type') == 'danger_call']
        
        # 寻找从入口点到危险调用的路径
        for entry_node in entry_nodes:
            for danger_node in danger_nodes:
                if nx.has_path(self.graph, entry_node, danger_node):
                    paths = list(nx.all_simple_paths(self.graph, entry_node, danger_node))
                    for path in paths:
                        if len(path) > 1:  # 确保路径至少有两个节点
                            attack_chains.append(path)
        
        return attack_chains
    
    def _calculate_chain_risk(self, chain: List[str]) -> str:
        """
        计算攻击链的风险等级
        """
        # 基于链的长度和危险调用类型计算风险
        chain_length = len(chain)
        
        # 检查链中是否包含高风险操作
        high_risk_operations = ['exec', 'eval', 'os.system', 'subprocess']
        medium_risk_operations = ['open', 'cursor.execute', 'db.execute']
        
        has_high_risk = False
        has_medium_risk = False
        
        for node_id in chain:
            node_attrs = self.graph.nodes.get(node_id, {})
            if node_attrs.get('type') == 'danger_call':
                function = node_attrs.get('function', '')
                for op in high_risk_operations:
                    if op in function:
                        has_high_risk = True
                        break
                for op in medium_risk_operations:
                    if op in function:
                        has_medium_risk = True
                        break
        
        if has_high_risk:
            return "High"
        elif has_medium_risk:
            return "Medium"
        else:
            return "Low"
    
    def _generate_attack_steps(self, chain: List[str]) -> List[str]:
        """
        生成攻击步骤
        """
        steps = []
        
        for i, node_id in enumerate(chain):
            node_attrs = self.graph.nodes.get(node_id, {})
            node_type = node_attrs.get('type')
            
            if node_type == 'entry_point':
                steps.append(f"Step {i+1}: 攻击者通过入口点 '{node_attrs.get('name')}' 进入系统")
            elif node_type == 'danger_call':
                steps.append(f"Step {i+1}: 利用危险调用 '{node_attrs.get('function')}' 执行恶意操作")
            elif node_type == 'data_flow':
                steps.append(f"Step {i+1}: 数据流从 '{node_attrs.get('source')}' 传递到 '{node_attrs.get('sink')}'")
        
        return steps
    
    def visualize_graph(self, output_file: str = "attack_graph.png"):
        """
        可视化攻击图
        
        Args:
            output_file: 输出文件路径
        """
        try:
            import matplotlib.pyplot as plt
            
            # 绘制图形
            pos = nx.spring_layout(self.graph)
            nx.draw(self.graph, pos, with_labels=True, node_size=1000, node_color='lightblue', font_size=8)
            
            # 保存图形
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Attack graph visualized and saved to {output_file}")
        except ImportError:
            print("matplotlib is not installed, cannot visualize graph")
        except Exception as e:
            print(f"Error visualizing graph: {e}")
