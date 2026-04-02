#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻击面分析模块

功能：
1. 攻击面图（Attack Surface Graph）生成
2. API 依赖关系分析
3. AI Prompt/Agent 链路分析
4. 攻击面可视化
"""

import os
import json
import re
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass
import networkx as nx

# 尝试导入 matplotlib，失败时不影响核心功能
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

@dataclass
class AttackSurfaceNode:
    """攻击面节点"""
    id: str
    type: str  # endpoint, function, api, prompt, tool
    name: str
    path: str
    risk_level: str  # low, medium, high, critical
    details: Dict[str, Any]

@dataclass
class AttackSurfaceEdge:
    """攻击面边"""
    source: str
    target: str
    type: str  # calls, uses, injects, triggers
    description: str

class AttackSurfaceAnalyzer:
    """攻击面分析器"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, AttackSurfaceNode] = {}
        self.edges: List[AttackSurfaceEdge] = []
        self.api_calls: Set[str] = set()
        self.prompt_injection_points: List[Dict[str, Any]] = []
        self.tool_calls: List[Dict[str, Any]] = []
    
    def analyze(self, target: str) -> Dict[str, Any]:
        """分析目标代码库的攻击面"""
        if os.path.isfile(target):
            self._analyze_file(target)
        elif os.path.isdir(target):
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in ['node_modules', 'venv', '__pycache__', '.git']]
                for file in files:
                    if file.endswith(('.py', '.js', '.ts', '.json', '.yaml', '.yml')):
                        file_path = os.path.join(root, file)
                        self._analyze_file(file_path)
        
        return self._generate_report()
    
    def _analyze_file(self, file_path: str):
        """分析单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 分析 API 调用
            self._analyze_api_calls(file_path, content)
            
            # 分析 Prompt 注入点
            self._analyze_prompt_injection(file_path, content)
            
            # 分析 Tool 调用
            self._analyze_tool_calls(file_path, content)
            
            # 分析函数调用关系
            self._analyze_function_calls(file_path, content)
            
        except Exception as e:
            print(f"分析文件 {file_path} 时出错: {e}")
    
    def _analyze_api_calls(self, file_path: str, content: str):
        """分析 API 调用"""
        # 匹配常见的 API 调用模式
        api_patterns = [
            r'\b(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["\'](.*?)["\']',
            r'\brequests\.(get|post|put|delete|patch)\s*\(\s*["\'](.*?)["\']',
            r'\baxios\.(get|post|put|delete|patch)\s*\(\s*["\'](.*?)["\']',
            r'\bfetch\s*\(\s*["\'](.*?)["\']',
            r'\bhttp\.(get|post|put|delete|patch)\s*\(\s*["\'](.*?)["\']',
            r'\brest\.(get|post|put|delete|patch)\s*\(\s*["\'](.*?)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) >= 2:
                    api_endpoint = match.group(2)
                    method = match.group(1) if len(match.groups()) > 1 else "GET"
                    self.api_calls.add(api_endpoint)
                    
                    # 创建 API 节点
                    node_id = f"api_{api_endpoint}"
                    if node_id not in self.nodes:
                        node = AttackSurfaceNode(
                            id=node_id,
                            type="api",
                            name=api_endpoint,
                            path=file_path,
                            risk_level="medium",
                            details={
                                "method": method,
                                "line_number": content[:match.start()].count('\n') + 1
                            }
                        )
                        self.nodes[node_id] = node
                        self.graph.add_node(node_id, **node.__dict__)
    
    def _analyze_prompt_injection(self, file_path: str, content: str):
        """分析 Prompt 注入点"""
        # 匹配 Prompt 相关代码
        prompt_patterns = [
            r'\bprompt\s*=\s*["\'](.*?)["\']',
            r'\bsystem_prompt\s*=\s*["\'](.*?)["\']',
            r'\buser_prompt\s*=\s*["\'](.*?)["\']',
            r'\bgenerate\s*\(\s*["\'](.*?)["\']',
            r'\bchat\s*\(\s*["\'](.*?)["\']',
        ]
        
        for pattern in prompt_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if match.groups():
                    prompt_content = match.group(1)
                    line_number = content[:match.start()].count('\n') + 1
                    
                    injection_point = {
                        "file": file_path,
                        "line_number": line_number,
                        "prompt_content": prompt_content[:100] + "..." if len(prompt_content) > 100 else prompt_content,
                        "risk_level": "high"
                    }
                    self.prompt_injection_points.append(injection_point)
                    
                    # 创建 Prompt 节点
                    node_id = f"prompt_{file_path}_{line_number}"
                    if node_id not in self.nodes:
                        node = AttackSurfaceNode(
                            id=node_id,
                            type="prompt",
                            name="Prompt Injection Point",
                            path=file_path,
                            risk_level="high",
                            details=injection_point
                        )
                        self.nodes[node_id] = node
                        self.graph.add_node(node_id, **node.__dict__)
    
    def _analyze_tool_calls(self, file_path: str, content: str):
        """分析 Tool 调用"""
        # 匹配 Tool 调用模式
        tool_patterns = [
            r'\btool\.call\s*\(\s*["\'](.*?)["\']',
            r'\btools\.invoke\s*\(\s*["\'](.*?)["\']',
            r'\bexecute_tool\s*\(\s*["\'](.*?)["\']',
            r'\bcall_tool\s*\(\s*["\'](.*?)["\']',
        ]
        
        for pattern in tool_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.groups():
                    tool_name = match.group(1)
                    line_number = content[:match.start()].count('\n') + 1
                    
                    tool_call = {
                        "file": file_path,
                        "line_number": line_number,
                        "tool_name": tool_name,
                        "risk_level": "medium"
                    }
                    self.tool_calls.append(tool_call)
                    
                    # 创建 Tool 节点
                    node_id = f"tool_{tool_name}"
                    if node_id not in self.nodes:
                        node = AttackSurfaceNode(
                            id=node_id,
                            type="tool",
                            name=tool_name,
                            path=file_path,
                            risk_level="medium",
                            details=tool_call
                        )
                        self.nodes[node_id] = node
                        self.graph.add_node(node_id, **node.__dict__)
    
    def _analyze_function_calls(self, file_path: str, content: str):
        """分析函数调用关系"""
        # 提取函数定义
        function_defs = re.findall(r'\b(def|function)\s+(\w+)\s*\(', content)
        functions = [func[1] for func in function_defs]
        
        # 提取函数调用
        for func_name in functions:
            call_pattern = rf'\b{func_name}\s*\(' 
            matches = re.finditer(call_pattern, content)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                # 创建函数节点
                node_id = f"function_{func_name}"
                if node_id not in self.nodes:
                    node = AttackSurfaceNode(
                        id=node_id,
                        type="function",
                        name=func_name,
                        path=file_path,
                        risk_level="low",
                        details={"line_number": line_number}
                    )
                    self.nodes[node_id] = node
                    self.graph.add_node(node_id, **node.__dict__)
    
    def _generate_report(self) -> Dict[str, Any]:
        """生成攻击面分析报告"""
        # 构建攻击面图
        self._build_attack_surface_graph()
        
        # 生成报告
        report = {
            "attack_surface_graph": {
                "nodes": [node.__dict__ for node in self.nodes.values()],
                "edges": [edge.__dict__ for edge in self.edges],
                "metrics": {
                    "total_nodes": len(self.nodes),
                    "total_edges": len(self.edges),
                    "high_risk_nodes": sum(1 for node in self.nodes.values() if node.risk_level in ["high", "critical"]),
                    "medium_risk_nodes": sum(1 for node in self.nodes.values() if node.risk_level == "medium"),
                    "low_risk_nodes": sum(1 for node in self.nodes.values() if node.risk_level == "low")
                }
            },
            "api_dependencies": {
                "total_apis": len(self.api_calls),
                "apis": list(self.api_calls)
            },
            "prompt_injection_points": self.prompt_injection_points,
            "tool_calls": self.tool_calls,
            "recommendations": self._generate_recommendations()
        }
        
        return report
    
    def _build_attack_surface_graph(self):
        """构建攻击面图"""
        # 连接相关节点
        for injection_point in self.prompt_injection_points:
            prompt_node_id = f"prompt_{injection_point['file']}_{injection_point['line_number']}"
            # 查找相关的 tool 调用
            for tool_call in self.tool_calls:
                if tool_call['file'] == injection_point['file']:
                    tool_node_id = f"tool_{tool_call['tool_name']}"
                    if prompt_node_id in self.nodes and tool_node_id in self.nodes:
                        edge = AttackSurfaceEdge(
                            source=prompt_node_id,
                            target=tool_node_id,
                            type="triggers",
                            description="Prompt 可能触发 Tool 调用"
                        )
                        self.edges.append(edge)
                        self.graph.add_edge(prompt_node_id, tool_node_id, **edge.__dict__)
        
        # 连接 API 调用
        for api_endpoint in self.api_calls:
            api_node_id = f"api_{api_endpoint}"
            # 查找调用该 API 的函数
            for node_id, node in self.nodes.items():
                if node.type == "function" and api_endpoint in str(node.details):
                    edge = AttackSurfaceEdge(
                        source=node_id,
                        target=api_node_id,
                        type="calls",
                        description="Function calls API"
                    )
                    self.edges.append(edge)
                    self.graph.add_edge(node_id, api_node_id, **edge.__dict__)
    
    def _generate_recommendations(self) -> List[str]:
        """生成安全建议"""
        recommendations = []
        
        if self.prompt_injection_points:
            recommendations.append("对所有 Prompt 输入进行严格验证和过滤，防止注入攻击")
        
        if self.tool_calls:
            recommendations.append("对 Tool 调用进行权限控制和参数验证")
        
        if self.api_calls:
            recommendations.append("对 API 调用进行速率限制和身份验证")
        
        if len(self.nodes) > 50:
            recommendations.append("考虑实施微服务架构，减少攻击面")
        
        return recommendations
    
    def visualize(self, output_file: str = "attack_surface_graph.png"):
        """可视化攻击面图"""
        if not MATPLOTLIB_AVAILABLE:
            return f"matplotlib 不可用，无法生成可视化"
        
        try:
            plt.figure(figsize=(12, 8))
            
            # 节点颜色映射
            color_map = {
                "low": "#4CAF50",
                "medium": "#FFC107",
                "high": "#FF9800",
                "critical": "#F44336"
            }
            
            # 节点类型形状映射
            shape_map = {
                "api": "s",
                "prompt": "o",
                "tool": "d",
                "function": "^"
            }
            
            # 绘制节点
            pos = nx.spring_layout(self.graph, k=0.3, iterations=50)
            
            for node_id, node in self.nodes.items():
                color = color_map.get(node.risk_level, "#9E9E9E")
                shape = shape_map.get(node.type, "o")
                
                nx.draw_networkx_nodes(
                    self.graph,
                    pos,
                    nodelist=[node_id],
                    node_color=color,
                    node_shape=shape,
                    node_size=300,
                    alpha=0.8
                )
            
            # 绘制边
            nx.draw_networkx_edges(
                self.graph,
                pos,
                edge_color="#9E9E9E",
                alpha=0.5,
                width=1.0
            )
            
            # 绘制标签
            labels = {node_id: node.name[:20] for node_id, node in self.nodes.items()}
            nx.draw_networkx_labels(
                self.graph,
                pos,
                labels=labels,
                font_size=8,
                font_color="#333333"
            )
            
            plt.title("Attack Surface Graph")
            plt.axis("off")
            plt.tight_layout()
            plt.savefig(output_file, dpi=150)
            plt.close()
            
            return output_file
        except Exception as e:
            return f"生成可视化时出错：{e}"

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "."
    
    analyzer = AttackSurfaceAnalyzer()
    report = analyzer.analyze(target)
    
    print(json.dumps(report, indent=2, ensure_ascii=False))
    
    # 生成可视化
    try:
        output_file = analyzer.visualize()
        print(f"\n攻击面图已生成：{output_file}")
    except Exception as e:
        print(f"生成可视化时出错：{e}")