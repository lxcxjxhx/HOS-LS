"""攻击链可视化模块

生成攻击链的可视化图表和风险热力图。
"""

import json
import os
from typing import Dict, Any, List, Optional
from pathlib import Path

import plotly.graph_objects as go
import networkx as nx
from plotly.subplots import make_subplots


class GraphVisualizer:
    """攻击链可视化工具"""
    
    def __init__(self):
        self.output_dir = os.path.join(os.getcwd(), "visualizations")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_attack_chain_graph(self, attack_chains: List[Dict[str, Any]]) -> str:
        """生成攻击链可视化图表
        
        Args:
            attack_chains: 攻击链列表
            
        Returns:
            图表文件路径
        """
        try:
            # 创建图形
            fig = go.Figure()
            
            # 处理每个攻击链
            for chain_idx, chain in enumerate(attack_chains):
                nodes = chain.get('nodes', [])
                edges = chain.get('edges', [])
                
                # 创建节点位置
                pos = self._calculate_node_positions(nodes)
                
                # 添加节点
                for node in nodes:
                    node_id = node.get('id')
                    node_label = node.get('label', node_id)
                    node_type = node.get('type', 'unknown')
                    severity = node.get('severity', 'low')
                    
                    # 根据节点类型和严重程度设置颜色
                    color = self._get_node_color(node_type, severity)
                    
                    fig.add_trace(go.Scatter(
                        x=[pos[node_id][0]],
                        y=[pos[node_id][1]],
                        mode='markers+text',
                        marker=dict(
                            size=20,
                            color=color,
                            line=dict(width=2, color='black')
                        ),
                        text=node_label,
                        textposition='top center',
                        name=f'Node {node_id}'
                    ))
                
                # 添加边
                for edge in edges:
                    source = edge.get('source')
                    target = edge.get('target')
                    edge_label = edge.get('label', '')
                    
                    if source in pos and target in pos:
                        fig.add_trace(go.Scatter(
                            x=[pos[source][0], pos[target][0]],
                            y=[pos[source][1], pos[target][1]],
                            mode='lines',
                            line=dict(width=2, color='grey'),
                            text=edge_label,
                            textposition='middle center',
                            name=f'Edge {source}->{target}'
                        ))
            
            # 设置布局
            fig.update_layout(
                title="攻击链可视化",
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                showlegend=False,
                hovermode='closest'
            )
            
            # 保存图表
            output_path = os.path.join(self.output_dir, "attack_chain_graph.html")
            fig.write_html(output_path)
            
            return output_path
        except Exception as e:
            print(f"生成攻击链图表时出错: {e}")
            return ""
    
    def generate_risk_heatmap(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """生成风险热力图
        
        Args:
            vulnerabilities: 漏洞列表
            
        Returns:
            图表文件路径
        """
        try:
            # 准备热力图数据
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            # 统计各严重程度的漏洞数量
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'info')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # 创建热力图
            fig = go.Figure(data=go.Heatmap(
                z=[[severity_counts['critical'], severity_counts['high'], severity_counts['medium'], severity_counts['low'], severity_counts['info']]],
                x=['Critical', 'High', 'Medium', 'Low', 'Info'],
                y=['Vulnerabilities'],
                colorscale='Reds',
                hoverongaps=False,
                colorbar=dict(title='Count')
            ))
            
            # 设置布局
            fig.update_layout(
                title="风险热力图",
                xaxis_title="Severity",
                yaxis_title="Count"
            )
            
            # 保存图表
            output_path = os.path.join(self.output_dir, "risk_heatmap.html")
            fig.write_html(output_path)
            
            return output_path
        except Exception as e:
            print(f"生成风险热力图时出错: {e}")
            return ""
    
    def generate_attack_path_graph(self, attack_paths: List[Dict[str, Any]]) -> str:
        """生成攻击路径图表
        
        Args:
            attack_paths: 攻击路径列表
            
        Returns:
            图表文件路径
        """
        try:
            # 创建子图
            fig = make_subplots(rows=len(attack_paths), cols=1, subplot_titles=[f"攻击路径 {i+1}" for i in range(len(attack_paths))])
            
            # 处理每个攻击路径
            for i, path in enumerate(attack_paths):
                nodes = path.get('nodes', [])
                edges = path.get('edges', [])
                
                # 创建节点位置
                pos = self._calculate_node_positions(nodes)
                
                # 添加节点
                for node in nodes:
                    node_id = node.get('id')
                    node_label = node.get('label', node_id)
                    node_type = node.get('type', 'unknown')
                    severity = node.get('severity', 'low')
                    
                    # 根据节点类型和严重程度设置颜色
                    color = self._get_node_color(node_type, severity)
                    
                    fig.add_trace(go.Scatter(
                        x=[pos[node_id][0]],
                        y=[pos[node_id][1]],
                        mode='markers+text',
                        marker=dict(
                            size=15,
                            color=color,
                            line=dict(width=2, color='black')
                        ),
                        text=node_label,
                        textposition='top center',
                        name=f'Node {node_id}'
                    ), row=i+1, col=1)
                
                # 添加边
                for edge in edges:
                    source = edge.get('source')
                    target = edge.get('target')
                    edge_label = edge.get('label', '')
                    
                    if source in pos and target in pos:
                        fig.add_trace(go.Scatter(
                            x=[pos[source][0], pos[target][0]],
                            y=[pos[source][1], pos[target][1]],
                            mode='lines',
                            line=dict(width=2, color='grey'),
                            text=edge_label,
                            textposition='middle center',
                            name=f'Edge {source}->{target}'
                        ), row=i+1, col=1)
            
            # 设置布局
            fig.update_layout(
                height=300 * len(attack_paths),
                showlegend=False,
                hovermode='closest'
            )
            
            # 保存图表
            output_path = os.path.join(self.output_dir, "attack_path_graph.html")
            fig.write_html(output_path)
            
            return output_path
        except Exception as e:
            print(f"生成攻击路径图表时出错: {e}")
            return ""
    
    def _calculate_node_positions(self, nodes: List[Dict[str, Any]]) -> Dict[str, List[float]]:
        """计算节点位置
        
        Args:
            nodes: 节点列表
            
        Returns:
            节点位置字典
        """
        pos = {}
        for i, node in enumerate(nodes):
            node_id = node.get('id')
            pos[node_id] = [i * 10, 0]
        return pos
    
    def _get_node_color(self, node_type: str, severity: str) -> str:
        """获取节点颜色
        
        Args:
            node_type: 节点类型
            severity: 严重程度
            
        Returns:
            颜色值
        """
        # 根据严重程度设置颜色
        severity_colors = {
            'critical': '#FF0000',  # 红色
            'high': '#FF8000',      # 橙色
            'medium': '#FFFF00',    # 黄色
            'low': '#00FF00',       # 绿色
            'info': '#0000FF'        # 蓝色
        }
        
        # 根据节点类型调整颜色
        type_adjustments = {
            'source': lambda c: c,           # 保持原色
            'sink': lambda c: c,             # 保持原色
            'function': lambda c: '#808080', # 灰色
            'class': lambda c: '#C0C0C0',    # 浅灰色
            'vulnerability': lambda c: c,    # 保持原色
            'attack_path': lambda c: '#800080' # 紫色
        }
        
        base_color = severity_colors.get(severity, '#0000FF')
        adjuster = type_adjustments.get(node_type, lambda c: c)
        return adjuster(base_color)
    
    def generate_dashboard(self, analysis_results: Dict[str, Any]) -> str:
        """生成综合仪表盘
        
        Args:
            analysis_results: 分析结果
            
        Returns:
            仪表盘文件路径
        """
        try:
            # 创建子图
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=(
                    "攻击链可视化",
                    "风险热力图",
                    "漏洞分布",
                    "攻击路径分析"
                )
            )
            
            # 1. 攻击链可视化
            attack_chains = analysis_results.get('attack_chains', [])
            if attack_chains:
                chain = attack_chains[0]  # 取第一个攻击链
                nodes = chain.get('nodes', [])
                edges = chain.get('edges', [])
                pos = self._calculate_node_positions(nodes)
                
                # 添加节点
                for node in nodes:
                    node_id = node.get('id')
                    node_label = node.get('label', node_id)
                    node_type = node.get('type', 'unknown')
                    severity = node.get('severity', 'low')
                    color = self._get_node_color(node_type, severity)
                    
                    fig.add_trace(go.Scatter(
                        x=[pos[node_id][0]],
                        y=[pos[node_id][1]],
                        mode='markers+text',
                        marker=dict(
                            size=15,
                            color=color,
                            line=dict(width=2, color='black')
                        ),
                        text=node_label,
                        textposition='top center',
                        name=f'Node {node_id}'
                    ), row=1, col=1)
                
                # 添加边
                for edge in edges:
                    source = edge.get('source')
                    target = edge.get('target')
                    if source in pos and target in pos:
                        fig.add_trace(go.Scatter(
                            x=[pos[source][0], pos[target][0]],
                            y=[pos[source][1], pos[target][1]],
                            mode='lines',
                            line=dict(width=2, color='grey'),
                            name=f'Edge {source}->{target}'
                        ), row=1, col=1)
            
            # 2. 风险热力图
            vulnerabilities = analysis_results.get('vulnerabilities', [])
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'info')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            fig.add_trace(go.Heatmap(
                z=[[severity_counts['critical'], severity_counts['high'], severity_counts['medium'], severity_counts['low'], severity_counts['info']]],
                x=['Critical', 'High', 'Medium', 'Low', 'Info'],
                y=['Vulnerabilities'],
                colorscale='Reds',
                hoverongaps=False,
                colorbar=dict(title='Count')
            ), row=1, col=2)
            
            # 3. 漏洞分布
            vuln_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', 'unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            fig.add_trace(go.Bar(
                x=list(vuln_types.keys()),
                y=list(vuln_types.values()),
                name='漏洞类型分布'
            ), row=2, col=1)
            
            # 4. 攻击路径分析
            attack_paths = analysis_results.get('attack_paths', [])
            if attack_paths:
                path = attack_paths[0]  # 取第一个攻击路径
                nodes = path.get('nodes', [])
                edges = path.get('edges', [])
                pos = self._calculate_node_positions(nodes)
                
                # 添加节点
                for node in nodes:
                    node_id = node.get('id')
                    node_label = node.get('label', node_id)
                    node_type = node.get('type', 'unknown')
                    severity = node.get('severity', 'low')
                    color = self._get_node_color(node_type, severity)
                    
                    fig.add_trace(go.Scatter(
                        x=[pos[node_id][0]],
                        y=[pos[node_id][1]],
                        mode='markers+text',
                        marker=dict(
                            size=12,
                            color=color,
                            line=dict(width=1, color='black')
                        ),
                        text=node_label,
                        textposition='top center',
                        name=f'Node {node_id}'
                    ), row=2, col=2)
                
                # 添加边
                for edge in edges:
                    source = edge.get('source')
                    target = edge.get('target')
                    if source in pos and target in pos:
                        fig.add_trace(go.Scatter(
                            x=[pos[source][0], pos[target][0]],
                            y=[pos[source][1], pos[target][1]],
                            mode='lines',
                            line=dict(width=1, color='grey'),
                            name=f'Edge {source}->{target}'
                        ), row=2, col=2)
            
            # 设置布局
            fig.update_layout(
                height=800,
                showlegend=False,
                hovermode='closest'
            )
            
            # 保存仪表盘
            output_path = os.path.join(self.output_dir, "dashboard.html")
            fig.write_html(output_path)
            
            return output_path
        except Exception as e:
            print(f"生成仪表盘时出错: {e}")
            return ""
