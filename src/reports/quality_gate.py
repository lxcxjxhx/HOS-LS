#!/usr/bin/env python3
"""
质量门禁检查器 v2.0

功能:
1. 验证规则是否通过质量门禁
2. 针对未达标项生成优化建议
3. 对比优化前后质量变化
4. 提供质量提升策略

版本：2.0
创建日期：2026-03-31
优化依据：基于用户 develop.json 习惯
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path


class QualityGateChecker:
    """质量门禁检查器"""
    
    def __init__(self, quality_thresholds: Optional[Dict[str, float]] = None):
        """
        初始化检查器
        
        Args:
            quality_thresholds: 质量阈值配置 (可选)
        """
        # 默认质量门禁标准
        self.default_thresholds = {
            'recall': {'threshold': 0.95, 'direction': '>=', 'weight': 0.25},
            'precision': {'threshold': 0.90, 'direction': '>=', 'weight': 0.20},
            'f1_score': {'threshold': 0.92, 'direction': '>=', 'weight': 0.25},
            'fpr': {'threshold': 0.05, 'direction': '<=', 'weight': 0.15},
            'fnr': {'threshold': 0.05, 'direction': '<=', 'weight': 0.15}
        }
        
        # 使用自定义阈值或默认值
        self.thresholds = quality_thresholds or self.default_thresholds
    
    def check_quality_gate(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        检查质量门禁
        
        Args:
            metrics: 质量指标字典
            
        Returns:
            门禁检查结果
        """
        gates = {}
        all_passed = True
        
        for metric_name, config in self.thresholds.items():
            actual_value = metrics.get(metric_name, 0)
            threshold = config['threshold']
            direction = config['direction']
            
            # 判断是否通过
            if direction == '>=':
                passed = actual_value >= threshold
            else:  # '<='
                passed = actual_value <= threshold
            
            gates[metric_name] = {
                'threshold': threshold,
                'actual': actual_value,
                'direction': direction,
                'passed': passed,
                'gap': abs(actual_value - threshold)
            }
            
            if not passed:
                all_passed = False
        
        return {
            'all_passed': all_passed,
            'gates': gates,
            'failed_gates': [k for k, v in gates.items() if not v['passed']],
            'passed_gates': [k for k, v in gates.items() if v['passed']],
            'overall_score': self._calculate_overall_score(metrics)
        }
    
    def _calculate_overall_score(self, metrics: Dict[str, Any]) -> float:
        """
        计算整体质量评分
        
        Args:
            metrics: 质量指标字典
            
        Returns:
            整体评分 (0-1)
        """
        score = 0.0
        
        for metric_name, config in self.thresholds.items():
            actual_value = metrics.get(metric_name, 0)
            threshold = config['threshold']
            weight = config.get('weight', 0.2)
            direction = config['direction']
            
            # 计算单项得分
            if direction == '>=':
                if actual_value >= threshold:
                    item_score = 1.0
                else:
                    item_score = max(0, actual_value / threshold)
            else:  # '<='
                if actual_value <= threshold:
                    item_score = 1.0
                else:
                    item_score = max(0, threshold / actual_value) if actual_value > 0 else 1.0
            
            score += item_score * weight
        
        return score
    
    def generate_optimization_suggestions(self, metrics: Dict[str, Any], 
                                        rule_data: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        针对未达标项生成优化建议
        
        Args:
            metrics: 质量指标字典
            rule_data: 规则数据 (可选)
            
        Returns:
            优化建议列表
        """
        suggestions = []
        quality_gate = self.check_quality_gate(metrics)
        
        # 针对每个未通过的指标生成建议
        for metric_name in quality_gate['failed_gates']:
            gate_info = quality_gate['gates'][metric_name]
            actual_value = gate_info['actual']
            threshold = gate_info['threshold']
            gap = gate_info['gap']
            
            # 根据指标类型生成具体建议
            if metric_name == 'recall':  # 检测率低
                suggestion = self._suggest_recall_improvement(rule_data, gap)
            elif metric_name == 'precision':  # 准确率低
                suggestion = self._suggest_precision_improvement(rule_data, gap)
            elif metric_name == 'f1_score':  # F1 分数低
                suggestion = self._suggest_f1_improvement(rule_data, gap)
            elif metric_name == 'fpr':  # 误报率高
                suggestion = self._suggest_fpr_reduction(rule_data, gap)
            elif metric_name == 'fnr':  # 漏报率高
                suggestion = self._suggest_fnr_reduction(rule_data, gap)
            else:
                continue
            
            suggestion['metric'] = metric_name
            suggestion['current_value'] = actual_value
            suggestion['target_value'] = threshold
            suggestion['gap'] = gap
            suggestion['priority'] = self._calculate_priority(gap, metric_name)
            
            suggestions.append(suggestion)
        
        # 按优先级排序
        suggestions.sort(key=lambda x: x['priority'], reverse=True)
        
        return suggestions
    
    def _suggest_recall_improvement(self, rule_data: Optional[Dict[str, Any]], gap: float) -> Dict[str, Any]:
        """检测率提升建议"""
        return {
            'type': 'ENHANCE_DETECTION',
            'priority_score': 0,  # 后续计算
            'actions': [
                {
                    'action': '增加检测模式',
                    'description': '分析漏报案例，提取共同特征，添加新的检测模式',
                    'expected_impact': f'检测率提升 {gap:.1%}'
                },
                {
                    'action': '扩展现有模式',
                    'description': '放宽现有检测模式的匹配条件，覆盖更多变体',
                    'expected_impact': '检测率提升 2-5%'
                },
                {
                    'action': '减少排除模式',
                    'description': '审查排除模式，移除过于宽泛的排除规则',
                    'expected_impact': '检测率提升 1-3%',
                    'warning': '可能增加误报，需谨慎'
                }
            ]
        }
    
    def _suggest_precision_improvement(self, rule_data: Optional[Dict[str, Any]], gap: float) -> Dict[str, Any]:
        """准确率提升建议"""
        return {
            'type': 'REDUCE_FALSE_POSITIVES',
            'priority_score': 0,
            'actions': [
                {
                    'action': '增加排除模式',
                    'description': '分析误报案例，提取共同特征，添加新的排除模式',
                    'expected_impact': f'准确率提升 {gap:.1%}'
                },
                {
                    'action': '收紧检测模式',
                    'description': '增加检测模式的特异性，减少宽泛匹配',
                    'expected_impact': '准确率提升 2-5%',
                    'warning': '可能降低检测率，需权衡'
                },
                {
                    'action': '增加上下文规则',
                    'description': '添加上下文判断逻辑，识别安全处理代码',
                    'expected_impact': '准确率提升 3-8%'
                }
            ]
        }
    
    def _suggest_f1_improvement(self, rule_data: Optional[Dict[str, Any]], gap: float) -> Dict[str, Any]:
        """F1 分数提升建议"""
        return {
            'type': 'BALANCE_PRECISION_RECALL',
            'priority_score': 0,
            'actions': [
                {
                    'action': '平衡检测率和准确率',
                    'description': '同时优化检测模式和排除模式，寻找最佳平衡点',
                    'expected_impact': f'F1 分数提升 {gap:.1%}'
                },
                {
                    'action': '调整置信度阈值',
                    'description': '根据实际场景调整置信度评分策略',
                    'expected_impact': 'F1 分数提升 1-3%'
                },
                {
                    'action': '增加测试覆盖',
                    'description': '补充边界测试用例，发现潜在问题',
                    'expected_impact': 'F1 分数提升 2-4%'
                }
            ]
        }
    
    def _suggest_fpr_reduction(self, rule_data: Optional[Dict[str, Any]], gap: float) -> Dict[str, Any]:
        """误报率降低建议"""
        return {
            'type': 'REDUCE_FALSE_POSITIVE_RATE',
            'priority_score': 0,
            'actions': [
                {
                    'action': '识别误报高发场景',
                    'description': '分析误报案例，识别高频误报的文件类型、代码模式',
                    'expected_impact': f'误报率降低 {gap:.1%}'
                },
                {
                    'action': '添加场景化排除规则',
                    'description': '针对误报高发场景添加特定的排除规则',
                    'expected_impact': '误报率降低 30-50%'
                },
                {
                    'action': '优化模式特异性',
                    'description': '增加模式的区分度，减少误匹配',
                    'expected_impact': '误报率降低 20-40%'
                }
            ]
        }
    
    def _suggest_fnr_reduction(self, rule_data: Optional[Dict[str, Any]], gap: float) -> Dict[str, Any]:
        """漏报率降低建议"""
        return {
            'type': 'REDUCE_FALSE_NEGATIVE_RATE',
            'priority_score': 0,
            'actions': [
                {
                    'action': '识别漏报盲区',
                    'description': '分析漏报案例，识别未覆盖的代码模式',
                    'expected_impact': f'漏报率降低 {gap:.1%}'
                },
                {
                    'action': '添加新模式',
                    'description': '针对漏报盲区添加专门的检测模式',
                    'expected_impact': '漏报率降低 40-60%'
                },
                {
                    'action': '扩展现有模式',
                    'description': '放宽现有模式的匹配条件',
                    'expected_impact': '漏报率降低 20-30%',
                    'warning': '可能增加误报，需权衡'
                }
            ]
        }
    
    def _calculate_priority(self, gap: float, metric_name: str) -> float:
        """
        计算优化优先级
        
        Args:
            gap: 与阈值的差距
            metric_name: 指标名称
            
        Returns:
            优先级分数 (0-1)
        """
        # 不同指标的权重
        weights = {
            'recall': 0.25,
            'precision': 0.20,
            'f1_score': 0.25,
            'fpr': 0.15,
            'fnr': 0.15
        }
        
        weight = weights.get(metric_name, 0.2)
        
        # 优先级 = 差距 * 权重
        priority = min(1.0, gap * weight * 5)  # 归一化到 0-1
        
        return priority
    
    def compare_versions(self, old_metrics: Dict[str, Any], 
                        new_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        对比两个版本的质量指标
        
        Args:
            old_metrics: 旧版本指标
            new_metrics: 新版本指标
            
        Returns:
            对比结果
        """
        comparison = {
            'metrics': {},
            'improvements': [],
            'regressions': [],
            'overall_improvement': 0
        }
        
        for metric_name in self.thresholds.keys():
            old_value = old_metrics.get(metric_name, 0)
            new_value = new_metrics.get(metric_name, 0)
            change = new_value - old_value
            
            # 判断是改进还是退步 (考虑方向)
            direction = self.thresholds[metric_name]['direction']
            
            if direction == '>=':
                is_improvement = change > 0
            else:  # '<='
                is_improvement = change < 0
            
            comparison['metrics'][metric_name] = {
                'old': old_value,
                'new': new_value,
                'change': change,
                'change_percent': (change / old_value * 100) if old_value > 0 else 0,
                'is_improvement': is_improvement
            }
            
            if is_improvement:
                comparison['improvements'].append(metric_name)
            elif change != 0:
                comparison['regressions'].append(metric_name)
        
        # 计算整体改进
        old_score = self._calculate_overall_score(old_metrics)
        new_score = self._calculate_overall_score(new_metrics)
        comparison['overall_improvement'] = new_score - old_score
        
        return comparison
    
    def generate_quality_report(self, metrics: Dict[str, Any], 
                               rule_data: Optional[Dict[str, Any]] = None) -> str:
        """
        生成质量报告
        
        Args:
            metrics: 质量指标
            rule_data: 规则数据
            
        Returns:
            质量报告 (Markdown 格式)
        """
        quality_gate = self.check_quality_gate(metrics)
        suggestions = self.generate_optimization_suggestions(metrics, rule_data)
        
        report = f"""# 质量门禁检查报告

**生成时间**: {datetime.now().isoformat()}
**规则 ID**: {rule_data.get('id', 'N/A') if rule_data else 'N/A'}

## 整体结果

**质量门禁**: {'✓ 通过' if quality_gate['all_passed'] else '✗ 未通过'}

**整体评分**: {quality_gate['overall_score']:.2%}

## 指标详情

| 指标 | 阈值 | 实际值 | 差距 | 结果 |
|------|------|--------|------|------|
"""
        
        # 添加指标详情
        for metric_name, gate_info in quality_gate['gates'].items():
            status_icon = '✓' if gate_info['passed'] else '✗'
            direction_symbol = '≥' if gate_info['direction'] == '>=' else '≤'
            report += f"| {metric_name.upper()} | {direction_symbol}{gate_info['threshold']:.2%} | {gate_info['actual']:.2%} | {gate_info['gap']:+.2%} | {status_icon} |\n"
        
        # 添加优化建议
        if suggestions:
            report += f"""
## 优化建议

共 {len(suggestions)} 条建议，按优先级排序:

"""
            for i, suggestion in enumerate(suggestions, 1):
                report += f"### {i}. {suggestion['type']} (优先级：{suggestion['priority']:.2f})\n\n"
                report += f"**当前值**: {suggestion['current_value']:.2%}  \n"
                report += f"**目标值**: {suggestion['target_value']:.2%}  \n"
                report += f"**差距**: {suggestion['gap']:.2%}\n\n"
                
                report += "**建议措施**:\n\n"
                for action in suggestion['actions']:
                    report += f"- **{action['action']}**: {action['description']}\n"
                    report += f"  - 预期影响：{action['expected_impact']}\n"
                    if 'warning' in action:
                        report += f"  - ⚠️ 注意：{action['warning']}\n"
                report += "\n"
        else:
            report += "\n## 优化建议\n\n✓ 所有指标均已达标，无需优化\n"
        
        return report
    
    def save_report(self, metrics: Dict[str, Any], output_path: str,
                   rule_data: Optional[Dict[str, Any]] = None):
        """
        保存质量报告到文件
        
        Args:
            metrics: 质量指标
            output_path: 输出文件路径
            rule_data: 规则数据
        """
        report = self.generate_quality_report(metrics, rule_data)
        
        # 确保目录存在
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"质量报告已保存到：{output_path}")


def main():
    """主函数"""
    # 示例质量指标
    metrics = {
        'recall': 0.92,
        'precision': 0.88,
        'f1_score': 0.90,
        'fpr': 0.08,
        'fnr': 0.06
    }
    
    # 示例规则数据
    rule_data = {
        'id': 'ai_security.test_rule',
        'patterns': ['test_pattern'],
        'exclude_patterns': ['test_exclude'],
        'severity': 'HIGH',
        'confidence': 0.85
    }
    
    # 创建检查器
    checker = QualityGateChecker()
    
    # 检查质量门禁
    quality_gate = checker.check_quality_gate(metrics)
    print(f"质量门禁：{'✓ 通过' if quality_gate['all_passed'] else '✗ 未通过'}")
    print(f"整体评分：{quality_gate['overall_score']:.2%}")
    print(f"未通过指标：{', '.join(quality_gate['failed_gates'])}")
    
    # 生成优化建议
    suggestions = checker.generate_optimization_suggestions(metrics, rule_data)
    print(f"\n共 {len(suggestions)} 条优化建议:")
    for suggestion in suggestions:
        print(f"- {suggestion['type']} (优先级：{suggestion['priority']:.2f})")
    
    # 版本对比示例
    old_metrics = {
        'recall': 0.85,
        'precision': 0.82,
        'f1_score': 0.835,
        'fpr': 0.12,
        'fnr': 0.10
    }
    
    comparison = checker.compare_versions(old_metrics, metrics)
    print(f"\n版本对比:")
    print(f"整体改进：{comparison['overall_improvement']:+.2%}")
    print(f"改进指标：{', '.join(comparison['improvements'])}")
    print(f"退步指标：{', '.join(comparison['regressions']) if comparison['regressions'] else '无'}")
    
    # 生成并保存报告
    checker.save_report(metrics, 'quality_report.md', rule_data)


if __name__ == '__main__':
    main()
