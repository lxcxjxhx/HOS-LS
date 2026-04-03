#!/usr/bin/env python3
"""
规则验证自动化脚本

功能：
1. 加载所有测试用例
2. 执行扫描验证
3. 计算质量指标
4. 生成验证报告（JSON/HTML）
"""

import os
import sys
import json
import re
from pathlib import Path
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from scanners.enhanced_scanner import EnhancedSecurityScanner


class RuleValidator:
    """规则验证器"""
    
    def __init__(self, rules_file, test_cases_dir):
        """
        初始化验证器
        
        Args:
            rules_file: 规则文件路径
            test_cases_dir: 测试用例目录
        """
        self.rules_file = rules_file
        self.test_cases_dir = test_cases_dir
        # 提供一个默认的 target 参数
        self.scanner = EnhancedSecurityScanner(target='.', rules_file=rules_file, silent=True)
        self.results = []
    
    def load_test_cases(self):
        """加载所有测试用例"""
        test_cases = []
        
        for root, dirs, files in os.walk(self.test_cases_dir):
            for file in files:
                if file.endswith('.py') and not file.startswith('__') and file != '.gitkeep':
                    file_path = os.path.join(root, file)
                    test_case = self._parse_test_case(file_path)
                    if test_case:
                        test_cases.append(test_case)
        
        return test_cases
    
    def _parse_test_case(self, file_path):
        """解析测试用例文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 从文件路径提取信息
            path_parts = Path(file_path).parts
            rule_category = path_parts[-3] if len(path_parts) >= 3 else 'unknown'
            rule_name = path_parts[-2] if len(path_parts) >= 2 else 'unknown'
            rule_id = f"{rule_category}.{rule_name}"
            
            # 从文件名提取测试类型
            file_name = Path(file_path).stem
            if file_name.startswith('positive'):
                test_type = 'positive'
                expected_detection = True
            elif file_name.startswith('negative'):
                test_type = 'negative'
                expected_detection = False
            elif file_name.startswith('boundary'):
                test_type = 'boundary'
                expected_detection = True  # 边界测试通常期望检测
            else:
                test_type = 'unknown'
                expected_detection = None
            
            # 从注释中提取元数据
            metadata = self._extract_metadata(content)
            
            test_case = {
                'file_path': file_path,
                'rule_id': metadata.get('rule_id', rule_id),
                'test_type': test_type,
                'test_id': metadata.get('test_id', f"{rule_id}-{test_type.upper()[:3]}-{file_name.split('_')[-1]}"),
                'description': metadata.get('description', 'No description'),
                'code': content,
                'expected_detection': metadata.get('expected_detection', expected_detection),
                'expected_severity': metadata.get('expected_severity', 'MEDIUM'),
                'code_type': metadata.get('code_type', 'unknown')
            }
            
            return test_case
            
        except Exception as e:
            print(f"⚠️  解析测试用例失败 {file_path}: {e}")
            return None
    
    def _extract_metadata(self, content):
        """从文件注释中提取元数据"""
        metadata = {}
        
        # 提取注释行（前 10 行）
        lines = content.split('\n')[:10]
        comment_lines = [line.strip() for line in lines if line.strip().startswith('#')]
        comment_text = '\n'.join(comment_lines)
        
        # 正则表达式提取
        patterns = {
            'test_id': r'Test Case ID:\s*(.+)',
            'rule_id': r'Rule:\s*(.+)',
            'test_type': r'Test Type:\s*(.+)',
            'description': r'Description:\s*(.+)',
            'expected_detection': r'Expected Detection:\s*(true|false)',
            'expected_severity': r'Expected Severity:\s*(CRITICAL|HIGH|MEDIUM|LOW)',
            'code_type': r'Code Type:\s*(vulnerable|safe|test|example)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, comment_text, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if key == 'expected_detection':
                    metadata[key] = value.lower() == 'true'
                else:
                    metadata[key] = value
        
        return metadata
    
    def run_single_test(self, test_case):
        """
        运行单个测试用例
        
        Args:
            test_case: 测试用例字典
            
        Returns:
            测试结果字典
        """
        try:
            # 1. 加载测试代码
            code = test_case['code']
            
            # 2. 执行扫描
            issues = self.scanner.scan_code(code)
            
            # 3. 检查是否检测到目标规则
            detected = any(
                issue.get('rule_id') == test_case['rule_id'] 
                for issue in issues
            )
            
            # 4. 比对预期结果
            expected = test_case['expected_detection']
            passed = (detected == expected)
            
            # 5. 记录结果
            result = {
                'test_id': test_case['test_id'],
                'rule_id': test_case['rule_id'],
                'description': test_case['description'],
                'test_type': test_case['test_type'],
                'expected': expected,
                'actual': detected,
                'passed': passed,
                'issues_found': len(issues),
                'issue_details': issues if not passed else []
            }
            
            return result
            
        except Exception as e:
            return {
                'test_id': test_case['test_id'],
                'rule_id': test_case['rule_id'],
                'description': test_case['description'],
                'test_type': test_case['test_type'],
                'passed': False,
                'error': str(e)
            }
    
    def run_all_tests(self):
        """运行所有测试用例"""
        test_cases = self.load_test_cases()
        print(f"共加载 {len(test_cases)} 个测试用例\n")
        
        passed_count = 0
        failed_count = 0
        
        for test_case in test_cases:
            result = self.run_single_test(test_case)
            self.results.append(result)
            
            if result['passed']:
                passed_count += 1
                status = "PASS"
                color = "\033[92m"  # Green
            else:
                failed_count += 1
                status = "FAIL"
                color = "\033[91m"  # Red
            
            reset = "\033[0m"
            print(f"{color}{status}{reset}: {test_case['rule_id']} - {test_case['description']}")
        
        print(f"\n{'='*60}")
        print(f"总计：{len(test_cases)} 个测试 | 通过 {passed_count} | 失败 {failed_count}")
        print(f"通过率：{passed_count/len(test_cases)*100:.1f}%")
        print(f"{'='*60}\n")
        
        return self.results
    
    def calculate_metrics(self):
        """计算关键指标"""
        if not self.results:
            return {}
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r.get('passed', False))
        
        # 按规则分组统计
        rule_stats = {}
        for result in self.results:
            rule_id = result['rule_id']
            if rule_id not in rule_stats:
                rule_stats[rule_id] = {
                    'total': 0,
                    'passed': 0,
                    'positive_tests': 0,
                    'positive_passed': 0,
                    'negative_tests': 0,
                    'negative_passed': 0
                }
            
            rule_stats[rule_id]['total'] += 1
            if result['passed']:
                rule_stats[rule_id]['passed'] += 1
            
            # 分离阳性和阴性测试
            if result['test_type'] == 'positive':
                rule_stats[rule_id]['positive_tests'] += 1
                if result['passed']:
                    rule_stats[rule_id]['positive_passed'] += 1
            elif result['test_type'] == 'negative':
                rule_stats[rule_id]['negative_tests'] += 1
                if result['passed']:
                    rule_stats[rule_id]['negative_passed'] += 1
        
        # 计算每个规则的指标
        for rule_id, stats in rule_stats.items():
            stats['pass_rate'] = stats['passed'] / stats['total'] if stats['total'] > 0 else 0
            stats['positive_rate'] = stats['positive_passed'] / stats['positive_tests'] if stats['positive_tests'] > 0 else 0
            stats['negative_rate'] = stats['negative_passed'] / stats['negative_tests'] if stats['negative_tests'] > 0 else 0
            
            # 计算 TP, FP, FN, TN
            tp = stats['positive_passed']  # 真阳性
            fp = stats['negative_tests'] - stats['negative_passed']  # 假阳性（误报）
            fn = stats['positive_tests'] - stats['positive_passed']  # 假阴性（漏报）
            tn = stats['negative_passed']  # 真阴性
            
            # 计算高级指标
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            fnr = fn / (tp + fn) if (tp + fn) > 0 else 0
            
            stats['metrics'] = {
                'recall': recall,
                'precision': precision,
                'f1_score': f1_score,
                'false_positive_rate': fpr,
                'false_negative_rate': fnr,
                'confusion_matrix': {
                    'tp': tp,
                    'fp': fp,
                    'fn': fn,
                    'tn': tn
                }
            }
        
        # 计算整体指标
        overall_metrics = {
            'total_tests': total,
            'passed_tests': passed,
            'pass_rate': passed / total if total > 0 else 0,
            'rule_count': len(rule_stats),
            'rules_passed_all': sum(1 for s in rule_stats.values() if s['pass_rate'] == 1.0),
            'rules_failed_any': sum(1 for s in rule_stats.values() if s['pass_rate'] < 1.0)
        }
        
        # 计算平均指标
        avg_recall = sum(s['metrics']['recall'] for s in rule_stats.values()) / len(rule_stats) if rule_stats else 0
        avg_precision = sum(s['metrics']['precision'] for s in rule_stats.values()) / len(rule_stats) if rule_stats else 0
        avg_f1 = sum(s['metrics']['f1_score'] for s in rule_stats.values()) / len(rule_stats) if rule_stats else 0
        avg_fpr = sum(s['metrics']['false_positive_rate'] for s in rule_stats.values()) / len(rule_stats) if rule_stats else 0
        
        overall_metrics['average_metrics'] = {
            'recall': avg_recall,
            'precision': avg_precision,
            'f1_score': avg_f1,
            'false_positive_rate': avg_fpr
        }
        
        return {
            'overall': overall_metrics,
            'by_rule': rule_stats
        }
    
    def generate_report(self, output_format='json'):
        """生成验证报告"""
        metrics = self.calculate_metrics()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'rules_file': str(self.rules_file),
            'test_cases_dir': str(self.test_cases_dir),
            'metrics': metrics,
            'details': self.results
        }
        
        if output_format == 'json':
            return json.dumps(report, indent=2, ensure_ascii=False)
        elif output_format == 'html':
            return self._generate_html_report(report)
        
        return report
    
    def _generate_html_report(self, report):
        """生成 HTML 格式报告"""
        metrics = report['metrics']
        overall = metrics.get('overall', {})
        avg_metrics = overall.get('average_metrics', {})
        
        html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HOS-LS 规则验证报告</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #2196F3; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-card.success {{ background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }}
        .metric-card.warning {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .metric-value {{ font-size: 2.5em; font-weight: bold; }}
        .metric-label {{ font-size: 0.9em; margin-top: 5px; opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #2196F3; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .pass {{ color: #4CAF50; font-weight: bold; }}
        .fail {{ color: #F44336; font-weight: bold; }}
        .rule-section {{ margin: 30px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #2196F3; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 10px 0; }}
        .metric-box {{ background: white; padding: 10px; border-radius: 4px; text-align: center; border: 1px solid #ddd; }}
        .metric-box .value {{ font-size: 1.5em; font-weight: bold; color: #2196F3; }}
        .metric-box .label {{ font-size: 0.8em; color: #666; }}
        .timestamp {{ color: #999; font-size: 0.9em; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 HOS-LS 规则验证报告</h1>
        <p class="timestamp">生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>总体概览</h2>
        <div class="summary">
            <div class="metric-card">
                <div class="metric-value">{overall.get('total_tests', 0)}</div>
                <div class="metric-label">总测试数</div>
            </div>
            <div class="metric-card success">
                <div class="metric-value">{overall.get('passed_tests', 0)}</div>
                <div class="metric-label">通过测试</div>
            </div>
            <div class="metric-card warning">
                <div class="metric-value">{overall.get('total_tests', 0) - overall.get('passed_tests', 0)}</div>
                <div class="metric-label">失败测试</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{overall.get('pass_rate', 0)*100:.1f}%</div>
                <div class="metric-label">通过率</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{overall.get('rule_count', 0)}</div>
                <div class="metric-label">规则数量</div>
            </div>
        </div>
        
        <h2>平均质量指标</h2>
        <div class="metrics-grid">
            <div class="metric-box">
                <div class="value">{avg_metrics.get('recall', 0)*100:.1f}%</div>
                <div class="label">检测率 (Recall)</div>
            </div>
            <div class="metric-box">
                <div class="value">{avg_metrics.get('precision', 0)*100:.1f}%</div>
                <div class="label">准确率 (Precision)</div>
            </div>
            <div class="metric-box">
                <div class="value">{avg_metrics.get('f1_score', 0)*100:.1f}%</div>
                <div class="label">F1 分数</div>
            </div>
            <div class="metric-box">
                <div class="value">{avg_metrics.get('false_positive_rate', 0)*100:.1f}%</div>
                <div class="label">误报率</div>
            </div>
        </div>
        
        <h2>按规则统计</h2>
        <table>
            <thead>
                <tr>
                    <th>规则 ID</th>
                    <th>总测试</th>
                    <th>通过</th>
                    <th>通过率</th>
                    <th>检测率</th>
                    <th>准确率</th>
                    <th>F1 分数</th>
                    <th>状态</th>
                </tr>
            </thead>
            <tbody>
"""
        
        # 添加规则统计
        for rule_id, stats in sorted(metrics.get('by_rule', {}).items(), 
                                    key=lambda x: x[1].get('pass_rate', 0), reverse=True):
            m = stats.get('metrics', {})
            status_class = "pass" if stats['pass_rate'] == 1.0 else "fail"
            status_text = "✓ 通过" if stats['pass_rate'] == 1.0 else "✗ 失败"
            
            html += f"""
                <tr>
                    <td>{rule_id}</td>
                    <td>{stats['total']}</td>
                    <td>{stats['passed']}</td>
                    <td>{stats['pass_rate']*100:.1f}%</td>
                    <td>{m.get('recall', 0)*100:.1f}%</td>
                    <td>{m.get('precision', 0)*100:.1f}%</td>
                    <td>{m.get('f1_score', 0)*100:.1f}%</td>
                    <td class="{status_class}">{status_text}</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        return html
    
    def save_report(self, output_path, output_format='json'):
        """保存报告到文件"""
        report_content = self.generate_report(output_format=output_format)
        
        # 确保输出目录存在
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"报告已保存到：{output_path}")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='HOS-LS 规则验证工具')
    parser.add_argument('--rules', '-r', 
                       default='src/rules/security_rules.json',
                       help='规则文件路径 (默认：src/rules/security_rules.json)')
    parser.add_argument('--test-cases', '-t',
                       default='rule_validation/test_cases',
                       help='测试用例目录 (默认：rule_validation/test_cases)')
    parser.add_argument('--output', '-o',
                       default=None,
                       help='输出文件路径 (默认：自动生成)')
    parser.add_argument('--format', '-f',
                       choices=['json', 'html'],
                       default='json',
                       help='输出格式 (默认：json)')
    
    args = parser.parse_args()
    
    # 配置路径
    project_root = Path(__file__).parent.parent
    rules_file = project_root / args.rules
    test_cases_dir = Path(__file__).parent / 'test_cases'
    
    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(__file__).parent / 'test_results' / f'validation_report_{timestamp}.{args.format}'
    
    # 检查规则文件是否存在
    if not rules_file.exists():
        print(f"规则文件不存在：{rules_file}")
        sys.exit(1)
    
    # 创建验证器并运行
    validator = RuleValidator(str(rules_file), str(test_cases_dir))
    validator.run_all_tests()
    validator.save_report(str(output_path), output_format=args.format)
    
    # 检查质量门禁
    metrics = validator.calculate_metrics()
    overall = metrics.get('overall', {})
    
    if overall.get('pass_rate', 0) < 0.95:
        print("警告：整体通过率低于 95%")
        sys.exit(1)
    else:
        print("质量门禁检查通过")
        sys.exit(0)


if __name__ == '__main__':
    main()
