#!/usr/bin/env python3
"""
规则验证 Harness v2.0

功能:
1. 验证 AI 生成规则的质量
2. 执行自动化测试
3. 计算质量指标 (Recall, Precision, F1, FPR, FNR)
4. 质量门禁检查
5. 生成验证报告

版本：2.0
创建日期：2026-03-31
优化依据：基于用户 develop.json 习惯
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import re


class RuleValidationHarness:
    """规则验证 Harness"""
    
    def __init__(self, rules_file: str, test_cases_dir: str):
        """
        初始化验证器
        
        Args:
            rules_file: 规则文件路径
            test_cases_dir: 测试用例目录
        """
        self.rules_file = rules_file
        self.test_cases_dir = test_cases_dir
        self.rules = self._load_rules(rules_file)
        self.results = []
    
    def _load_rules(self, rules_file: str) -> Dict[str, Any]:
        """加载规则文件"""
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"加载规则文件失败：{e}")
            return {'rules': {}}
    
    def load_test_cases(self) -> List[Dict[str, Any]]:
        """
        加载所有测试用例
        
        Returns:
            测试用例列表
        """
        test_cases = []
        test_cases_path = Path(self.test_cases_dir)
        
        if not test_cases_path.exists():
            print(f"测试用例目录不存在：{self.test_cases_dir}")
            return test_cases
        
        # 遍历所有测试文件
        for root, dirs, files in os.walk(test_cases_path):
            for file in files:
                if file.endswith(('.py', '.json', '.txt')) and not file.startswith('__'):
                    file_path = Path(root) / file
                    test_case = self._parse_test_case(file_path)
                    if test_case:
                        test_cases.append(test_case)
        
        return test_cases
    
    def _parse_test_case(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        解析测试用例文件
        
        Args:
            file_path: 测试文件路径
            
        Returns:
            测试用例字典
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 从文件头注释中提取测试用例信息
            test_case = {
                'file_path': str(file_path),
                'test_id': self._extract_metadata(content, 'Test Case ID'),
                'rule_id': self._extract_metadata(content, 'Rule'),
                'test_type': self._extract_metadata(content, 'Test Type'),
                'description': self._extract_metadata(content, 'Description'),
                'code': content,
                'expected_detection': self._extract_expected_detection(content),
                'expected_severity': self._extract_metadata(content, 'Expected Severity'),
                'file_type': file_path.suffix,
            }
            
            return test_case
        except Exception as e:
            print(f"解析测试用例失败 {file_path}: {e}")
            return None
    
    def _extract_metadata(self, content: str, field: str) -> str:
        """从注释中提取元数据"""
        patterns = {
            'Test Case ID': r'#\s*Test Case ID:\s*(.+)',
            'Rule': r'#\s*Rule:\s*(.+)',
            'Test Type': r'#\s*Test Type:\s*(.+)',
            'Description': r'#\s*Description:\s*(.+)',
            'Expected Severity': r'#\s*Expected Severity:\s*(.+)',
        }
        
        pattern = patterns.get(field, rf'#\s*{field}:\s*(.+)')
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1).strip() if match else ''
    
    def _extract_expected_detection(self, content: str) -> bool:
        """提取预期检测结果"""
        patterns = [
            r'Expected Detection:\s*(true|false)',
            r'Expected:\s*(true|false)',
            r'#\s*应该被检测',
            r'#\s*不应该被检测',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                text = match.group(0).lower()
                if 'false' in text or '不应该' in text:
                    return False
                elif 'true' in text or '应该' in text:
                    return True
        
        # 默认根据文件名判断
        file_name = Path(content).name.lower()
        if 'positive' in file_name:
            return True
        elif 'negative' in file_name:
            return False
        
        return True  # 默认阳性
    
    def run_single_test(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """
        运行单个测试用例
        
        Args:
            test_case: 测试用例字典
            
        Returns:
            测试结果字典
        """
        result = {
            'test_id': test_case.get('test_id', 'UNKNOWN'),
            'rule_id': test_case.get('rule_id', 'UNKNOWN'),
            'description': test_case.get('description', ''),
            'expected': test_case.get('expected_detection', True),
            'actual': False,
            'passed': False,
            'issues_found': 0,
            'details': []
        }
        
        try:
            # 执行规则匹配（简化版本，实际应调用扫描器）
            code = test_case.get('code', '')
            rule_id = test_case.get('rule_id', '')
            
            # 查找对应规则
            rule = self._find_rule(rule_id)
            
            if rule:
                # 执行模式匹配
                issues = self._match_patterns(code, rule)
                result['actual'] = len(issues) > 0
                result['issues_found'] = len(issues)
                result['details'] = issues
            else:
                # 规则未找到，视为失败
                result['actual'] = False
                result['details'] = ['规则未找到']
            
            # 判断是否通过
            result['passed'] = (result['actual'] == result['expected'])
            
        except Exception as e:
            result['details'].append(f'执行错误：{str(e)}')
            result['passed'] = False
        
        return result
    
    def _find_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """查找规则"""
        rules_data = self.rules.get('rules', {})
        
        for category, rules in rules_data.items():
            if rule_id.startswith(category):
                rule_name = rule_id.replace(f'{category}.', '')
                if rule_name in rules:
                    return rules[rule_name]
        
        return None
    
    def _match_patterns(self, code: str, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        匹配规则模式
        
        Args:
            code: 代码
            rule: 规则定义
            
        Returns:
            检测到的问题列表
        """
        issues = []
        
        # 获取检测模式
        patterns = rule.get('patterns', [])
        exclude_patterns = rule.get('exclude_patterns', [])
        
        # 检查排除模式
        for exclude_pattern in exclude_patterns:
            try:
                if re.search(exclude_pattern, code, re.IGNORECASE):
                    return []  # 匹配排除模式，不检测
            except re.error:
                continue
        
        # 检查检测模式
        for pattern in patterns:
            try:
                if re.search(pattern, code, re.IGNORECASE):
                    issues.append({
                        'pattern': pattern,
                        'match': True,
                        'severity': rule.get('severity', 'MEDIUM')
                    })
            except re.error:
                continue
        
        return issues
    
    def run_all_tests(self) -> List[Dict[str, Any]]:
        """
        运行所有测试用例
        
        Returns:
            所有测试结果
        """
        test_cases = self.load_test_cases()
        
        if not test_cases:
            print("未找到测试用例")
            return []
        
        print(f"共加载 {len(test_cases)} 个测试用例")
        
        self.results = []
        for test_case in test_cases:
            result = self.run_single_test(test_case)
            self.results.append(result)
            
            status = "✓ PASS" if result['passed'] else "✗ FAIL"
            print(f"{status}: {result['test_id']} - {result['description']}")
        
        return self.results
    
    def calculate_metrics(self) -> Dict[str, Any]:
        """
        计算质量指标
        
        Returns:
            指标字典
        """
        if not self.results:
            return {
                'total_tests': 0,
                'passed_tests': 0,
                'pass_rate': 0,
                'recall': 0,
                'precision': 0,
                'f1_score': 0,
                'false_positive_rate': 0,
                'false_negative_rate': 0
            }
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r['passed'])
        
        # 分离阳性和阴性测试
        positive_tests = [r for r in self.results if r['expected']]
        negative_tests = [r for r in self.results if not r['expected']]
        
        # 计算 TP, FP, FN, TN
        tp = sum(1 for r in positive_tests if r['actual'])  # 真阳性
        fp = sum(1 for r in negative_tests if r['actual'])  # 假阳性
        fn = sum(1 for r in positive_tests if not r['actual'])  # 假阴性
        tn = sum(1 for r in negative_tests if not r['actual'])  # 真阴性
        
        # 计算指标
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0  # 召回率
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0  # 准确率
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # 误报率
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0  # 漏报率
        
        # 按规则分组统计
        rule_stats = {}
        for result in self.results:
            rule_id = result['rule_id']
            if rule_id not in rule_stats:
                rule_stats[rule_id] = {'total': 0, 'passed': 0}
            rule_stats[rule_id]['total'] += 1
            if result['passed']:
                rule_stats[rule_id]['passed'] += 1
        
        metrics = {
            'total_tests': total,
            'passed_tests': passed,
            'pass_rate': passed / total if total > 0 else 0,
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
            },
            'rule_stats': rule_stats
        }
        
        return metrics
    
    def check_quality_gate(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        质量门禁检查
        
        Args:
            metrics: 质量指标
            
        Returns:
            门禁检查结果
        """
        gates = {
            'recall': {'threshold': 0.95, 'passed': metrics.get('recall', 0) >= 0.95},
            'precision': {'threshold': 0.90, 'passed': metrics.get('precision', 0) >= 0.90},
            'f1_score': {'threshold': 0.92, 'passed': metrics.get('f1_score', 0) >= 0.92},
            'fpr': {'threshold': 0.05, 'passed': metrics.get('false_positive_rate', 1) <= 0.05},
            'fnr': {'threshold': 0.05, 'passed': metrics.get('false_negative_rate', 1) <= 0.05}
        }
        
        all_passed = all(gate['passed'] for gate in gates.values())
        
        return {
            'all_passed': all_passed,
            'gates': gates,
            'failed_gates': [k for k, v in gates.items() if not v['passed']]
        }
    
    def generate_report(self, output_format: str = 'json') -> str:
        """
        生成验证报告
        
        Args:
            output_format: 输出格式 (json/html)
            
        Returns:
            报告内容
        """
        metrics = self.calculate_metrics()
        quality_gate = self.check_quality_gate(metrics)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'rules_file': self.rules_file,
            'test_cases_dir': self.test_cases_dir,
            'metrics': metrics,
            'quality_gate': quality_gate,
            'details': self.results
        }
        
        if output_format == 'json':
            return json.dumps(report, indent=2, ensure_ascii=False)
        elif output_format == 'html':
            return self._generate_html_report(report)
        
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """生成 HTML 格式报告"""
        metrics = report['metrics']
        quality_gate = report['quality_gate']
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>规则验证报告</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .metric-card {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #2196F3; }}
        .metric-label {{ color: #666; margin-top: 5px; }}
        .quality-pass {{ color: #4CAF50; }}
        .quality-fail {{ color: #F44336; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #2196F3; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .pass {{ color: #4CAF50; }}
        .fail {{ color: #F44336; }}
    </style>
</head>
<body>
    <h1>📊 规则验证报告</h1>
    <p>生成时间：{report['timestamp']}</p>
    
    <div class="summary">
        <div class="metric-card">
            <div class="metric-value">{metrics['total_tests']}</div>
            <div class="metric-label">总测试数</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{metrics['passed_tests']}</div>
            <div class="metric-label">通过测试</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{metrics['pass_rate']:.2%}</div>
            <div class="metric-label">通过率</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{metrics['recall']:.2%}</div>
            <div class="metric-label">检测率 (Recall)</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{metrics['precision']:.2%}</div>
            <div class="metric-label">准确率 (Precision)</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{metrics['f1_score']:.2%}</div>
            <div class="metric-label">F1 分数</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{metrics['false_positive_rate']:.2%}</div>
            <div class="metric-label">误报率</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{metrics['false_negative_rate']:.2%}</div>
            <div class="metric-label">漏报率</div>
        </div>
    </div>
    
    <h2>质量门禁检查</h2>
    <p>整体结果：
        <span class="{'quality-pass' if quality_gate['all_passed'] else 'quality-fail'}">
            {'✓ 通过' if quality_gate['all_passed'] else '✗ 未通过'}
        </span>
    </p>
    
    <table>
        <thead>
            <tr>
                <th>指标</th>
                <th>阈值</th>
                <th>实际值</th>
                <th>结果</th>
            </tr>
        </thead>
        <tbody>
"""
        
        # 添加门禁检查结果
        for gate_name, gate_data in quality_gate['gates'].items():
            metric_value = metrics.get(gate_name, 0)
            if gate_name in ['fpr', 'fnr']:
                status = "✓" if gate_data['passed'] else "✗"
                html += f"""
            <tr>
                <td>{gate_name.upper()}</td>
                <td>≤{gate_data['threshold']:.2%}</td>
                <td>{metric_value:.2%}</td>
                <td class="{'pass' if gate_data['passed'] else 'fail'}">{status}</td>
            </tr>
"""
            else:
                status = "✓" if gate_data['passed'] else "✗"
                html += f"""
            <tr>
                <td>{gate_name.upper()}</td>
                <td>≥{gate_data['threshold']:.2%}</td>
                <td>{metric_value:.2%}</td>
                <td class="{'pass' if gate_data['passed'] else 'fail'}">{status}</td>
            </tr>
"""
        
        html += """
        </tbody>
    </table>
    
    <h2>测试详情</h2>
    <table>
        <thead>
            <tr>
                <th>测试 ID</th>
                <th>规则 ID</th>
                <th>描述</th>
                <th>预期</th>
                <th>实际</th>
                <th>结果</th>
            </tr>
        </thead>
        <tbody>
"""
        
        # 添加测试结果详情
        for result in report['details'][:50]:  # 限制显示 50 条
            status_class = 'pass' if result['passed'] else 'fail'
            status_icon = '✓' if result['passed'] else '✗'
            html += f"""
            <tr>
                <td>{result['test_id']}</td>
                <td>{result['rule_id']}</td>
                <td>{result['description']}</td>
                <td>{'检测' if result['expected'] else '不检测'}</td>
                <td>{'检测' if result['actual'] else '不检测'}</td>
                <td class="{status_class}">{status_icon}</td>
            </tr>
"""
        
        html += """
        </tbody>
    </table>
</body>
</html>
"""
        return html
    
    def save_report(self, output_path: str, output_format: str = 'json'):
        """
        保存报告到文件
        
        Args:
            output_path: 输出文件路径
            output_format: 输出格式
        """
        report_content = self.generate_report(output_format)
        
        # 确保目录存在
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"报告已保存到：{output_path}")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='规则验证 Harness')
    parser.add_argument('--rules', '-r', required=True, help='规则文件路径')
    parser.add_argument('--test-cases', '-t', required=True, help='测试用例目录')
    parser.add_argument('--output', '-o', default='validation_report.json', help='输出文件路径')
    parser.add_argument('--format', '-f', choices=['json', 'html'], default='json', help='输出格式')
    
    args = parser.parse_args()
    
    # 创建验证器
    harness = RuleValidationHarness(args.rules, args.test_cases)
    
    # 运行所有测试
    harness.run_all_tests()
    
    # 计算指标
    metrics = harness.calculate_metrics()
    print(f"\n质量指标:")
    print(f"  总测试数：{metrics['total_tests']}")
    print(f"  通过测试：{metrics['passed_tests']}")
    print(f"  通过率：{metrics['pass_rate']:.2%}")
    print(f"  检测率 (Recall): {metrics['recall']:.2%}")
    print(f"  准确率 (Precision): {metrics['precision']:.2%}")
    print(f"  F1 分数：{metrics['f1_score']:.2%}")
    print(f"  误报率：{metrics['false_positive_rate']:.2%}")
    print(f"  漏报率：{metrics['false_negative_rate']:.2%}")
    
    # 质量门禁检查
    quality_gate = harness.check_quality_gate(metrics)
    print(f"\n质量门禁：{'✓ 通过' if quality_gate['all_passed'] else '✗ 未通过'}")
    if not quality_gate['all_passed']:
        print(f"未通过的指标：{', '.join(quality_gate['failed_gates'])}")
    
    # 保存报告
    harness.save_report(args.output, args.format)


if __name__ == '__main__':
    main()
