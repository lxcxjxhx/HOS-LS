#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
评估引擎
用于评估 HOS-LS 的检测效果
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import time
import json
from pathlib import Path

@dataclass
class EvalCase:
    """评估测试用例"""
    name: str
    code: str
    expected_vulnerabilities: List[str]
    description: str = ""

@dataclass
class EvalResult:
    """评估结果"""
    case: EvalCase
    success: bool
    precision: float
    recall: float
    f1_score: float
    runtime_seconds: float
    findings: List[Dict[str, Any]]

class EvaluationEngine:
    """评估引擎"""
    
    def __init__(self):
        """初始化评估引擎"""
        pass
    
    def run_evaluation(self, test_cases: List[EvalCase]) -> List[EvalResult]:
        """运行评估
        
        Args:
            test_cases: 测试用例列表
            
        Returns:
            评估结果列表
        """
        results = []
        
        for case in test_cases:
            start_time = time.time()
            
            try:
                # 创建临时文件
                temp_file = Path(f"temp_test_{hash(case.name)}.py")
                temp_file.write_text(case.code, encoding='utf-8')
                
                # 执行扫描
                import sys
                sys.path.insert(0, str(Path(__file__).parent.parent))
                
                from src.scanners.enhanced_scanner import EnhancedSecurityScanner
                from src.utils.findings_filter import FindingsFilter
                
                scanner = EnhancedSecurityScanner(str(temp_file), silent=True)
                scan_results = scanner.scan()
                
                # 提取所有发现
                all_findings = []
                for category, findings in scan_results.items():
                    if isinstance(findings, list):
                        all_findings.extend(findings)
                
                # 过滤误报
                filter = FindingsFilter(use_hard_exclusions=True, use_ai_filtering=True)
                success, filtered_results, stats = filter.filter_findings(all_findings)
                
                # 计算指标
                detected = set(f.get('category', f.get('issue', 'unknown')) for f in filtered_results['filtered_findings'])
                expected = set(case.expected_vulnerabilities)
                
                true_positives = len(detected & expected)
                false_positives = len(detected - expected)
                false_negatives = len(expected - detected)
                
                precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
                recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
                f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                
                results.append(EvalResult(
                    case=case,
                    success=len(detected & expected) > 0,
                    precision=precision,
                    recall=recall,
                    f1_score=f1,
                    runtime_seconds=time.time() - start_time,
                    findings=filtered_results['filtered_findings']
                ))
                
                # 清理临时文件
                temp_file.unlink(missing_ok=True)
                
            except Exception as e:
                # 处理错误
                results.append(EvalResult(
                    case=case,
                    success=False,
                    precision=0.0,
                    recall=0.0,
                    f1_score=0.0,
                    runtime_seconds=time.time() - start_time,
                    findings=[{"error": str(e)}]
                ))
        
        return results
    
    def generate_report(self, results: List[EvalResult]) -> Dict[str, Any]:
        """生成评估报告
        
        Args:
            results: 评估结果列表
            
        Returns:
            评估报告
        """
        total_cases = len(results)
        passed_cases = sum(1 for r in results if r.success)
        avg_precision = sum(r.precision for r in results) / total_cases if total_cases > 0 else 0
        avg_recall = sum(r.recall for r in results) / total_cases if total_cases > 0 else 0
        avg_f1 = sum(r.f1_score for r in results) / total_cases if total_cases > 0 else 0
        avg_runtime = sum(r.runtime_seconds for r in results) / total_cases if total_cases > 0 else 0
        
        detailed_results = []
        for r in results:
            detailed_results.append({
                "case_name": r.case.name,
                "description": r.case.description,
                "success": r.success,
                "precision": r.precision,
                "recall": r.recall,
                "f1_score": r.f1_score,
                "runtime_seconds": r.runtime_seconds,
                "expected_vulnerabilities": r.case.expected_vulnerabilities,
                "detected_vulnerabilities": list(set(f.get('category', f.get('issue', 'unknown')) for f in r.findings)),
                "findings_count": len(r.findings)
            })
        
        return {
            "total_cases": total_cases,
            "passed_cases": passed_cases,
            "pass_rate": passed_cases / total_cases if total_cases > 0 else 0,
            "average_precision": avg_precision,
            "average_recall": avg_recall,
            "average_f1_score": avg_f1,
            "average_runtime_seconds": avg_runtime,
            "detailed_results": detailed_results
        }
    
    def load_test_cases(self, directory: str) -> List[EvalCase]:
        """加载测试用例
        
        Args:
            directory: 测试用例目录
            
        Returns:
            测试用例列表
        """
        test_cases = []
        test_dir = Path(directory)
        
        # 遍历目录
        for test_file in test_dir.glob("**/*.py"):
            try:
                code = test_file.read_text(encoding='utf-8')
                
                # 从文件名提取信息
                case_name = test_file.stem
                description = f"测试文件: {test_file.relative_to(test_dir)}"
                
                # 简单的预期漏洞推断
                expected_vulnerabilities = []
                if "sql_injection" in str(test_file):
                    expected_vulnerabilities.append("sql_injection")
                elif "xss" in str(test_file):
                    expected_vulnerabilities.append("xss")
                elif "command_injection" in str(test_file):
                    expected_vulnerabilities.append("command_injection")
                elif "prompt_injection" in str(test_file):
                    expected_vulnerabilities.append("prompt_injection")
                
                test_cases.append(EvalCase(
                    name=case_name,
                    code=code,
                    expected_vulnerabilities=expected_vulnerabilities,
                    description=description
                ))
            except Exception as e:
                print(f"加载测试用例 {test_file} 失败: {e}")
        
        return test_cases
    
    def run_benchmark(self) -> Dict[str, Any]:
        """运行基准测试
        
        Returns:
            基准测试结果
        """
        # 加载测试用例
        test_cases = self.load_test_cases("evals/test_cases")
        
        if not test_cases:
            return {"error": "未找到测试用例"}
        
        # 运行评估
        results = self.run_evaluation(test_cases)
        
        # 生成报告
        report = self.generate_report(results)
        
        # 保存报告
        report_file = Path("evals/reports/benchmark_report.json")
        report_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report

def main():
    """主函数"""
    engine = EvaluationEngine()
    report = engine.run_benchmark()
    
    print("基准测试完成！")
    print(f"总测试用例: {report['total_cases']}")
    print(f"通过测试用例: {report['passed_cases']}")
    print(f"通过率: {report['pass_rate']:.2f}")
    print(f"平均准确率: {report['average_precision']:.2f}")
    print(f"平均召回率: {report['average_recall']:.2f}")
    print(f"平均 F1 分数: {report['average_f1_score']:.2f}")
    print(f"平均运行时间: {report['average_runtime_seconds']:.2f} 秒")
    
    print(f"报告已保存到: evals/reports/benchmark_report.json")

if __name__ == '__main__':
    main()