"""Benchmark体系

用于评估安全分析模型的性能，包括测试用例管理、性能评估、结果分析等功能。
"""

import json
import os
import time
from typing import Dict, List, Optional, Tuple

from src.core.config import Config, get_config


class BenchmarkManager:
    """Benchmark管理器

    管理安全分析模型的基准测试，包括测试用例管理、性能评估、结果分析等功能。
    """
    
    def __init__(self, config: Optional[Config] = None):
        """初始化Benchmark管理器
        
        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self.benchmark_dir = os.path.join(self.config.data.storage_path, "benchmark")
        self.test_cases_file = os.path.join(self.benchmark_dir, "test_cases.json")
        self.results_file = os.path.join(self.benchmark_dir, "results.json")
        
        # 确保Benchmark目录存在
        os.makedirs(self.benchmark_dir, exist_ok=True)
        
        # 初始化测试用例和结果存储
        self._initialize_storage()
    
    def _initialize_storage(self):
        """初始化存储文件"""
        # 初始化测试用例文件
        if not os.path.exists(self.test_cases_file):
            with open(self.test_cases_file, 'w', encoding='utf-8') as f:
                json.dump({"test_cases": [], "last_updated": None}, f, ensure_ascii=False, indent=2)
        
        # 初始化结果文件
        if not os.path.exists(self.results_file):
            with open(self.results_file, 'w', encoding='utf-8') as f:
                json.dump({"results": [], "last_updated": None}, f, ensure_ascii=False, indent=2)
    
    def get_test_cases(self) -> List[Dict]:
        """获取所有测试用例
        
        Returns:
            测试用例列表
        """
        with open(self.test_cases_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data.get("test_cases", [])
    
    def add_test_case(self, test_case: Dict) -> bool:
        """添加测试用例
        
        Args:
            test_case: 测试用例信息
        
        Returns:
            是否添加成功
        """
        try:
            # 读取现有测试用例
            test_cases = self.get_test_cases()
            
            # 生成测试用例ID
            test_case_id = f"test_{int(time.time())}_{len(test_cases)}"
            
            # 添加基础信息
            test_case["id"] = test_case_id
            test_case["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            test_case["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # 添加到列表
            test_cases.append(test_case)
            
            # 更新存储
            self._save_test_cases(test_cases)
            
            return True
        except Exception as e:
            print(f"添加测试用例失败: {str(e)}")
            return False
    
    def update_test_case(self, test_case_id: str, updates: Dict) -> bool:
        """更新测试用例
        
        Args:
            test_case_id: 测试用例ID
            updates: 更新内容
        
        Returns:
            是否更新成功
        """
        try:
            # 读取现有测试用例
            test_cases = self.get_test_cases()
            
            # 找到目标测试用例
            for i, test_case in enumerate(test_cases):
                if test_case.get("id") == test_case_id:
                    # 更新内容
                    test_case.update(updates)
                    test_case["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # 更新存储
                    self._save_test_cases(test_cases)
                    return True
            
            return False
        except Exception as e:
            print(f"更新测试用例失败: {str(e)}")
            return False
    
    def delete_test_case(self, test_case_id: str) -> bool:
        """删除测试用例
        
        Args:
            test_case_id: 测试用例ID
        
        Returns:
            是否删除成功
        """
        try:
            # 读取现有测试用例
            test_cases = self.get_test_cases()
            
            # 过滤掉目标测试用例
            new_test_cases = [test_case for test_case in test_cases if test_case.get("id") != test_case_id]
            
            # 更新存储
            self._save_test_cases(new_test_cases)
            
            return len(new_test_cases) < len(test_cases)
        except Exception as e:
            print(f"删除测试用例失败: {str(e)}")
            return False
    
    def run_benchmark(self, test_case_ids: List[str], model_name: str) -> Dict:
        """运行基准测试
        
        Args:
            test_case_ids: 测试用例ID列表
            model_name: 模型名称
        
        Returns:
            测试结果
        """
        try:
            # 获取测试用例
            test_cases = self.get_test_cases()
            selected_test_cases = [tc for tc in test_cases if tc.get("id") in test_case_ids]
            
            # 运行测试
            results = []
            total_time = 0
            
            for test_case in selected_test_cases:
                start_time = time.time()
                
                # 这里应该调用实际的安全分析模型进行测试
                # 暂时使用模拟结果
                test_result = self._run_test_case(test_case, model_name)
                
                end_time = time.time()
                test_time = end_time - start_time
                total_time += test_time
                
                test_result["test_time"] = round(test_time, 3)
                results.append(test_result)
            
            # 计算统计信息
            stats = self._calculate_stats(results)
            
            # 保存结果
            benchmark_result = {
                "id": f"benchmark_{int(time.time())}",
                "model_name": model_name,
                "test_cases": test_case_ids,
                "results": results,
                "statistics": stats,
                "total_time": round(total_time, 3),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self._save_result(benchmark_result)
            
            return benchmark_result
        except Exception as e:
            print(f"运行基准测试失败: {str(e)}")
            return {"error": str(e)}
    
    def _run_test_case(self, test_case: Dict, model_name: str) -> Dict:
        """运行单个测试用例
        
        Args:
            test_case: 测试用例
            model_name: 模型名称
        
        Returns:
            测试结果
        """
        # 模拟测试结果
        # 实际实现应该调用真实的安全分析模型
        expected_vulnerabilities = test_case.get("expected_vulnerabilities", [])
        actual_vulnerabilities = []
        
        # 模拟检测结果
        for expected_vuln in expected_vulnerabilities:
            # 模拟80%的检测率
            import random
            if random.random() < 0.8:
                actual_vulnerabilities.append(expected_vuln)
        
        # 计算精确度和召回率
        tp = len(actual_vulnerabilities)
        fp = 0  # 模拟没有误报
        fn = len(expected_vulnerabilities) - tp
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            "test_case_id": test_case.get("id"),
            "test_case_name": test_case.get("name"),
            "expected_vulnerabilities": expected_vulnerabilities,
            "actual_vulnerabilities": actual_vulnerabilities,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1_score": round(f1_score, 3),
            "status": "PASS" if f1_score >= 0.7 else "FAIL"
        }
    
    def _calculate_stats(self, results: List[Dict]) -> Dict:
        """计算统计信息
        
        Args:
            results: 测试结果列表
        
        Returns:
            统计信息
        """
        if not results:
            return {
                "total_test_cases": 0,
                "passed_test_cases": 0,
                "failed_test_cases": 0,
                "average_precision": 0,
                "average_recall": 0,
                "average_f1_score": 0,
                "average_test_time": 0
            }
        
        total = len(results)
        passed = sum(1 for r in results if r.get("status") == "PASS")
        failed = total - passed
        
        avg_precision = sum(r.get("precision", 0) for r in results) / total
        avg_recall = sum(r.get("recall", 0) for r in results) / total
        avg_f1 = sum(r.get("f1_score", 0) for r in results) / total
        avg_time = sum(r.get("test_time", 0) for r in results) / total
        
        return {
            "total_test_cases": total,
            "passed_test_cases": passed,
            "failed_test_cases": failed,
            "average_precision": round(avg_precision, 3),
            "average_recall": round(avg_recall, 3),
            "average_f1_score": round(avg_f1, 3),
            "average_test_time": round(avg_time, 3)
        }
    
    def get_results(self) -> List[Dict]:
        """获取所有测试结果
        
        Returns:
            测试结果列表
        """
        with open(self.results_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data.get("results", [])
    
    def get_result_by_id(self, result_id: str) -> Optional[Dict]:
        """根据ID获取测试结果
        
        Args:
            result_id: 结果ID
        
        Returns:
            测试结果或None
        """
        results = self.get_results()
        for result in results:
            if result.get("id") == result_id:
                return result
        return None
    
    def get_results_by_model(self, model_name: str) -> List[Dict]:
        """根据模型名称获取测试结果
        
        Args:
            model_name: 模型名称
        
        Returns:
            测试结果列表
        """
        results = self.get_results()
        return [result for result in results if result.get("model_name") == model_name]
    
    def export_result(self, result_id: str, output_path: str) -> bool:
        """导出测试结果
        
        Args:
            result_id: 结果ID
            output_path: 输出文件路径
        
        Returns:
            是否导出成功
        """
        try:
            # 找到目标结果
            result = self.get_result_by_id(result_id)
            if not result:
                return False
            
            # 导出到文件
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            
            return True
        except Exception as e:
            print(f"导出测试结果失败: {str(e)}")
            return False
    
    def _save_test_cases(self, test_cases: List[Dict]):
        """保存测试用例到存储
        
        Args:
            test_cases: 测试用例列表
        """
        data = {
            "test_cases": test_cases,
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        with open(self.test_cases_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def _save_result(self, result: Dict):
        """保存测试结果到存储
        
        Args:
            result: 测试结果
        """
        results = self.get_results()
        results.append(result)
        
        data = {
            "results": results,
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        with open(self.results_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def get_benchmark_statistics(self) -> Dict:
        """获取Benchmark统计信息
        
        Returns:
            Benchmark统计信息
        """
        test_cases = self.get_test_cases()
        results = self.get_results()
        
        # 计算测试用例统计
        test_case_count = len(test_cases)
        
        # 计算结果统计
        result_count = len(results)
        model_names = set(result.get("model_name") for result in results)
        
        # 计算平均性能
        if results:
            avg_precision = sum(r.get("statistics", {}).get("average_precision", 0) for r in results) / result_count
            avg_recall = sum(r.get("statistics", {}).get("average_recall", 0) for r in results) / result_count
            avg_f1 = sum(r.get("statistics", {}).get("average_f1_score", 0) for r in results) / result_count
        else:
            avg_precision = 0
            avg_recall = 0
            avg_f1 = 0
        
        return {
            "test_case_count": test_case_count,
            "result_count": result_count,
            "model_count": len(model_names),
            "average_precision": round(avg_precision, 3),
            "average_recall": round(avg_recall, 3),
            "average_f1_score": round(avg_f1, 3)
        }
