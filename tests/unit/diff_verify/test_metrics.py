"""评测指标单元测试"""

import pytest
from eval.metrics import (
    calculate_pair_correct,
    calculate_metrics,
    format_metrics_report,
    create_evaluation_result
)
from data.schema import (
    EvaluationResult, PairResult, EvaluationMetrics,
    SampleData, SampleMetadata, DatasetType, VulnerabilityType
)


class TestPairCorrect:
    """Pair-Correct指标测试"""
    
    def test_pair_correct_all_correct(self):
        """测试全部正确的情况"""
        # 漏洞样本都预测为True
        vuln_results = [
            EvaluationResult(sample_id="v1", prediction=True, ground_truth=True),
            EvaluationResult(sample_id="v2", prediction=True, ground_truth=True),
        ]
        
        # 修复样本都预测为False
        patched_results = [
            EvaluationResult(sample_id="p1", prediction=False, ground_truth=False),
            EvaluationResult(sample_id="p2", prediction=False, ground_truth=False),
        ]
        
        pairs, rate = calculate_pair_correct(vuln_results, patched_results)
        
        assert len(pairs) == 2
        assert rate == 1.0  # 100%正确
    
    def test_pair_correct_all_wrong(self):
        """测试全部错误的情况"""
        vuln_results = [
            EvaluationResult(sample_id="v1", prediction=False, ground_truth=True),  # 漏报
            EvaluationResult(sample_id="v2", prediction=False, ground_truth=True),  # 漏报
        ]
        
        patched_results = [
            EvaluationResult(sample_id="p1", prediction=True, ground_truth=False),  # 误报
            EvaluationResult(sample_id="p2", prediction=True, ground_truth=False),  # 误报
        ]
        
        pairs, rate = calculate_pair_correct(vuln_results, patched_results)
        
        assert len(pairs) == 2
        assert rate == 0.0  # 0%正确
    
    def test_pair_correct_partial(self):
        """测试部分正确的情况"""
        vuln_results = [
            EvaluationResult(sample_id="v1", prediction=True, ground_truth=True),   # 正确
            EvaluationResult(sample_id="v2", prediction=False, ground_truth=True),  # 漏报
        ]
        
        patched_results = [
            EvaluationResult(sample_id="p1", prediction=False, ground_truth=False),  # 正确
            EvaluationResult(sample_id="p2", prediction=True, ground_truth=False),   # 误报
        ]
        
        pairs, rate = calculate_pair_correct(vuln_results, patched_results)
        
        assert len(pairs) == 2
        assert rate == 0.5  # 50%正确（只有第一对正确）


class TestMetrics:
    """评测指标测试"""
    
    def test_calculate_metrics(self):
        """测试指标计算"""
        results = [
            EvaluationResult(sample_id="v1", prediction=True, ground_truth=True),
            EvaluationResult(sample_id="v2", prediction=True, ground_truth=True),
            EvaluationResult(sample_id="p1", prediction=False, ground_truth=False),
            EvaluationResult(sample_id="p2", prediction=False, ground_truth=False),
        ]
        
        metrics = calculate_metrics(results)
        
        assert metrics.total_samples == 4
        assert metrics.accuracy == 1.0
        assert metrics.vuln_recall == 1.0
        assert metrics.patched_specificity == 1.0
    
    def test_calculate_metrics_with_errors(self):
        """测试有错误的指标计算"""
        results = [
            EvaluationResult(sample_id="v1", prediction=True, ground_truth=True),
            EvaluationResult(sample_id="v2", prediction=False, ground_truth=True),   # 漏报
            EvaluationResult(sample_id="p1", prediction=False, ground_truth=False),
            EvaluationResult(sample_id="p2", prediction=True, ground_truth=False),   # 误报
        ]
        
        metrics = calculate_metrics(results)
        
        assert metrics.total_samples == 4
        assert metrics.accuracy == 0.5
        assert metrics.vuln_recall == 0.5
        assert metrics.false_positives == 1
        assert metrics.false_negatives == 1


class TestCreateEvaluationResult:
    """创建评测结果测试"""
    
    def test_create_result_with_enum(self):
        """测试使用枚举创建结果"""
        sample = SampleData(
            metadata=SampleMetadata(
                sample_id="test_001",
                dataset=DatasetType.CUSTOM,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                is_vulnerable=True
            ),
            r_before="/tmp/test",
            task_desc="Test task",
            delta_ai="test diff"
        )
        
        result = create_evaluation_result(sample, prediction=True, confidence=0.9)
        
        assert result.sample_id == "test_001"
        assert result.prediction == True
        assert result.ground_truth == True
        assert result.is_correct == True
        assert result.confidence == 0.9
    
    def test_create_result_with_string_type(self):
        """测试使用字符串类型创建结果"""
        sample = SampleData(
            metadata=SampleMetadata(
                sample_id="test_002",
                dataset=DatasetType.CUSTOM,
                vulnerability_type="sql_injection",  # 字符串而非枚举
                is_vulnerable=False
            ),
            r_before="/tmp/test",
            task_desc="Test task",
            delta_ai="test diff"
        )
        
        result = create_evaluation_result(sample, prediction=False)
        
        assert result.sample_id == "test_002"
        assert result.prediction == False
        assert result.ground_truth == False
        assert result.is_correct == True


class TestFormatReport:
    """报告格式化测试"""
    
    def test_format_metrics_report(self):
        """测试格式化指标报告"""
        metrics = EvaluationMetrics()
        metrics.total_samples = 100
        metrics.accuracy = 0.85
        metrics.vuln_recall = 0.90
        metrics.pair_correct_rate = 0.75
        
        report = format_metrics_report(metrics, "Test Report")
        
        assert "Test Report" in report
        assert "100" in report
        assert "85.00%" in report
        assert "90.00%" in report
        assert "75.00%" in report
