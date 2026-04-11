"""报告生成器单元测试

测试报告生成器的功能。
"""

from pathlib import Path
import json
import pytest

from src.troubleshooting.report_generator import ReportGenerator
from src.troubleshooting.troubleshooter import TroubleshootingResult


class TestReportGenerator:
    """测试报告生成器"""
    
    @pytest.fixture
    def report_generator(self):
        """创建报告生成器实例"""
        return ReportGenerator()
    
    @pytest.fixture
    def sample_results(self):
        """创建示例排查结果"""
        results = [
            TroubleshootingResult(
                file_path=Path("test1.py"),
                priority_score=0.9,
                priority_level="high",
                vulnerabilities=["sql_injection", "xss"],
                test_cases=[],
                analysis_summary="测试文件1分析结果",
                risk_level="high"
            ),
            TroubleshootingResult(
                file_path=Path("test2.py"),
                priority_score=0.6,
                priority_level="medium",
                vulnerabilities=["command_injection"],
                test_cases=[],
                analysis_summary="测试文件2分析结果",
                risk_level="medium"
            ),
            TroubleshootingResult(
                file_path=Path("test3.py"),
                priority_score=0.3,
                priority_level="low",
                vulnerabilities=[],
                test_cases=[],
                analysis_summary="测试文件3分析结果",
                risk_level="low"
            )
        ]
        return results
    
    def test_prepare_report_data(self, report_generator, sample_results):
        """测试报告数据准备功能"""
        report_data = report_generator._prepare_report_data(sample_results)
        
        # 检查报告数据结构
        assert "generated_at" in report_data
        assert "summary" in report_data
        assert "detailed_results" in report_data
        
        # 检查摘要数据
        summary = report_data["summary"]
        assert summary["total_files"] == 3
        assert summary["high_risk_files"] == 1
        assert summary["medium_risk_files"] == 1
        assert summary["low_risk_files"] == 1
        assert "vulnerability_stats" in summary
        assert "priority_stats" in summary
        
        # 检查详细结果
        detailed_results = report_data["detailed_results"]
        assert len(detailed_results) == 3
        assert detailed_results[0]["risk_level"] == "high"  # 应该按风险级别排序
    
    def test_generate_json_report(self, report_generator, sample_results, tmp_path):
        """测试生成JSON格式报告"""
        output_path = tmp_path / "report.json"
        report_generator.generate(sample_results, str(output_path), format="json")
        
        # 检查文件存在
        assert output_path.exists()
        
        # 检查文件内容
        with open(output_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        assert "generated_at" in data
        assert "summary" in data
        assert "detailed_results" in data
    
    def test_generate_html_report(self, report_generator, sample_results, tmp_path):
        """测试生成HTML格式报告"""
        output_path = tmp_path / "report.html"
        report_generator.generate(sample_results, str(output_path), format="html")
        
        # 检查文件存在
        assert output_path.exists()
        
        # 检查文件内容
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "<html" in content
        assert "排查报告" in content
        assert "test1.py" in content
    
    def test_generate_markdown_report(self, report_generator, sample_results, tmp_path):
        """测试生成Markdown格式报告"""
        output_path = tmp_path / "report.md"
        report_generator.generate(sample_results, str(output_path), format="markdown")
        
        # 检查文件存在
        assert output_path.exists()
        
        # 检查文件内容
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "# 排查报告" in content
        assert "test1.py" in content
        assert "高风险" in content
    
    def test_invalid_format(self, report_generator, sample_results, tmp_path):
        """测试无效的报告格式"""
        output_path = tmp_path / "report.txt"
        with pytest.raises(ValueError):
            report_generator.generate(sample_results, str(output_path), format="txt")


if __name__ == "__main__":
    pytest.main([__file__])