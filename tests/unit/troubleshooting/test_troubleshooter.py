"""排查模块单元测试

测试排查模块的核心功能。
"""

import asyncio
from pathlib import Path
import pytest

from src.troubleshooting.troubleshooter import Troubleshooter
from src.troubleshooting.report_generator import ReportGenerator


class TestTroubleshooter:
    """测试排查器"""
    
    @pytest.fixture
    def troubleshooter(self):
        """创建排查器实例"""
        return Troubleshooter()
    
    @pytest.fixture
    def report_generator(self):
        """创建报告生成器实例"""
        return ReportGenerator()
    
    def test_collect_files(self, troubleshooter):
        """测试文件收集功能"""
        # 测试收集Python文件
        files = troubleshooter._collect_files(["*.py"])
        assert len(files) > 0
        for file in files:
            assert file.suffix == ".py"
            assert file.is_file()
    
    def test_detect_language(self, troubleshooter):
        """测试语言检测功能"""
        # 测试Python文件
        python_file = Path("test.py")
        assert troubleshooter._detect_language(python_file) == "python"
        
        # 测试JavaScript文件
        js_file = Path("test.js")
        assert troubleshooter._detect_language(js_file) == "javascript"
        
        # 测试TypeScript文件
        ts_file = Path("test.ts")
        assert troubleshooter._detect_language(ts_file) == "typescript"
        
        # 测试未知文件类型
        unknown_file = Path("test.txt")
        assert troubleshooter._detect_language(unknown_file) == "python"
    
    def test_evaluate_risk_level(self, troubleshooter):
        """测试风险级别评估功能"""
        # 测试高优先级+多个漏洞
        assert troubleshooter._evaluate_risk_level("high", 5) == "critical"
        
        # 测试高优先级+少量漏洞
        assert troubleshooter._evaluate_risk_level("high", 2) == "high"
        
        # 测试中优先级+漏洞
        assert troubleshooter._evaluate_risk_level("medium", 1) == "medium"
        
        # 测试低优先级+无漏洞
        assert troubleshooter._evaluate_risk_level("low", 0) == "low"
    
    def test_troubleshoot(self, troubleshooter):
        """测试排查功能"""
        # 测试限制文件数量为2
        import asyncio
        results = asyncio.run(troubleshooter.troubleshoot(["*.py"], max_files=2))
        assert len(results) <= 2
        for result in results:
            assert hasattr(result, 'file_path')
            assert hasattr(result, 'priority_score')
            assert hasattr(result, 'priority_level')
            assert hasattr(result, 'vulnerabilities')
            assert hasattr(result, 'test_cases')
            assert hasattr(result, 'analysis_summary')
            assert hasattr(result, 'risk_level')
    
    def test_generate_report(self, troubleshooter, tmp_path):
        """测试报告生成功能"""
        # 先生成一些排查结果
        import asyncio
        results = asyncio.run(troubleshooter.troubleshoot(["*.py"], max_files=2))
        
        # 测试JSON格式报告
        json_report = tmp_path / "report.json"
        troubleshooter.generate_report(results, str(json_report), format="json")
        assert json_report.exists()
        
        # 测试HTML格式报告
        html_report = tmp_path / "report.html"
        troubleshooter.generate_report(results, str(html_report), format="html")
        assert html_report.exists()
        
        # 测试Markdown格式报告
        md_report = tmp_path / "report.md"
        troubleshooter.generate_report(results, str(md_report), format="markdown")
        assert md_report.exists()


if __name__ == "__main__":
    pytest.main([__file__])