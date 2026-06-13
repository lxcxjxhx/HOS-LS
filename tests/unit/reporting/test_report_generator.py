"""报告生成器测试"""

import pytest
import tempfile
from pathlib import Path

from src.reporting.generator import (
    BaseReportGenerator,
    JSONReportGenerator,
    HTMLReportGenerator,
    MarkdownReportGenerator,
    SARIFReportGenerator,
    ReportGenerator,
)
from src.core.engine import ScanResult, ScanStatus, Finding, Location, Severity


@pytest.fixture
def sample_findings():
    return [
        Finding(
            rule_id="HOS001",
            rule_name="SQL Injection",
            description="Potential SQL injection vulnerability",
            severity=Severity.HIGH,
            location=Location(file="test.py", line=10, column=5),
            message="Unsanitized input used in SQL query",
            code_snippet="cursor.execute(query + user_input)",
            fix_suggestion="Use parameterized queries",
        ),
        Finding(
            rule_id="HOS002",
            rule_name="Command Injection",
            description="Potential command injection vulnerability",
            severity=Severity.CRITICAL,
            location=Location(file="test.py", line=20, column=1),
            message="User input passed to os.system",
            code_snippet="os.system(cmd + user_input)",
            fix_suggestion="Use subprocess with shell=False",
        ),
    ]


@pytest.fixture
def sample_result(sample_findings):
    result = ScanResult(
        target="test.py",
        status=ScanStatus.COMPLETED,
        findings=sample_findings,
    )
    return result


class TestJSONReportGenerator:
    def test_generate(self, sample_result):
        generator = JSONReportGenerator()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.json"
            result_path = generator.generate([sample_result], str(output_path))
            
            assert Path(result_path).exists()
            
            import json
            with open(result_path) as f:
                data = json.load(f)
            
            assert "results" in data
            assert "summary" in data
            assert data["summary"]["total_findings"] == 2

    def test_format_property(self):
        generator = JSONReportGenerator()
        assert generator.format == "json"


class TestHTMLReportGenerator:
    def test_generate(self, sample_result):
        generator = HTMLReportGenerator()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.html"
            result_path = generator.generate([sample_result], str(output_path))
            
            assert Path(result_path).exists()
            
            content = Path(result_path).read_text(encoding='utf-8')
            assert "HOS-LS" in content
            assert "SQL Injection" in content
            assert "Command Injection" in content

    def test_format_property(self):
        generator = HTMLReportGenerator()
        assert generator.format == "html"


class TestMarkdownReportGenerator:
    def test_generate(self, sample_result):
        generator = MarkdownReportGenerator()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.md"
            result_path = generator.generate([sample_result], str(output_path))
            
            assert Path(result_path).exists()
            
            content = Path(result_path).read_text(encoding='utf-8')
            assert "# HOS-LS" in content
            assert "SQL Injection" in content

    def test_format_property(self):
        generator = MarkdownReportGenerator()
        assert generator.format == "markdown"


class TestSARIFReportGenerator:
    def test_generate(self, sample_result):
        generator = SARIFReportGenerator()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.sarif"
            result_path = generator.generate([sample_result], str(output_path))
            
            assert Path(result_path).exists()
            
            import json
            with open(result_path) as f:
                data = json.load(f)
            
            assert data["version"] == "2.1.0"
            assert "runs" in data

    def test_format_property(self):
        generator = SARIFReportGenerator()
        assert generator.format == "sarif"


class TestReportGenerator:
    def test_generate_json(self, sample_result):
        generator = ReportGenerator()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.json"
            result_path = generator.generate([sample_result], str(output_path), "json")
            
            assert Path(result_path).exists()

    def test_generate_html(self, sample_result):
        generator = ReportGenerator()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.html"
            result_path = generator.generate([sample_result], str(output_path), "html")
            
            assert Path(result_path).exists()

    def test_invalid_format(self, sample_result):
        generator = ReportGenerator()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.xyz"
            
            with pytest.raises(ValueError):
                generator.generate([sample_result], str(output_path), "invalid_format")

    def test_list_formats(self):
        generator = ReportGenerator()
        formats = generator.list_formats()
        
        assert "json" in formats
        assert "html" in formats
        assert "markdown" in formats
        assert "sarif" in formats

    def test_register_generator(self, sample_result):
        generator = ReportGenerator()
        
        class CustomGenerator(BaseReportGenerator):
            @property
            def format(self):
                return "custom"
            
            def generate(self, results, output_path):
                Path(output_path).write_text("custom report")
                return output_path
        
        generator.register_generator("custom", CustomGenerator)
        
        assert "custom" in generator.list_formats()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.custom"
            result_path = generator.generate([sample_result], str(output_path), "custom")
            
            assert Path(result_path).exists()
            assert Path(result_path).read_text() == "custom report"
