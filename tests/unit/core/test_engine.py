"""Engine module tests"""

import asyncio
import tempfile
import pytest
from pathlib import Path
from datetime import datetime

from src.core.engine import (
    Severity, ScanStatus, ScanMode,
    Location, CodeContext, Finding,
    ScanResult, ModeRouter, BaseScanner, ScanEngine,
    extract_code_context,
)
from src.core.config import Config


class TestSeverity:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_str_representation(self):
        assert str(Severity.HIGH) == "high"
        assert str(Severity.CRITICAL) == "critical"

    def test_comparison_less_than(self):
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_comparison_greater_than(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW

    def test_comparison_equal(self):
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.MEDIUM <= Severity.MEDIUM

    def test_comparison_not_less(self):
        assert not (Severity.CRITICAL < Severity.INFO)
        assert not (Severity.LOW < Severity.INFO)


class TestScanStatus:
    def test_status_values(self):
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.CANCELLED.value == "cancelled"


class TestScanMode:
    def test_mode_values(self):
        assert ScanMode.AUTO.value == "auto"
        assert ScanMode.PURE_AI.value == "pure-ai"
        assert ScanMode.FAST.value == "fast"
        assert ScanMode.DEEP.value == "deep"
        assert ScanMode.STEALTH.value == "stealth"
        assert ScanMode.VULN_LAB.value == "vuln-lab"


class TestLocation:
    def test_default_values(self):
        loc = Location(file="test.py")
        assert loc.file == "test.py"
        assert loc.line == 0
        assert loc.column == 0

    def test_with_line(self):
        loc = Location(file="test.py", line=10)
        assert str(loc) == "test.py:10"

    def test_with_line_and_column(self):
        loc = Location(file="test.py", line=10, column=5)
        assert str(loc) == "test.py:10:5"

    def test_without_line(self):
        loc = Location(file="test.py")
        assert str(loc) == "test.py"


class TestCodeContext:
    def test_default_values(self):
        ctx = CodeContext()
        assert ctx.context_before == []
        assert ctx.vulnerable_line == ""
        assert ctx.context_after == []
        assert ctx.line_number == 0

    def test_to_dict(self):
        ctx = CodeContext(
            context_before=["line1", "line2"],
            vulnerable_line="vuln_line",
            context_after=["line3", "line4"],
            line_number=10,
        )
        d = ctx.to_dict()
        assert d["context_before"] == ["line1", "line2"]
        assert d["vulnerable_line"] == "vuln_line"
        assert d["context_after"] == ["line3", "line4"]
        assert d["line_number"] == 10


class TestFinding:
    def test_default_values(self):
        loc = Location(file="test.py", line=10)
        finding = Finding(
            rule_id="TEST001",
            rule_name="Test Rule",
            description="Test description",
            severity=Severity.HIGH,
            location=loc,
        )
        assert finding.confidence == 1.0
        assert finding.message == ""
        assert finding.code_snippet == ""
        assert finding.fix_suggestion == ""
        assert finding.references == []
        assert finding.metadata == {}

    def test_to_dict(self):
        loc = Location(file="test.py", line=10)
        finding = Finding(
            rule_id="TEST001",
            rule_name="Test Rule",
            description="Test description",
            severity=Severity.HIGH,
            location=loc,
            confidence=0.9,
            message="Found issue",
            code_snippet="vuln_code",
            fix_suggestion="fix it",
        )
        d = finding.to_dict()
        assert d["rule_id"] == "TEST001"
        assert d["severity"] == "high"
        assert d["location"]["file"] == "test.py"
        assert d["location"]["line"] == 10
        assert d["confidence"] == 0.9
        assert d["message"] == "Found issue"
        assert d["code_snippet"] == "vuln_code"
        assert d["fix_suggestion"] == "fix it"

    def test_to_dict_with_code_context(self):
        loc = Location(file="test.py", line=10)
        ctx = CodeContext(vulnerable_line="vuln")
        finding = Finding(
            rule_id="TEST001",
            rule_name="Test",
            description="Desc",
            severity=Severity.MEDIUM,
            location=loc,
            code_context=ctx,
        )
        d = finding.to_dict()
        assert "code_context" in d
        assert d["code_context"]["vulnerable_line"] == "vuln"


class TestScanResult:
    def test_default_values(self):
        result = ScanResult(target="test", status=ScanStatus.PENDING)
        assert result.target == "test"
        assert result.status == ScanStatus.PENDING
        assert result.findings == []
        assert result.error_message == ""
        assert result.start_time is not None

    def test_duration(self):
        result = ScanResult(target="test", status=ScanStatus.PENDING)
        duration = result.duration
        assert duration >= 0

    def test_add_finding(self):
        result = ScanResult(target="test", status=ScanStatus.PENDING)
        loc = Location(file="test.py", line=1)
        finding = Finding(
            rule_id="TEST001",
            rule_name="Test",
            description="Desc",
            severity=Severity.HIGH,
            location=loc,
        )
        result.add_finding(finding)
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "TEST001"

    def test_findings_by_severity(self):
        result = ScanResult(target="test", status=ScanStatus.PENDING)
        loc = Location(file="test.py", line=1)
        result.add_finding(Finding(rule_id="1", rule_name="T", description="D", severity=Severity.HIGH, location=loc))
        result.add_finding(Finding(rule_id="2", rule_name="T", description="D", severity=Severity.LOW, location=loc))
        result.add_finding(Finding(rule_id="3", rule_name="T", description="D", severity=Severity.HIGH, location=loc))

        by_sev = result.findings_by_severity
        assert len(by_sev[Severity.HIGH]) == 2
        assert len(by_sev[Severity.LOW]) == 1
        assert len(by_sev[Severity.CRITICAL]) == 0

    def test_deduplicate_findings(self):
        result = ScanResult(target="test", status=ScanStatus.PENDING)
        loc1 = Location(file="test.py", line=1)
        loc2 = Location(file="test.py", line=2)
        result.add_finding(Finding(rule_id="1", rule_name="T", description="D", severity=Severity.HIGH, location=loc1, confidence=0.5))
        result.add_finding(Finding(rule_id="1", rule_name="T", description="D", severity=Severity.HIGH, location=loc1, confidence=0.8))
        result.add_finding(Finding(rule_id="2", rule_name="T", description="D", severity=Severity.LOW, location=loc2))

        removed = result.deduplicate_findings()
        assert removed == 1
        assert len(result.findings) == 2

    def test_complete(self):
        result = ScanResult(target="test", status=ScanStatus.PENDING)
        result.complete()
        assert result.status == ScanStatus.COMPLETED
        assert result.end_time is not None

    def test_fail(self):
        result = ScanResult(target="test", status=ScanStatus.PENDING)
        result.fail("Test error")
        assert result.status == ScanStatus.FAILED
        assert result.error_message == "Test error"
        assert result.end_time is not None

    def test_to_dict(self):
        result = ScanResult(target="test", status=ScanStatus.PENDING)
        loc = Location(file="test.py", line=1)
        result.add_finding(Finding(rule_id="1", rule_name="T", description="D", severity=Severity.HIGH, location=loc))
        result.complete()
        d = result.to_dict()
        assert d["target"] == "test"
        assert d["status"] == "completed"
        assert "findings" in d
        assert "summary" in d
        assert d["summary"]["total"] == 1
        assert d["summary"]["high"] == 1


class TestModeRouter:
    def test_default_mode(self):
        config = Config()
        router = ModeRouter(config)
        assert router.get_mode() == ScanMode.AUTO

    def test_pure_ai_mode(self):
        config = Config()
        config.scan_mode = "pure-ai"
        router = ModeRouter(config)
        assert router.should_use_pure_ai() is True

    def test_deep_mode(self):
        config = Config()
        config.scan_mode = "deep"
        router = ModeRouter(config)
        assert router.should_use_pure_ai() is True

    def test_incremental_scan_default(self):
        config = Config()
        router = ModeRouter(config)
        assert router.should_incremental_scan() is True

    def test_incremental_scan_disabled(self):
        config = Config()
        config.scan.incremental = False
        router = ModeRouter(config)
        assert router.should_incremental_scan() is False

    def test_invalid_mode(self):
        config = Config()
        config.scan_mode = "invalid-mode"
        router = ModeRouter(config)
        assert router.get_mode() == ScanMode.AUTO

    def test_set_checkpoint_manager(self):
        config = Config()
        router = ModeRouter(config)
        router.set_checkpoint_manager("mock_manager")
        assert router.checkpoint_manager == "mock_manager"

    def test_set_incremental_index(self):
        config = Config()
        router = ModeRouter(config)
        router.set_incremental_index("mock_index")
        assert router.incremental_index == "mock_index"

    def test_set_context_memory(self):
        config = Config()
        router = ModeRouter(config)
        router.set_context_memory("mock_memory")
        assert router.context_memory == "mock_memory"


class TestExtractCodeContext:
    def test_extract_context_from_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            for i in range(1, 21):
                f.write(f"line {i}\n")
            f.flush()
            ctx = extract_code_context(f.name, 10, context_size=2)
            assert ctx.line_number == 10
            assert "line 10" in ctx.vulnerable_line
            assert len(ctx.context_before) == 2
            assert len(ctx.context_after) == 2

    def test_extract_context_nonexistent_file(self):
        ctx = extract_code_context("/nonexistent/file.py", 10)
        assert ctx.line_number == 0
        assert ctx.vulnerable_line == ""

    def test_extract_context_invalid_line(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("line 1\n")
            f.flush()
            ctx = extract_code_context(f.name, 0)
            assert ctx.line_number == 0

    def test_extract_context_with_end_line(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            for i in range(1, 21):
                f.write(f"line {i}\n")
            f.flush()
            ctx = extract_code_context(f.name, 5, context_size=2, end_line=7)
            assert ctx.line_number == 5


class TestScanEngine:
    def test_init(self):
        config = Config()
        engine = ScanEngine(config)
        assert engine.config == config
        assert engine.scanners == []

    def test_register_scanner(self):
        config = Config()
        engine = ScanEngine(config)
        class MockScanner(BaseScanner):
            name = "mock"
            version = "1.0.0"
            async def scan(self, target):
                return ScanResult(target=str(target), status=ScanStatus.COMPLETED)
            def supports(self, target):
                return True
        scanner = MockScanner(config)
        engine.register_scanner(scanner)
        assert len(engine.scanners) == 1
        assert engine.scanners[0] == scanner

    def test_unregister_scanner(self):
        config = Config()
        engine = ScanEngine(config)
        class MockScanner(BaseScanner):
            name = "mock"
            version = "1.0.0"
            async def scan(self, target):
                return ScanResult(target=str(target), status=ScanStatus.COMPLETED)
            def supports(self, target):
                return True
        scanner = MockScanner(config)
        engine.register_scanner(scanner)
        engine.unregister_scanner(scanner)
        assert len(engine.scanners) == 0

    def test_register_plugin(self):
        config = Config()
        engine = ScanEngine(config)
        class MockPlugin:
            name = "plugin"
            version = "1.0.0"
            async def scan(self, target, config):
                pass
            def supports(self, target):
                return True
        engine.register_plugin("test_plugin", MockPlugin())
        assert "test_plugin" in engine._plugins

    def test_get_mode_router(self):
        config = Config()
        engine = ScanEngine(config)
        router = engine.get_mode_router()
        assert isinstance(router, ModeRouter)

    def test_get_supported_scanners(self):
        config = Config()
        engine = ScanEngine(config)
        class MockScanner(BaseScanner):
            name = "mock"
            version = "1.0.0"
            async def scan(self, target):
                pass
            def supports(self, target):
                return True
        scanner = MockScanner(config)
        engine.register_scanner(scanner)
        supported = engine.get_supported_scanners("test.py")
        assert len(supported) == 1

    def test_generate_scan_plan(self):
        config = Config()
        engine = ScanEngine(config)
        plan = engine.generate_scan_plan("test_project")
        assert plan is not None

    def test_generate_scan_plan_with_force_strategy(self):
        config = Config()
        engine = ScanEngine(config)
        plan = engine.generate_scan_plan("test_project", force_strategy="security-first")
        assert plan is not None

    def test_get_current_plan(self):
        config = Config()
        engine = ScanEngine(config)
        assert engine.get_current_plan() is None
        engine.generate_scan_plan("test_project")
        assert engine.get_current_plan() is not None

    def test_get_plan_metadata(self):
        config = Config()
        engine = ScanEngine(config)
        metadata = engine.get_plan_metadata()
        assert isinstance(metadata, dict)

    def test_scan_no_scanner(self):
        config = Config()
        engine = ScanEngine(config)
        result = asyncio.get_event_loop().run_until_complete(engine.scan("test.py"))
        assert result.status == ScanStatus.FAILED

    def test_create_result_from_scanner(self):
        config = Config()
        class MockScanner(BaseScanner):
            name = "mock"
            version = "1.0.0"
            async def scan(self, target):
                return self.create_result(target)
            def supports(self, target):
                return True
        scanner = MockScanner(config)
        result = scanner.create_result("test.py")
        assert result.target == "test.py"
        assert result.status == ScanStatus.PENDING
