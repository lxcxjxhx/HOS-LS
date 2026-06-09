"""Utils logger module tests"""

import logging
import tempfile
import pytest
import os

from src.utils.logger import setup_logging, get_logger


class TestSetupLogging:
    def test_setup_default(self):
        logger = setup_logging(level="INFO")
        assert logger.name == "hos-ls"
        assert logger.level == logging.INFO
        assert len(logger.handlers) > 0

    def test_setup_debug_level(self):
        logger = setup_logging(level="DEBUG")
        assert logger.level == logging.DEBUG

    def test_setup_warning_level(self):
        logger = setup_logging(level="WARNING")
        assert logger.level == logging.WARNING

    def test_setup_error_level(self):
        logger = setup_logging(level="ERROR")
        assert logger.level == logging.ERROR

    def test_setup_with_file(self):
        with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
            logger = setup_logging(level="INFO", log_file=f.name)
            assert len(logger.handlers) >= 2

    def test_setup_without_rich(self):
        logger = setup_logging(level="INFO", use_rich=False)
        assert len(logger.handlers) > 0

    def test_handlers_cleared_on_reinit(self):
        logger = setup_logging(level="INFO")
        initial_count = len(logger.handlers)
        logger2 = setup_logging(level="DEBUG")
        assert len(logger2.handlers) > 0


class TestGetLogger:
    def test_get_default_logger(self):
        logger = get_logger()
        assert logger.name == "hos-ls"

    def test_get_named_logger(self):
        logger = get_logger("custom-logger")
        assert logger.name == "custom-logger"

    def test_get_same_logger_twice(self):
        logger1 = get_logger("test-logger")
        logger2 = get_logger("test-logger")
        assert logger1 is logger2
