"""Pytest configuration and shared fixtures."""

import sys
from pathlib import Path

# Add src to Python path
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

import pytest


@pytest.fixture
def sample_vulnerable_code():
    """Sample vulnerable code for testing."""
    return """
def vulnerable_function(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
"""


@pytest.fixture
def sample_safe_code():
    """Sample safe code for testing."""
    return """
def safe_function(user_input):
    query = "SELECT * FROM users WHERE id = ?"
    return query, (user_input,)
"""


@pytest.fixture
def temp_test_file(tmp_path):
    """Create a temporary test file."""
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_example():\n    assert True\n")
    return test_file
