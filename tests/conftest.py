"""Pytest configuration and fixtures."""

import pytest

from apiposture.core.analysis.source_loader import ParsedSource, SourceLoader


@pytest.fixture
def parse_code():
    """Fixture to parse Python code from a string."""
    def _parse(code: str) -> ParsedSource:
        return SourceLoader.parse_text(code)
    return _parse
