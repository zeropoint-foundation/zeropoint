"""Shared fixtures for the SDK test suite.

Tests are run with ``pytest tests/ -k "not integration"`` by default;
integration tests (those marked ``@pytest.mark.integration``) expect a
live zp-server and are skipped by the standard CI invocation.
"""

from __future__ import annotations

import pytest

from zeropoint import ZeroPointClient

TEST_BASE_URL = "http://zp-test.localhost"


@pytest.fixture
def base_url() -> str:
    return TEST_BASE_URL


@pytest.fixture
def client(base_url: str):
    """A sync client pinned at the test base URL.

    Uses the *real* httpx transport — respx patches it at the call-site
    level via the `respx_mock` fixture.
    """
    with ZeroPointClient(base_url=base_url) as c:
        yield c
