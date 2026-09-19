"""SentinelForge — Test configuration and shared fixtures."""

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import Base
from sentinelforge.remediation.persistence import SessionFactory

# Dedicated test signing key — NEVER use this in production.
TEST_SIGNING_KEY = "sentinelforge-test-signing-key-not-for-production"


@pytest.fixture(autouse=True)
def _set_test_signing_key(monkeypatch):
    """Ensure SENTINELFORGE_SIGNING_KEY is set for all tests.

    Tests that construct SafetyBoundaryBridge() or RedAgentPlanner() without
    explicit arguments will use this dedicated test key. Production code
    requires SENTINELFORGE_SIGNING_KEY to be set via environment/secrets manager.
    """
    monkeypatch.setenv("SENTINELFORGE_SIGNING_KEY", TEST_SIGNING_KEY)


@pytest.fixture
def test_session_factory():
    """Create an in-memory SQLite session factory for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    # Import all models so Base metadata is populated
    import sentinelforge.db.models  # noqa: F401
    import sentinelforge.db.digital_twin_models  # noqa: F401
    import sentinelforge.remediation.db_models  # noqa: F401

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    return SessionFactory(Session)
