"""SentinelForge — Test configuration and shared fixtures."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import Base
from sentinelforge.remediation.persistence import SessionFactory


@pytest.fixture
def test_session_factory():
    """Create an in-memory SQLite session factory for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    # Import all models so Base metadata is populated
    import sentinelforge.db.models  # noqa: F401
    import sentinelforge.remediation.db_models  # noqa: F401

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    return SessionFactory(Session)
