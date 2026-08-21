"""SentinelForge — Test helper for in-memory SQLite persistence tests."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import Base
from sentinelforge.remediation.persistence import SessionFactory


def create_test_session_factory():
    """Create an in-memory SQLite session factory for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return SessionFactory(Session)
