"""
Shared pytest fixtures.

Auth override: every test that hits the API gets a mock admin user injected
via FastAPI's dependency_overrides so no real database or JWT is needed.

DB override: all tests use a fresh in-memory SQLite database, isolated from
forensic.db so accumulated real data doesn't pollute test assertions.
"""
import pytest
from types import SimpleNamespace
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from main import app
from backend.api.auth import get_current_user
from backend.db.models import Base, get_db


def _make_test_engine():
    # StaticPool: all sessions share one connection → single in-memory DB
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa_event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, _record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    return engine


def _mock_admin():
    return SimpleNamespace(id=1, username="test_admin", role="admin", is_active=True)


@pytest.fixture(autouse=True)
def override_auth_and_db():
    """Fresh in-memory DB + mock admin user for every test."""
    engine = _make_test_engine()
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def _get_test_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_current_user] = _mock_admin
    app.dependency_overrides[get_db] = _get_test_db
    yield
    app.dependency_overrides.clear()
    engine.dispose()
