"""Pytest fixtures and configuration for GuardRail test suite."""

from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.agent.audit import CommandAuditLogger
from app.ledger.database import Base, get_db
from app.ledger.models import Run
from app.main import app


@pytest.fixture(name="db_session")
def fixture_db_session() -> Generator[Session, None, None]:
    """Provide an isolated, in-memory SQLite database session for unit tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()

    # Seed the demo run record
    demo_run = Run(
        run_id="run_seeddemo1",
        sandbox_name="sbx-seeddemo1",
        problem_id="prompt_injection_exfil",
        defense_profile="baseline",
        state="deleted",
        execution_target="celesto_sandbox",
        success=True,
        wall_clock_s=18.5,
        boot_to_ready_s=0.52,
        cost_usd=0.015,
        attack_success=False,
        run_metadata={"seeded": True, "note": "Seeded unit test record"},
    )
    session.add(demo_run)
    session.commit()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(name="client")
def fixture_client(db_session: Session) -> Generator[TestClient, None, None]:
    """Provide a FastAPI TestClient with the database dependency overridden."""

    def override_get_db() -> Generator[Session, None, None]:
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def redirect_test_command_audit_logger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect test-generated command logs to a temporary file to preserve tracked evidence."""
    test_log_file = tmp_path / "test_commands.jsonl"
    orig_init = CommandAuditLogger.__init__

    def patched_init(self, log_file_path: Path | None = None, ledger_repo=None) -> None:
        effective_path = log_file_path or test_log_file
        orig_init(self, log_file_path=effective_path, ledger_repo=ledger_repo)

    monkeypatch.setattr(CommandAuditLogger, "__init__", patched_init)

