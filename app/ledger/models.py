"""SQLAlchemy 2.x declarative models for the GuardRail run ledger.

Defines all five required persistence entities:
1. Run: Represents one sandbox execution or evaluation run.
2. Event: Chronological lifecycle or audit event tied to a run.
3. CommandAttempt: Record of each attempted command and allow/block decision.
4. PolicyDecision: Security policy decision linked to a run and command attempt.
5. Evaluation: Requested evaluation batch or benchmark job.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.ledger.database import Base


def utcnow() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class Run(Base):
    """Run model representing one sandbox execution or evaluation run."""

    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    sandbox_name: Mapped[str | None] = mapped_column(
        String(64), unique=True, index=True, nullable=True
    )
    problem_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default="prompt_injection_exfil"
    )
    defense_profile: Mapped[str] = mapped_column(String(32), nullable=False, default="baseline")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="created")
    execution_target: Mapped[str] = mapped_column(
        String(32), nullable=False, default="celesto_sandbox"
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    wall_clock_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    boot_to_ready_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    attack_success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    evidence_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    run_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    # Relationships
    events: Mapped[list["Event"]] = relationship(
        "Event", back_populates="run", cascade="all, delete-orphan", order_by="Event.timestamp"
    )
    command_attempts: Mapped[list["CommandAttempt"]] = relationship(
        "CommandAttempt",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="CommandAttempt.timestamp",
    )
    policy_decisions: Mapped[list["PolicyDecision"]] = relationship(
        "PolicyDecision",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="PolicyDecision.timestamp",
    )

    def __repr__(self) -> str:
        return f"<Run(run_id='{self.run_id}', sandbox='{self.sandbox_name}', state='{self.state}')>"


class Event(Base):
    """Chronological lifecycle or audit event associated with a run."""

    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    run_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    run: Mapped["Run"] = relationship("Run", back_populates="events")

    def __repr__(self) -> str:
        return (
            f"<Event(event_id='{self.event_id}', run_id='{self.run_id}', type='{self.event_type}')>"
        )


class CommandAttempt(Base):
    """Record of an attempted command and whether it was allowed or blocked."""

    __tablename__ = "command_attempts"

    attempt_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    run_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)  # "allow" or "block"
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(
        String(16), nullable=True
    )  # "low", "medium", "high", "critical"
    execution_target: Mapped[str] = mapped_column(
        String(32), nullable=False, default="celesto_sandbox"
    )
    canary_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    run: Mapped["Run"] = relationship("Run", back_populates="command_attempts")
    policy_decisions: Mapped[list["PolicyDecision"]] = relationship(
        "PolicyDecision", back_populates="command_attempt"
    )

    def __repr__(self) -> str:
        return f"<CommandAttempt(attempt_id='{self.attempt_id}', decision='{self.decision}')>"


class PolicyDecision(Base):
    """Security policy decision made about an attempted action."""

    __tablename__ = "policy_decisions"

    decision_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    run_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("command_attempts.attempt_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    policy_name: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)  # "allow" or "block"
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    run: Mapped["Run"] = relationship("Run", back_populates="policy_decisions")
    command_attempt: Mapped["CommandAttempt | None"] = relationship(
        "CommandAttempt", back_populates="policy_decisions"
    )

    def __repr__(self) -> str:
        return f"<PolicyDecision(decision_id='{self.decision_id}', policy='{self.policy_name}')>"


class Evaluation(Base):
    """Requested evaluation job containing tasks across defense configurations."""

    __tablename__ = "evaluations"

    evaluation_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    task: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    defense_profile: Mapped[str] = mapped_column(String(32), nullable=False)
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, default=20)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:
        return f"<Evaluation(id='{self.evaluation_id}', status='{self.status}')>"
