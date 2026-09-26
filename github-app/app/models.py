import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Enum as SAEnum, JSON, ForeignKey, Boolean,
    Index,
)
from sqlalchemy.orm import relationship
from app.database import Base


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class FinalVerdict(str, enum.Enum):
    pass_ = "pass"
    warning = "warning"
    fail = "fail"


class ScanRun(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        Index("uq_scan_dedupe_key", "dedupe_key", unique=True),
    )

    id = Column(Integer, primary_key=True, index=True)
    repo_full_name = Column(String, nullable=False, index=True)
    pr_number = Column(Integer, nullable=False)
    head_sha = Column(String, nullable=False)
    installation_id = Column(Integer, nullable=False)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.pending, nullable=False)
    verdict = Column(SAEnum(FinalVerdict), nullable=True)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    # Only the latest run for a head owns its key; historical retries keep NULL.
    dedupe_key = Column(String, nullable=True)
    locked_until = Column(DateTime, nullable=True)
    worker_id = Column(String, nullable=True)
    attempts = Column(Integer, nullable=False, default=0, server_default="0")
    available_at = Column(DateTime, nullable=True)

    findings = relationship("ScanFinding", back_populates="scan_run", cascade="all, delete-orphan")


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    file = Column(String, nullable=False)
    line = Column(Integer, nullable=True)
    severity = Column(String, nullable=False)
    rule = Column(String, nullable=False)
    explanation = Column(Text, nullable=False)
    raw_evidence = Column(Text, nullable=False)
    proposed_patch = Column(Text, nullable=True)
    patch_verified = Column(String, nullable=True)   # "approve" | "revise" | "reject"
    fix_applied = Column(Boolean, default=False, nullable=False, server_default="0")
    fix_commit_sha = Column(String, nullable=True)
    agent_data = Column(JSON, nullable=True)          # full agent output blob

    scan_run = relationship("ScanRun", back_populates="findings")


class OutboxStatus(str, enum.Enum):
    pending = "pending"
    delivered = "delivered"
    failed = "failed"


class ReportingOutbox(Base):
    """Durable GitHub publication awaiting dispatch (commit status / PR review)."""
    __tablename__ = "reporting_outbox"

    id = Column(Integer, primary_key=True, index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    event_type = Column(String, nullable=False)          # "commit_status" | "pr_review"
    repo_full_name = Column(String, nullable=False)
    pr_number = Column(Integer, nullable=False)
    head_sha = Column(String, nullable=False)
    installation_id = Column(Integer, nullable=False)
    payload = Column(JSON, nullable=False)
    status = Column(SAEnum(OutboxStatus), default=OutboxStatus.pending, nullable=False)
    attempts = Column(Integer, nullable=False, default=0, server_default="0")
    locked_until = Column(DateTime, nullable=True)
    worker_id = Column(String, nullable=True)
    available_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
