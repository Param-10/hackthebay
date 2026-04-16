import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Enum as SAEnum, JSON, ForeignKey, Boolean,
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
