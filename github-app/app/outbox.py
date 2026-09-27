"""Durable reporting outbox.

GitHub review and commit-status publications are staged in the database
atomically with the scan result and dispatched by a small retrying worker,
so a crash between saving findings and notifying GitHub no longer loses
feedback. Delivery is at-least-once: an ambiguous HTTP response may re-send,
and the reporter's existing idempotence guards (status overwrite, duplicate
review detection) absorb the repeats.
"""
from __future__ import annotations

import logging
import threading
import uuid
from datetime import timedelta

from sqlalchemy import or_

from app.agents.reasoning import ReasoningOutput
from app.agents.verification import VerificationOutput
from app.database import SessionLocal
from app.models import OutboxStatus, ReportingOutbox
from app.reporter import post_commit_status, post_pr_review
from app.scanner.fetcher import get_installation_token
from app.scanner.queue import utcnow

logger = logging.getLogger(__name__)

OUTBOX_LEASE_SECONDS = 60
MAX_OUTBOX_ATTEMPTS = 5
OUTBOX_RETRY_DELAY_SECONDS = 5

_COMMIT_STATUS = "commit_status"
_PR_REVIEW = "pr_review"


def enqueue_commit_status(
    db, scan_run_id: int, repo: str, pr_number: int, head_sha: str,
    installation_id: int, overall_risk: str, summary: str,
) -> None:
    """Stage a commit-status publication; caller commits with the scan result."""
    db.add(ReportingOutbox(
        scan_run_id=scan_run_id, event_type=_COMMIT_STATUS, repo_full_name=repo,
        pr_number=pr_number, head_sha=head_sha, installation_id=installation_id,
        payload={"overall_risk": overall_risk, "summary": summary},
    ))


def enqueue_pr_review(
    db, scan_run_id: int, repo: str, pr_number: int, head_sha: str,
    installation_id: int, reasoning: ReasoningOutput, verification: VerificationOutput,
) -> None:
    """Stage a PR-review publication; caller commits with the scan result."""
    db.add(ReportingOutbox(
        scan_run_id=scan_run_id, event_type=_PR_REVIEW, repo_full_name=repo,
        pr_number=pr_number, head_sha=head_sha, installation_id=installation_id,
        payload={
            "reasoning": reasoning.model_dump(mode="json"),
            "verification": verification.model_dump(mode="json"),
        },
    ))


def claim_outbox_event() -> tuple[int, dict, str] | None:
    """Claim the oldest eligible event with a short lease (fencing style)."""
    now = utcnow()
    with SessionLocal() as db:
        db.query(ReportingOutbox).filter(
            ReportingOutbox.status == OutboxStatus.pending,
            ReportingOutbox.worker_id.is_not(None),
            or_(ReportingOutbox.locked_until.is_(None), ReportingOutbox.locked_until <= now),
        ).update({
            ReportingOutbox.locked_until: None, ReportingOutbox.worker_id: None,
        }, synchronize_session=False)
        db.commit()
        eligible = (
            ReportingOutbox.status == OutboxStatus.pending,
            ReportingOutbox.attempts < MAX_OUTBOX_ATTEMPTS,
            or_(ReportingOutbox.available_at.is_(None), ReportingOutbox.available_at <= now),
            or_(ReportingOutbox.locked_until.is_(None), ReportingOutbox.locked_until <= now),
        )
        ids = [row.id for row in db.query(ReportingOutbox.id).filter(*eligible).order_by(ReportingOutbox.id).limit(10)]
        db.rollback()  # Do not upgrade a stale read snapshot to a write transaction.
        for event_id in ids:
            owner = str(uuid.uuid4())
            claimed = db.query(ReportingOutbox).filter(ReportingOutbox.id == event_id, *eligible).update({
                ReportingOutbox.worker_id: owner,
                ReportingOutbox.locked_until: now + timedelta(seconds=OUTBOX_LEASE_SECONDS),
                ReportingOutbox.attempts: ReportingOutbox.attempts + 1,
            }, synchronize_session=False)
            db.commit()
            if claimed:
                event = db.get(ReportingOutbox, event_id)
                return (
                    event_id,
                    {
                        "type": event.event_type,
                        "repo_full_name": event.repo_full_name,
                        "pr_number": event.pr_number,
                        "head_sha": event.head_sha,
                        "installation_id": event.installation_id,
                        "payload": event.payload or {},
                    },
                    owner,
                )
    return None


def dispatch_event(data: dict) -> None:
    """Deliver one staged publication; raises on any failure."""
    token = get_installation_token(data["installation_id"])
    payload = data["payload"]
    if data["type"] == _COMMIT_STATUS:
        post_commit_status(
            data["repo_full_name"], data["head_sha"], token,
            payload["overall_risk"], payload["summary"],
        )
    else:
        reasoning = ReasoningOutput.model_validate(payload["reasoning"])
        verification = VerificationOutput.model_validate(payload["verification"])
        post_pr_review(
            data["repo_full_name"], data["pr_number"], data["head_sha"], token,
            reasoning, verification,
        )


def mark_outbox_result(event_id: int, owner: str, *, error: str | None) -> bool:
    """Record delivery (error=None) or schedule a bounded retry / terminal failure."""
    with SessionLocal() as db:
        owned = db.query(ReportingOutbox).filter(
            ReportingOutbox.id == event_id,
            ReportingOutbox.worker_id == owner,
            ReportingOutbox.locked_until > utcnow(),
        )
        event = owned.first()
        if event is None:
            return False
        if error is None:
            owned.update({
                ReportingOutbox.status: OutboxStatus.delivered,
                ReportingOutbox.locked_until: None, ReportingOutbox.worker_id: None,
            }, synchronize_session=False)
        else:
            terminal = event.attempts >= MAX_OUTBOX_ATTEMPTS
            owned.update({
                ReportingOutbox.status: OutboxStatus.failed if terminal else OutboxStatus.pending,
                ReportingOutbox.last_error: error[:500],
                ReportingOutbox.locked_until: None, ReportingOutbox.worker_id: None,
                ReportingOutbox.available_at: utcnow() + timedelta(seconds=OUTBOX_RETRY_DELAY_SECONDS),
            }, synchronize_session=False)
        db.commit()
        return True


def reporting_loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            claimed = claim_outbox_event()
            if claimed is None:
                stop.wait(1)
                continue
            event_id, data, owner = claimed
            try:
                dispatch_event(data)
                mark_outbox_result(event_id, owner, error=None)
            except Exception as exc:
                logger.exception("Outbox dispatch failed for event %s", event_id)
                mark_outbox_result(event_id, owner, error=str(exc))
        except Exception:
            logger.exception("Reporting outbox iteration failed")
            stop.wait(2)


def start_reporting_worker():
    stop = threading.Event()
    thread = threading.Thread(
        target=reporting_loop, args=(stop,), name="polaris-outbox", daemon=True,
    )
    thread.start()
    return stop, thread


def stop_reporting_worker(handle) -> None:
    stop, thread = handle
    stop.set()
    thread.join(timeout=5)