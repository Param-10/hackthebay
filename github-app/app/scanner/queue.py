"""Durable scan scheduling using atomic updates on SQLite or PostgreSQL."""
from datetime import datetime, timedelta, timezone
import uuid

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from app.database import SessionLocal
from app.models import FinalVerdict, ScanRun, ScanStatus

LEASE_SECONDS = 600
MAX_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 5


class LeaseLost(RuntimeError):
    pass


def utcnow():
    # Existing database timestamps are stored without a timezone, in UTC.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def scan_key(repo: str, pr_number: int, head_sha: str) -> str:
    return f"{repo.lower()}:{pr_number}:{head_sha.lower()}"


def enqueue_scan(job: dict, *, retry: bool = False) -> tuple[int, bool]:
    key = scan_key(job["repo_full_name"], job["pr_number"], job["head_sha"])
    with SessionLocal() as db:
        existing = db.query(ScanRun).filter(ScanRun.dedupe_key == key).first()
        if existing:
            if existing.status in (ScanStatus.pending, ScanStatus.running):
                return existing.id, False
            if not retry:
                # A concurrent manual retry may be taking over the key right now;
                # resolve to whichever run owns it at return time so webhook
                # responses never point at a stale terminal history row.
                current = db.query(ScanRun).filter(ScanRun.dedupe_key == key).first()
                return (current.id if current is not None else existing.id), False
            # Release only a terminal run's identity, preserving its findings/history.
            changed = db.query(ScanRun).filter(
                ScanRun.id == existing.id,
                ScanRun.dedupe_key == key,
                ScanRun.status.in_([ScanStatus.completed, ScanStatus.failed]),
            ).update({ScanRun.dedupe_key: None}, synchronize_session=False)
            if not changed:
                db.rollback()
                current = db.query(ScanRun).filter(ScanRun.dedupe_key == key).one()
                return current.id, False
        run = ScanRun(
            repo_full_name=job["repo_full_name"], pr_number=job["pr_number"],
            head_sha=job["head_sha"], installation_id=job["installation_id"],
            status=ScanStatus.pending, dedupe_key=key,
        )
        db.add(run)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            current = db.query(ScanRun).filter(ScanRun.dedupe_key == key).first()
            if current is None:
                raise
            return current.id, False
        return run.id, True


def recover_stale_scans() -> int:
    now = utcnow()
    with SessionLocal() as db:
        expired = (
            ScanRun.status == ScanStatus.running,
            or_(ScanRun.locked_until.is_(None), ScanRun.locked_until <= now),
        )
        failed = db.query(ScanRun).filter(*expired, ScanRun.attempts >= MAX_ATTEMPTS).update({
            ScanRun.status: ScanStatus.failed, ScanRun.verdict: FinalVerdict.fail,
            ScanRun.summary: "Scan failed after 3 attempts: worker lease expired (SCAN_TIMEOUT). Retry manually.",
            ScanRun.worker_id: None, ScanRun.locked_until: None,
        }, synchronize_session=False)
        recovered = db.query(ScanRun).filter(*expired, ScanRun.attempts < MAX_ATTEMPTS).update({
            ScanRun.status: ScanStatus.pending, ScanRun.worker_id: None,
            ScanRun.locked_until: None, ScanRun.available_at: now,
            ScanRun.summary: "Interrupted scan recovered; waiting for another attempt.",
        }, synchronize_session=False)
        db.commit()
        return failed + recovered


def claim_scan() -> tuple[int, str] | None:
    recover_stale_scans()
    now = utcnow()
    with SessionLocal() as db:
        eligible = (
            ScanRun.status == ScanStatus.pending,
            ScanRun.dedupe_key.is_not(None),
            ScanRun.attempts < MAX_ATTEMPTS,
            or_(ScanRun.available_at.is_(None), ScanRun.available_at <= now),
        )
        ids = [row.id for row in db.query(ScanRun.id).filter(*eligible).order_by(ScanRun.id).limit(20)]
        db.rollback()  # Do not upgrade a stale read snapshot to a write transaction.
        for scan_id in ids:
            owner = str(uuid.uuid4())
            claimed = db.query(ScanRun).filter(ScanRun.id == scan_id, *eligible).update({
                ScanRun.status: ScanStatus.running, ScanRun.worker_id: owner,
                ScanRun.locked_until: now + timedelta(seconds=LEASE_SECONDS),
                ScanRun.attempts: ScanRun.attempts + 1,
            }, synchronize_session=False)
            db.commit()
            if claimed:
                return scan_id, owner
    return None


def owned_query(db, scan_id: int, owner: str):
    return db.query(ScanRun).filter(
        ScanRun.id == scan_id, ScanRun.worker_id == owner,
        ScanRun.status == ScanStatus.running, ScanRun.dedupe_key.is_not(None),
        ScanRun.locked_until > utcnow(),
    )


def assert_owned(scan_id: int, owner: str) -> None:
    with SessionLocal() as db:
        if owned_query(db, scan_id, owner).first() is None:
            raise LeaseLost(f"Scan {scan_id} no longer owns its lease")


def fence_result(db, scan_run) -> None:
    """Hold a row write lock until results commit; stale attempts cannot overwrite them."""
    owner = getattr(scan_run, "worker_id", None)
    if owner is not None and not owned_query(db, scan_run.id, owner).update(
        {ScanRun.worker_id: owner}, synchronize_session=False,
    ):
        db.rollback()
        raise LeaseLost(f"Scan {scan_run.id} no longer owns its lease")


def retry_or_fail(scan_id: int, owner: str, *, reason: str = "SCANNER_INTERNAL") -> bool:
    """Return True only when this attempt reaches terminal failure."""
    with SessionLocal() as db:
        run = owned_query(db, scan_id, owner).first()
        if run is None:
            return False
        terminal = run.attempts >= MAX_ATTEMPTS
        updated = owned_query(db, scan_id, owner).update({
            ScanRun.status: ScanStatus.failed if terminal else ScanStatus.pending,
            ScanRun.verdict: FinalVerdict.fail if terminal else None,
            ScanRun.summary: (
                f"Scan failed after 3 attempts ({reason}). Retry manually."
                if terminal else f"Scan interrupted ({reason}); retry scheduled."
            ),
            ScanRun.worker_id: None, ScanRun.locked_until: None,
            ScanRun.available_at: utcnow() + timedelta(seconds=RETRY_DELAY_SECONDS),
        }, synchronize_session=False)
        db.commit()
        return bool(updated and terminal)
