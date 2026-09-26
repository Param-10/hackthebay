from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

os.environ.setdefault("GITHUB_APP_ID", "1")
os.environ.setdefault("GITHUB_PRIVATE_KEY", "unused.pem")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret")
os.environ.setdefault("GEMINI_API_KEY", "test-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import make_url

from app.agents.reasoning import ReasonedFinding, ReasoningOutput
from app.agents.verification import VerificationOutput
from app.database import Base
from app.models import OutboxStatus, ReportingOutbox
from app.scanner import queue
from app import outbox

JOB = {"repo_full_name": "owner/repo", "pr_number": 1, "head_sha": "abc", "installation_id": 7}


@contextmanager
def isolated_database(directory):
    dsn = os.environ.get("QUEUE_TEST_DATABASE_URL")
    admin = None
    if dsn:
        admin = create_engine(dsn)
        schema = "outbox_test_" + uuid.uuid4().hex
        with admin.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        url = make_url(dsn).update_query_dict({"options": f"-csearch_path={schema}"})
        engine = create_engine(url)
    else:
        engine = create_engine(f"sqlite:///{Path(directory) / 'outbox.db'}",
                               connect_args={"check_same_thread": False, "timeout": 15})
    try:
        yield engine
    finally:
        engine.dispose()
        if admin is not None:
            admin.dispose()


class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.engine = self.enterContext(isolated_database(self.temp.name))
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, autoflush=False)
        for module in [queue, outbox]:
            patcher = patch.object(module, "SessionLocal", self.sessions)
            patcher.start()
            self.addCleanup(patcher.stop)

    def stage_commit_status(self, risk="high", summary="Two high findings"):
        scan_id, _ = queue.enqueue_scan(JOB)
        with self.sessions() as db:
            outbox.enqueue_commit_status(
                db, scan_id, JOB["repo_full_name"], JOB["pr_number"], JOB["head_sha"],
                JOB["installation_id"], risk, summary,
            )
            db.commit()
        return scan_id

    def test_commit_status_event_is_delivered(self):
        self.stage_commit_status()
        with patch.object(outbox, "get_installation_token", return_value="token"), \
             patch.object(outbox, "post_commit_status") as post:
            claimed = outbox.claim_outbox_event()
            self.assertIsNotNone(claimed)
            event_id, data, owner = claimed
            outbox.dispatch_event(data)
            outbox.mark_outbox_result(event_id, owner, error=None)
        post.assert_called_once_with(
            JOB["repo_full_name"], JOB["head_sha"], "token", "high", "Two high findings",
        )
        with self.sessions() as db:
            event = db.get(ReportingOutbox, event_id)
            self.assertEqual(event.status, OutboxStatus.delivered)

    def test_review_payload_round_trips_through_dispatch(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        reasoning = ReasoningOutput(
            overall_risk="high",
            summary="Two high findings",
            findings=[
                ReasonedFinding(
                    file="main.tf", line=1, severity="high", rule="TF001: Encryption disabled",
                    explanation="Encryption disabled on the resource.",
                    risk_context="Threat: data exposure. Impact: breach.",
                    proposed_patch=None, patch_explanation=None,
                    evidence="encrypted = false",
                ),
            ],
        )
        verification = VerificationOutput(verdicts=[], all_clear=True)
        with self.sessions() as db:
            outbox.enqueue_pr_review(
                db, scan_id, JOB["repo_full_name"], JOB["pr_number"], JOB["head_sha"],
                JOB["installation_id"], reasoning, verification,
            )
            db.commit()
        with patch.object(outbox, "get_installation_token", return_value="token"), \
             patch.object(outbox, "post_pr_review") as review:
            event_id, data, owner = outbox.claim_outbox_event()
            outbox.dispatch_event(data)
            outbox.mark_outbox_result(event_id, owner, error=None)
        repo, pr, sha, token, got_reasoning, got_verification = review.call_args.args
        self.assertEqual((repo, pr, sha, token), (JOB["repo_full_name"], JOB["pr_number"], JOB["head_sha"], "token"))
        self.assertEqual(got_reasoning, reasoning)
        self.assertEqual(got_verification, verification)

    def test_failed_dispatch_retries_then_terminally_fails(self):
        event_id = self.stage_commit_status()
        with patch.object(outbox, "get_installation_token", return_value="token"), \
             patch.object(outbox, "post_commit_status", side_effect=RuntimeError("network down")):
            for _ in range(outbox.MAX_OUTBOX_ATTEMPTS):
                claimed = outbox.claim_outbox_event()
                self.assertIsNotNone(claimed)
                _, data, owner = claimed
                with self.assertRaises(RuntimeError):
                    outbox.dispatch_event(data)
                outbox.mark_outbox_result(event_id, owner, error="network down")
                with self.sessions() as db:
                    db.query(ReportingOutbox).filter_by(id=event_id).update(
                        {"available_at": outbox.utcnow() - timedelta(seconds=1)},
                        synchronize_session=False,
                    )
                    db.commit()
        self.assertIsNone(outbox.claim_outbox_event())
        with self.sessions() as db:
            event = db.get(ReportingOutbox, event_id)
            self.assertEqual(event.status, OutboxStatus.failed)
            self.assertIn("network down", event.last_error)
            self.assertEqual(event.attempts, outbox.MAX_OUTBOX_ATTEMPTS)

    def test_claim_returns_none_when_outbox_is_idle(self):
        queue.enqueue_scan(JOB)
        self.assertIsNone(outbox.claim_outbox_event())

    def test_expired_lease_is_reclaimed(self):
        self.stage_commit_status()
        first = outbox.claim_outbox_event()
        self.assertIsNotNone(first)
        with self.sessions() as db:
            db.query(ReportingOutbox).filter_by(id=first[0]).update(
                {"locked_until": outbox.utcnow() - timedelta(seconds=1),
                 "available_at": None}, synchronize_session=False)
            db.commit()
        second = outbox.claim_outbox_event()
        self.assertEqual(second[0], first[0])
        self.assertNotEqual(second[2], first[2])


if __name__ == "__main__":
    unittest.main()