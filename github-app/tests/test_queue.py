from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
import multiprocessing
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("GITHUB_APP_ID", "1")
os.environ.setdefault("GITHUB_PRIVATE_KEY", "unused.pem")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret")
os.environ.setdefault("GEMINI_API_KEY", "test-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import make_url

from app.database import Base
from app.migrate import upgrade
from app.models import FinalVerdict, ScanFinding, ScanRun, ScanStatus
from app.scanner import queue, worker

JOB = {"repo_full_name": "owner/repo", "pr_number": 1, "head_sha": "abc", "installation_id": 7}


@contextmanager
def isolated_database(directory):
    dsn = os.environ.get("QUEUE_TEST_DATABASE_URL")
    admin = None
    if dsn:
        admin = create_engine(dsn)
        schema = "queue_test_" + uuid.uuid4().hex
        with admin.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        url = make_url(dsn).update_query_dict({"options": f"-csearch_path={schema}"})
        engine = create_engine(url)
    else:
        engine = create_engine(f"sqlite:///{Path(directory) / 'queue.db'}",
                               connect_args={"check_same_thread": False, "timeout": 15})
    try:
        yield engine
    finally:
        engine.dispose()
        if admin is not None:
            with admin.begin() as conn:
                conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin.dispose()


def claim_in_process(url, ready, hold=False):
    engine = create_engine(url)
    queue.SessionLocal = sessionmaker(bind=engine, autoflush=False)
    claimed = queue.claim_scan()
    ready.send(claimed)
    ready.close()
    if hold:
        time.sleep(60)
    engine.dispose()


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.engine = self.enterContext(isolated_database(self.temp.name))
        self.url = self.engine.url.render_as_string(hide_password=False)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, autoflush=False)
        for module in [queue, worker]:
            patcher = patch.object(module, "SessionLocal", self.sessions)
            patcher.start()
            self.addCleanup(patcher.stop)

    def get(self, scan_id):
        with self.sessions() as db:
            run = db.get(ScanRun, scan_id)
            db.expunge(run)
            return run

    def expire(self, scan_id):
        with self.sessions() as db:
            db.query(ScanRun).filter_by(id=scan_id).update({"locked_until": queue.utcnow() - timedelta(seconds=1)})
            db.commit()

    def test_concurrent_enqueue_creates_exactly_one_run(self):
        barrier = threading.Barrier(8)
        def enqueue(_):
            barrier.wait()
            return queue.enqueue_scan(JOB)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(enqueue, range(8)))
        self.assertEqual(len({result[0] for result in results}), 1)
        self.assertEqual(sum(result[1] for result in results), 1)

    def test_redelivery_after_completion_is_a_noop(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        with self.sessions() as db:
            db.get(ScanRun, scan_id).status = ScanStatus.completed
            db.commit()
        self.assertEqual(queue.enqueue_scan(JOB), (scan_id, False))

    def test_manual_retry_preserves_history_and_deduplicates(self):
        original, _ = queue.enqueue_scan(JOB)
        with self.sessions() as db:
            db.get(ScanRun, original).status = ScanStatus.failed
            db.add(ScanFinding(scan_run_id=original, file="x.tf", rule="TF001", severity="high", explanation="fixture", raw_evidence="fixture"))
            db.commit()
        with ThreadPoolExecutor(max_workers=6) as pool:
            retried = list(pool.map(lambda _: queue.enqueue_scan(JOB, retry=True), range(6)))
        self.assertEqual(len({row[0] for row in retried}), 1)
        self.assertEqual(sum(row[1] for row in retried), 1)
        self.assertNotEqual(original, retried[0][0])
        self.assertIsNone(self.get(original).dedupe_key)
        with self.sessions() as db:
            self.assertEqual(db.query(ScanFinding).filter_by(scan_run_id=original).count(), 1)

    def test_retry_active_run_returns_same_id(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        queue.claim_scan()
        self.assertEqual(queue.enqueue_scan(JOB, retry=True), (scan_id, False))

    def test_concurrent_claims_have_one_owner(self):
        queue.enqueue_scan(JOB)
        with ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(pool.map(lambda _: queue.claim_scan(), range(8)))
        self.assertEqual(sum(claim is not None for claim in claims), 1)

    def test_separate_processes_have_one_owner(self):
        queue.enqueue_scan(JOB)
        context = multiprocessing.get_context("spawn")
        processes, receivers = [], []
        try:
            for _ in range(3):
                receive, send = context.Pipe(duplex=False)
                process = context.Process(target=claim_in_process, args=(self.url, send))
                process.start()
                send.close()
                processes.append(process)
                receivers.append(receive)
            claims = []
            for receive in receivers:
                self.assertTrue(receive.poll(15))
                claims.append(receive.recv())
            self.assertEqual(sum(claim is not None for claim in claims), 1)
        finally:
            for process in processes:
                process.join(timeout=5)
                if process.is_alive():
                    process.terminate()
                    process.join()
                process.close()
            for receive in receivers:
                receive.close()

    def test_killed_worker_is_reclaimable_after_lease_expiry(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=claim_in_process, args=(self.url, send, True))
        process.start()
        send.close()
        try:
            self.assertTrue(receive.poll(15))
            original = receive.recv()
            process.terminate()
            process.join(timeout=5)
            self.assertIsNone(queue.claim_scan())
            self.expire(scan_id)
            recovered = queue.claim_scan()
            self.assertEqual(recovered[0], original[0])
            self.assertNotEqual(recovered[1], original[1])
            self.assertEqual(self.get(scan_id).attempts, 2)
        finally:
            if process.is_alive():
                process.kill()
                process.join()
            process.close()
            receive.close()

    def test_three_expired_attempts_become_terminal(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        for attempt in range(3):
            self.assertIsNotNone(queue.claim_scan())
            self.assertEqual(self.get(scan_id).attempts, attempt + 1)
            self.expire(scan_id)
        self.assertIsNone(queue.claim_scan())
        self.assertEqual(self.get(scan_id).status, ScanStatus.failed)
        self.assertIn("SCAN_TIMEOUT", self.get(scan_id).summary)

    def test_live_lease_is_not_recovered(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        queue.claim_scan()
        self.assertEqual(queue.recover_stale_scans(), 0)
        self.assertEqual(self.get(scan_id).status, ScanStatus.running)

    def test_null_legacy_lease_is_recovered(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        with self.sessions() as db:
            db.get(ScanRun, scan_id).status = ScanStatus.running
            db.commit()
        self.assertEqual(queue.recover_stale_scans(), 1)
        self.assertIsNotNone(queue.claim_scan())

    def test_stale_worker_cannot_commit_findings_or_status(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        queue.claim_scan()
        with self.sessions() as stale:
            run = stale.get(ScanRun, scan_id)
            self.expire(scan_id)
            current = queue.claim_scan()
            stale.add(ScanFinding(scan_run_id=scan_id, file="stale.tf", rule="TF001", severity="high", explanation="fixture", raw_evidence="fixture"))
            with self.assertRaises(queue.LeaseLost):
                worker._commit_result(run, stale, FinalVerdict.pass_, "stale result")
        self.assertEqual(self.get(scan_id).worker_id, current[1])
        self.assertEqual(self.get(scan_id).status, ScanStatus.running)
        with self.sessions() as db:
            self.assertEqual(db.query(ScanFinding).count(), 0)

    def test_failures_retry_with_backoff_and_stop_after_three_attempts(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        for attempt in range(3):
            claimed = queue.claim_scan()
            self.assertEqual(queue.retry_or_fail(*claimed), attempt == 2)
            self.assertIsNone(queue.claim_scan())
            with self.sessions() as db:
                db.get(ScanRun, scan_id).available_at = queue.utcnow() - timedelta(seconds=1)
                db.commit()
        self.assertEqual(self.get(scan_id).status, ScanStatus.failed)

    def test_execute_reconstructs_job_from_database(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        claimed = queue.claim_scan()
        with patch.object(worker, "get_installation_token", return_value="fake"), \
             patch.object(worker, "post_commit_status"), patch.object(worker, "_execute") as execute:
            execute.side_effect = lambda job, run, db: worker._commit_result(run, db, FinalVerdict.pass_, "done")
            worker.run_scan(*claimed)
        self.assertEqual(execute.call_args.args[0], JOB)
        self.assertEqual(self.get(scan_id).status, ScanStatus.completed)

    def test_worker_error_rolls_back_partial_findings(self):
        scan_id, _ = queue.enqueue_scan(JOB)
        claimed = queue.claim_scan()
        def fail(job, run, db):
            db.add(ScanFinding(scan_run_id=run.id, file="partial.tf", rule="TF001", severity="high", explanation="fixture", raw_evidence="fixture"))
            raise RuntimeError("injected failure")
        with patch.object(worker, "get_installation_token", return_value="fake"), \
             patch.object(worker, "post_commit_status"), patch.object(worker, "_execute", side_effect=fail):
            worker.run_scan(*claimed)
        self.assertEqual(self.get(scan_id).status, ScanStatus.pending)
        with self.sessions() as db:
            self.assertEqual(db.query(ScanFinding).count(), 0)

    def test_process_supervisor_terminates_timeout_before_retry(self):
        queue.enqueue_scan(JOB)
        claimed = queue.claim_scan()
        process = MagicMock()
        process.is_alive.side_effect = [True, True, False]
        with patch.object(worker.multiprocessing, "get_context") as context, \
             patch.object(worker.time, "monotonic", side_effect=[0, 1000]):
            context.return_value.Process.return_value = process
            worker.run_claimed_process(claimed, threading.Event())
        process.terminate.assert_called_once()
        process.close.assert_called_once()
        self.assertEqual(self.get(claimed[0]).status, ScanStatus.pending)
        self.assertIn("SCAN_TIMEOUT", self.get(claimed[0]).summary)

    def test_webhook_only_persists_work_and_duplicate_is_noop(self):
        from fastapi.testclient import TestClient
        import app.main as main
        with patch.object(main, "init_db"), patch.object(main, "start_worker"), \
             patch.object(main, "stop_worker"), patch.object(main, "parse_pr_event", new=AsyncMock(return_value=JOB)), \
             patch.object(worker, "get_installation_token") as token:
            with TestClient(main.app) as client:
                first = client.post("/webhook").json()
                second = client.post("/webhook").json()
        self.assertEqual(first["scan_id"], second["scan_id"])
        self.assertEqual(first["status"], "queued")
        self.assertEqual(second["status"], "already_queued")
        token.assert_not_called()


class MigrationTests(unittest.TestCase):
    def test_legacy_duplicates_and_findings_survive_idempotent_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            with isolated_database(directory) as engine:
                with engine.begin() as conn:
                    conn.execute(text("CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, repo_full_name VARCHAR, pr_number INTEGER, head_sha VARCHAR, installation_id INTEGER, status VARCHAR, verdict VARCHAR, summary VARCHAR, created_at TIMESTAMP, updated_at TIMESTAMP)"))
                    conn.execute(text("CREATE TABLE scan_findings (id INTEGER PRIMARY KEY, scan_run_id INTEGER REFERENCES scan_runs(id), file VARCHAR)"))
                    conn.execute(text("INSERT INTO scan_runs (id, repo_full_name, pr_number, head_sha, installation_id, status) VALUES (1, 'owner/repo', 1, 'abc', 7, 'running'), (2, 'owner/repo', 1, 'abc', 7, 'pending'), (3, 'owner/repo', 2, 'def', 7, 'completed')"))
                    conn.execute(text("INSERT INTO scan_findings VALUES (1, 1, 'keep.tf')"))
                upgrade(engine)
                upgrade(engine)
                with engine.connect() as conn:
                    rows = conn.execute(text("SELECT id, status, dedupe_key FROM scan_runs ORDER BY id")).all()
                    self.assertEqual(rows[0], (1, 'failed', None))
                    self.assertEqual(rows[1], (2, 'pending', 'owner/repo:1:abc'))
                    self.assertEqual(rows[2][1], 'completed')
                    self.assertEqual(conn.execute(text("SELECT file FROM scan_findings")).scalar(), 'keep.tf')

    def test_old_database_requires_explicit_migration(self):
        import app.database as database
        engine = create_engine('sqlite:///:memory:')
        try:
            with engine.begin() as conn:
                conn.execute(text('CREATE TABLE scan_runs (id INTEGER PRIMARY KEY)'))
            with patch.object(database, 'engine', engine):
                with self.assertRaisesRegex(RuntimeError, 'migration required'):
                    database.init_db()
        finally:
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
