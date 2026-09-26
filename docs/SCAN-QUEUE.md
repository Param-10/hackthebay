**Durable scan execution**

The webhook commits a pending scan before acknowledging it. Each web process
starts one polling supervisor through FastAPI's lifespan. The supervisor claims
one database job at a time and runs it in a fresh spawned Python process. The
worker reconstructs repository, PR, head SHA, and installation ID from the row;
an in-memory webhook payload is not needed after restart.

The database identity is the normalized repository, PR number, and head SHA.
A unique nullable `dedupe_key` prevents repeated webhook deliveries from creating
another run, including after completion or terminal failure. An explicit retry
releases a terminal run's key and creates a new run in the same transaction.
Historical IDs and findings remain available; concurrent retries share one new run.

Claims use a conditional database update, not a process-local lock. A claim has
a unique owner, a ten-minute lease, and an attempt number. The supervisor stops
an overlong child shortly before lease expiry. Ownership is checked during the
scan and again under a database write lock when findings and status commit.
Expired attempts cannot overwrite the results of a replacement worker.

Pending jobs are discovered every two seconds. A graceful stop terminates the
child and schedules another attempt; an abrupt supervisor/host failure is
recovered after lease expiry. Exceptions use a five-second retry delay. After
three claimed attempts, the scan becomes failed and requires an explicit retry.
Lease expiry also recovers legacy running rows with no lease. Each process runs
at most one child; use PostgreSQL when multiple hosts share the queue.

**Existing database upgrade**

Back up the database, stop all old application processes, and run from `github-app`:

```bash
python -m app.migrate
```

Then start the new application using the existing command:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The migration adds five columns and a unique index. It retains all scan and
finding records, assigns identity ownership to the latest historical run for
each head, and marks older duplicate active runs failed with an explanation.
It is repeatable. The application refuses to start against an unmigrated
existing schema. Fresh databases are initialized automatically. Never mix old
and new application versions against the migrated queue.

SQLite must use a persistent file, not `:memory:`: spawned workers open their own
connections. PostgreSQL must be shared by all application instances. Durable
storage is still required on the hosting platform; an ephemeral filesystem
cannot preserve a SQLite queue across host replacement.

**Verification**

The ordinary offline test suite uses disposable SQLite databases and mocked
GitHub/Gemini calls:

```bash
python -m unittest discover -s tests -v
```

To run the same queue/migration cases on a disposable PostgreSQL database:

```bash
QUEUE_TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/polaris_test \
  python -m unittest discover -s tests -p test_queue.py -v
```

Each PostgreSQL test creates and drops its own random `queue_test_...` schema.
Use a test database. CI provisions PostgreSQL and runs both backends. Tests cover
concurrent enqueue/claim, separate worker processes, a killed claimant, expired
ownership, bounded retries, history-preserving manual retries, and legacy migration.

**Limits**

Execution is retried, so interrupted attempts may repeat read-only GitHub calls
or AI enrichment. Results and terminal failures remain visible in the
database/dashboard. GitHub review and commit-status publications are now staged
in a durable reporting outbox (`reporting_outbox`) in the same transaction as
the scan result and dispatched by a retrying worker, so a crash after saving
findings no longer loses GitHub feedback. Delivery is at-least-once: an
ambiguous HTTP response may re-send, and the reporter's idempotence guards
(status overwrites, duplicate-review detection) absorb the repeats. Events that
exhaust their bounded retries are marked `failed` with the last error and remain
visible for manual replay or the next scan run's status overwrite.

The fixed lease assumes reasonably synchronized clocks across hosts. A killed
supervisor can leave a child alive temporarily; lease fencing protects subsequent
database writes, but cannot undo a remote request already in flight. No live
provider calls or production migration are required to run the offline tests.

**Measured performance (offline, reproducible)**

Recorded with `scan_benchmark` (kept with workspace artifacts) on Python 3.11.9;
all timings exclude live GitHub/Gemini network time.

| Measurement | n | min | p50 | p95 | max |
|---|---|---|---|---|---|
| Deterministic scan, 8-file corpus | 60 | 1.3 ms | 2.1 ms | 4.0 ms | 6.8 ms |
| Deterministic scan, 40-file corpus | 30 | 1.4 ms | 2.0 ms | 12.0 ms | 12.9 ms |
| Full scan pipeline (mocked GitHub + healthy AI), 40 files | 15 | 4 ms | 5 ms | 12 ms | 12 ms |
| Full scan pipeline, provider outage (AI_TIMEOUT) | 15 | 4 ms | 5 ms | 44 ms | 44 ms |
| Full scan pipeline, provider outage (AI_UNAVAILABLE) | 15 | 4 ms | 5 ms | 9 ms | 9 ms |
| enqueue_scan (file SQLite, 30 iters) | 30 | 0.2 ms | 0.2 ms | 0.6 ms | 5.2 ms |
| claim_scan + recover (30 iters) | 30 | 0.8 ms | 0.9 ms | 1.2 ms | 4.6 ms |
| Spawned worker startup (fresh interpreter) | 3 | 1.05 s | 1.09 s | 1.12 s | 1.12 s |

Error rates observed in the same runs:

- **Detector error rate:** 0 unhandled per-file exceptions across 48 corpus files and
  14 adversarial inputs (empty, binary, oversized, malformed YAML/Terraform/CI).
  Detector failures are contained by the per-file wrapper and log rather than fail the scan.
- **Provider error rate:** 0/15 provider errors on the healthy baseline; 15/15 scans
  degraded under an injected outage — every degraded scan still completed deterministically
  (the documented fallback), so provider failure cost ~0 additional scan time offline.

Latency drivers in production are the GitHub fetches and the Gemini budget (default 90 s
cap), not local rule execution; the dominating local constant is the ~1.1 s spawned-child
startup per scan, which is why leases are 10 minutes and the supervisor kills overlong
children before lease expiry.
