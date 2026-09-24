"""Add durable scan columns and identity index without deleting scan history.

Run with old web/worker processes stopped: python -m app.migrate
"""
from sqlalchemy import inspect, text

from app.database import Base, engine
from app import models  # noqa: F401
from app.scanner.queue import scan_key


def upgrade(bind=engine):
    with bind.begin() as conn:
        if conn.dialect.name == "sqlite":
            conn.exec_driver_sql("BEGIN IMMEDIATE")
        elif conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(728194201)"))
        tables = inspect(conn).get_table_names()
        if "scan_runs" not in tables:
            Base.metadata.create_all(bind=conn)
            return
        if conn.dialect.name == "postgresql":
            conn.execute(text("LOCK TABLE scan_runs IN ACCESS EXCLUSIVE MODE"))
        columns = {column["name"] for column in inspect(conn).get_columns("scan_runs")}
        additions = {
            "dedupe_key": "VARCHAR", "locked_until": "TIMESTAMP",
            "worker_id": "VARCHAR", "attempts": "INTEGER NOT NULL DEFAULT 0",
            "available_at": "TIMESTAMP",
        }
        for name, definition in additions.items():
            if name not in columns:
                conn.execute(text(f"ALTER TABLE scan_runs ADD COLUMN {name} {definition}"))
        if "dedupe_key" not in columns:
            # Keep the latest historical run as the identity owner. Preserve old IDs
            # and findings; terminalize older duplicate active runs instead of deleting.
            seen = set()
            rows = conn.execute(text(
                "SELECT id, repo_full_name, pr_number, head_sha, status FROM scan_runs ORDER BY id DESC"
            )).mappings().all()
            for row in rows:
                key = scan_key(row["repo_full_name"], row["pr_number"], row["head_sha"])
                if key not in seen:
                    conn.execute(text("UPDATE scan_runs SET dedupe_key=:key WHERE id=:id"),
                                 {"key": key, "id": row["id"]})
                    seen.add(key)
                elif row["status"] in ("pending", "running"):
                    conn.execute(text(
                        "UPDATE scan_runs SET status='failed', verdict='fail', "
                        "summary='Superseded by a newer scan during durable queue migration.' WHERE id=:id"
                    ), {"id": row["id"]})
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_dedupe_key ON scan_runs (dedupe_key)"))


if __name__ == "__main__":
    upgrade()
    print("Durable scan migration complete.")
