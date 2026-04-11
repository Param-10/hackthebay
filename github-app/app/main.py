import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks, Request, HTTPException
from fastapi.responses import JSONResponse

from app.database import init_db
from app.webhook import parse_pr_event
from app.scanner.worker import run_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Database initialised")
    yield


app = FastAPI(title="IaC Security Scanner", lifespan=lifespan)


@app.post("/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Entry point for GitHub App webhooks.
    Verifies signature, filters for PR events on infra files,
    then kicks off a background scan job.
    """
    job = await parse_pr_event(request)
    if job is None:
        return JSONResponse({"status": "ignored"})

    background_tasks.add_task(run_scan, job)
    logger.info(
        "Queued scan for %s PR#%s sha=%s",
        job["repo_full_name"], job["pr_number"], job["head_sha"][:8],
    )
    return JSONResponse({"status": "queued", "pr": job["pr_number"]})


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/scans/{repo_owner}/{repo_name}")
async def list_scans(repo_owner: str, repo_name: str, limit: int = 20):
    """List recent scan runs for a repo (dashboard endpoint)."""
    from app.database import SessionLocal
    from app.models import ScanRun
    db = SessionLocal()
    try:
        runs = (
            db.query(ScanRun)
            .filter(ScanRun.repo_full_name == f"{repo_owner}/{repo_name}")
            .order_by(ScanRun.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": r.id,
                "pr_number": r.pr_number,
                "head_sha": r.head_sha,
                "status": r.status,
                "verdict": r.verdict,
                "summary": r.summary,
                "created_at": r.created_at.isoformat(),
            }
            for r in runs
        ]
    finally:
        db.close()


@app.get("/scans/{scan_id}/findings")
async def get_findings(scan_id: int):
    """Return all findings for a scan run."""
    from app.database import SessionLocal
    from app.models import ScanFinding
    db = SessionLocal()
    try:
        findings = db.query(ScanFinding).filter(ScanFinding.scan_run_id == scan_id).all()
        if not findings:
            raise HTTPException(status_code=404, detail="Scan not found")
        return [
            {
                "file": f.file,
                "line": f.line,
                "severity": f.severity,
                "rule": f.rule,
                "explanation": f.explanation,
                "raw_evidence": f.raw_evidence,
                "proposed_patch": f.proposed_patch,
                "patch_verified": f.patch_verified,
            }
            for f in findings
        ]
    finally:
        db.close()
