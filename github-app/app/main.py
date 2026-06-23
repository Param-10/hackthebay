import logging
import base64
import re
import time
from datetime import datetime, timezone
from collections import defaultdict
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks, Request, HTTPException, Depends
from fastapi.responses import JSONResponse

from app.database import init_db
from app.config import get_settings
from app.models import ScanStatus
from app.webhook import parse_pr_event
from app.scanner.worker import enqueue_scan, run_scan
from app.scanner.fetcher import get_installation_token, _auth_headers, GITHUB_API
from app.scanner.patches import verify_finding_patch

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_SECRET = get_settings().api_secret

# ── Simple in-memory rate limiter ─────────────────────────────────────────────
_rate_buckets: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT = 60
RATE_WINDOW = 60


def _to_utc_iso(value: datetime) -> str:
    """
    Return a stable UTC ISO-8601 timestamp for API responses.
    SQLite can return naive datetimes; we treat them as UTC.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _analysis_mode(status, summary: str | None) -> str:
    text = summary or ""
    if status == ScanStatus.failed:
        return "error"
    if "AI enrichment unavailable" in text or "validation was unavailable" in text:
        return "degraded"
    if text.startswith("AI-enhanced"):
        return "ai_enhanced"
    return "deterministic"


def _check_rate_limit(key: str) -> None:
    now = time.time()
    bucket = _rate_buckets[key]
    _rate_buckets[key] = [t for t in bucket if now - t < RATE_WINDOW]
    if len(_rate_buckets[key]) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
    _rate_buckets[key].append(now)


async def verify_api_auth(request: Request) -> None:
    """Verify requests come from the trusted frontend proxy."""
    if not API_SECRET:
        raise HTTPException(status_code=503, detail="Backend API authentication is not configured")
    token = request.headers.get("X-API-Secret", "")
    if token != API_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Database initialised")
    yield


app = FastAPI(title="IaC Security Scanner", lifespan=lifespan, docs_url=None, redoc_url=None)


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

    scan_id, created = enqueue_scan(job)
    if created:
        background_tasks.add_task(run_scan, scan_id, job)
    logger.info(
        "Queued scan for %s PR#%s sha=%s",
        job["repo_full_name"], job["pr_number"], job["head_sha"][:8],
    )
    return JSONResponse({
        "status": "queued" if created else "already_queued",
        "pr": job["pr_number"],
        "scan_id": scan_id,
    })


@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"status": "ok", "service": "polaris-api"}


@app.api_route("/health", methods=["GET", "HEAD"])
async def health():
    return {"status": "ok"}


@app.get("/scans")
async def list_all_scans(request: Request, owner: str | None = None, limit: int = 50, _auth=Depends(verify_api_auth)):
    """List recent scan runs for a specific repo owner."""
    _check_rate_limit(request.client.host if request.client else "unknown")
    if not owner:
        raise HTTPException(status_code=400, detail="owner query parameter is required")
    if limit < 1 or limit > 200:
        limit = 50
    from app.database import SessionLocal
    from app.models import ScanRun
    db = SessionLocal()
    try:
        safe_owner = re.sub(r"[^a-zA-Z0-9_\-.]", "", owner)
        if not safe_owner:
            raise HTTPException(status_code=400, detail="Invalid owner")
        query = db.query(ScanRun).filter(ScanRun.repo_full_name.startswith(f"{safe_owner}/"))
        runs = query.order_by(ScanRun.created_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "repo_full_name": r.repo_full_name,
                "pr_number": r.pr_number,
                "head_sha": r.head_sha,
                "status": r.status,
                "verdict": r.verdict,
                "summary": r.summary,
                "analysis_mode": _analysis_mode(r.status, r.summary),
                "created_at": _to_utc_iso(r.created_at),
            }
            for r in runs
        ]
    finally:
        db.close()


@app.get("/scans/{scan_id}/findings")
async def get_findings(request: Request, scan_id: int, _auth=Depends(verify_api_auth)):
    """Return all findings for a scan run."""
    _check_rate_limit(request.client.host if request.client else "unknown")
    if scan_id < 1:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
    from app.database import SessionLocal
    from app.models import ScanRun, ScanFinding
    db = SessionLocal()
    try:
        run = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = db.query(ScanFinding).filter(ScanFinding.scan_run_id == scan_id).all()
        result = []
        for f in findings:
            agent_data = f.agent_data or {}
            result.append({
                "id": f.id,
                "file": f.file,
                "line": f.line,
                "severity": f.severity,
                "rule": f.rule,
                "explanation": f.explanation,
                "raw_evidence": f.raw_evidence,
                "proposed_patch": f.proposed_patch,
                "patch_verified": f.patch_verified,
                "fix_applied": f.fix_applied,
                "fix_commit_sha": f.fix_commit_sha,
                "source": agent_data.get("source", "deterministic"),
                "confidence": agent_data.get("confidence", "high"),
                "fix_eligible": bool(agent_data.get("fix_eligible", False)),
                "validation_notes": agent_data.get("validation_notes", []),
                "remediation": agent_data.get("remediation"),
                "reference": agent_data.get("reference"),
            })
        return result
    finally:
        db.close()


@app.get("/scans/{scan_id}/meta")
async def get_scan_meta(request: Request, scan_id: int, _auth=Depends(verify_api_auth)):
    """Return scan run metadata (repo, PR, summary, etc.)."""
    _check_rate_limit(request.client.host if request.client else "unknown")
    if scan_id < 1:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
    from app.database import SessionLocal
    from app.models import ScanRun
    db = SessionLocal()
    try:
        run = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {
            "id": run.id,
            "repo_full_name": run.repo_full_name,
            "pr_number": run.pr_number,
            "head_sha": run.head_sha,
            "status": run.status,
            "verdict": run.verdict,
            "summary": run.summary,
            "analysis_mode": _analysis_mode(run.status, run.summary),
            "retryable": run.status == ScanStatus.failed or _analysis_mode(run.status, run.summary) == "degraded",
            "created_at": _to_utc_iso(run.created_at),
        }
    finally:
        db.close()


@app.post("/scans/{scan_id}/retry")
async def retry_scan(
    request: Request,
    scan_id: int,
    background_tasks: BackgroundTasks,
    _auth=Depends(verify_api_auth),
):
    """Queue an idempotent scan for the pull request's current head."""
    _check_rate_limit(request.client.host if request.client else "unknown")
    if scan_id < 1:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    import httpx
    from app.database import SessionLocal
    from app.models import ScanRun

    db = SessionLocal()
    try:
        run = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Scan not found")
        try:
            token = get_installation_token(run.installation_id)
            response = httpx.get(
                f"{GITHUB_API}/repos/{run.repo_full_name}/pulls/{run.pr_number}",
                headers=_auth_headers(token),
                timeout=15,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="Could not refresh pull request") from exc

        pull = response.json()
        job = {
            "repo_full_name": run.repo_full_name,
            "pr_number": run.pr_number,
            "head_sha": pull["head"]["sha"],
            "base_sha": pull["base"]["sha"],
            "installation_id": run.installation_id,
            "pr_url": pull["html_url"],
        }
        new_scan_id, created = enqueue_scan(job)
        if created:
            background_tasks.add_task(run_scan, new_scan_id, job)
        return {
            "status": "queued" if created else "already_queued",
            "scan_id": new_scan_id,
            "head_sha": job["head_sha"],
        }
    finally:
        db.close()


@app.post("/scans/{scan_id}/findings/{finding_id}/apply")
async def apply_fix(request: Request, scan_id: int, finding_id: int, _auth=Depends(verify_api_auth)):
    """
    One-Click Auto-Fix: apply the proposed patch for a finding
    by committing the corrected file to the PR branch via GitHub API.
    """
    _check_rate_limit(request.client.host if request.client else "unknown")
    if scan_id < 1 or finding_id < 1:
        raise HTTPException(status_code=400, detail="Invalid ID")

    import httpx
    from sqlalchemy.orm import Session
    from app.database import SessionLocal
    from app.models import ScanRun, ScanFinding

    db: Session = SessionLocal()
    locked = False
    try:
        run = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Scan not found")

        finding = (
            db.query(ScanFinding)
            .filter(ScanFinding.id == finding_id, ScanFinding.scan_run_id == scan_id)
            .with_for_update()
            .first()
        )
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        if not finding.proposed_patch:
            raise HTTPException(status_code=400, detail="No patch available for this finding")
        if finding.patch_verified != "approve":
            raise HTTPException(status_code=409, detail="Fix has not passed mechanical verification")
        if finding.fix_applied:
            if not finding.fix_commit_sha:
                raise HTTPException(status_code=409, detail="Fix application is already in progress")
            return {
                "status": "already_applied",
                "commit_sha": finding.fix_commit_sha,
                "file": finding.file,
                "rule": finding.rule,
            }

        if ".." in finding.file or finding.file.startswith("/"):
            raise HTTPException(status_code=400, detail="Invalid file path")

        finding.fix_applied = True
        db.commit()
        locked = True

        try:
            token = get_installation_token(run.installation_id)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not authenticate with GitHub")

        headers = _auth_headers(token)

        try:
            pr_resp = httpx.get(
                f"{GITHUB_API}/repos/{run.repo_full_name}/pulls/{run.pr_number}",
                headers=headers,
                timeout=15,
            )
            pr_resp.raise_for_status()
        except httpx.HTTPError:
            raise HTTPException(status_code=502, detail="Could not fetch PR info")
        pr_data = pr_resp.json()
        if pr_data["head"]["sha"] != run.head_sha:
            raise HTTPException(status_code=409, detail="Scan is stale; retry the scan on the latest commit")
        branch = pr_data["head"]["ref"]

        try:
            file_resp = httpx.get(
                f"{GITHUB_API}/repos/{run.repo_full_name}/contents/{finding.file}",
                params={"ref": run.head_sha},
                headers=headers,
                timeout=15,
            )
        except httpx.HTTPError:
            raise HTTPException(status_code=502, detail="Could not fetch file content")

        if file_resp.status_code == 404:
            raise HTTPException(status_code=404, detail="File not found on branch")
        if file_resp.status_code >= 400:
            raise HTTPException(status_code=502, detail="GitHub error fetching file")

        file_data = file_resp.json()
        file_sha = file_data["sha"]

        try:
            original = base64.b64decode(file_data["content"]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(status_code=422, detail="Could not decode file content")

        patch_check = verify_finding_patch(
            original=original,
            patch=finding.proposed_patch,
            filename=finding.file,
            rule=finding.rule,
            severity=finding.severity,
        )
        if not patch_check.eligible or patch_check.patched is None:
            raise HTTPException(
                status_code=422,
                detail=patch_check.notes[0] if patch_check.notes else "Could not verify patch",
            )
        patched = patch_check.patched

        try:
            commit_resp = httpx.put(
                f"{GITHUB_API}/repos/{run.repo_full_name}/contents/{finding.file}",
                json={
                    "message": f"fix: apply Polaris auto-fix for {finding.rule}\n\nApplied via Polaris one-click auto-fix from scan #{scan_id}.",
                    "content": base64.b64encode(patched.encode("utf-8")).decode("ascii"),
                    "sha": file_sha,
                    "branch": branch,
                },
                headers=headers,
                timeout=20,
            )
        except httpx.HTTPError:
            raise HTTPException(status_code=502, detail="Could not commit fix to GitHub")

        if commit_resp.status_code not in (200, 201):
            logger.error("Failed to commit fix: %s %s", commit_resp.status_code, commit_resp.text[:300])
            raise HTTPException(status_code=500, detail="Failed to commit fix to GitHub")

        commit_sha = commit_resp.json().get("commit", {}).get("sha", "unknown")

        finding.fix_commit_sha = commit_sha
        db.commit()

        logger.info(
            "Applied fix for %s finding #%s -> commit %s",
            run.repo_full_name, finding_id, commit_sha[:8],
        )

        return {
            "status": "applied",
            "commit_sha": commit_sha,
            "file": finding.file,
            "rule": finding.rule,
            "branch": branch,
        }
    except HTTPException:
        if locked:
            finding.fix_applied = False
            finding.fix_commit_sha = None
            db.commit()
        raise
    except Exception:
        if locked:
            finding.fix_applied = False
            finding.fix_commit_sha = None
            db.commit()
        logger.exception("Unexpected error applying fix for finding #%s", finding_id)
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        db.close()


@app.get("/scans/{repo_owner}/{repo_name}")
async def list_scans(request: Request, repo_owner: str, repo_name: str, limit: int = 20, _auth=Depends(verify_api_auth)):
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
                "repo_full_name": r.repo_full_name,
                "pr_number": r.pr_number,
                "head_sha": r.head_sha,
                "status": r.status,
                "verdict": r.verdict,
                "summary": r.summary,
                "created_at": _to_utc_iso(r.created_at),
            }
            for r in runs
        ]
    finally:
        db.close()
