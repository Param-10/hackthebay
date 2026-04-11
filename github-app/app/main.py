import logging
import base64
import os
import re
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks, Request, HTTPException, Depends
from fastapi.responses import JSONResponse

from app.database import init_db
from app.webhook import parse_pr_event
from app.scanner.worker import run_scan
from app.scanner.fetcher import get_installation_token, _auth_headers, GITHUB_API

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_SECRET = os.environ.get("API_SECRET", "")

# ── Simple in-memory rate limiter ─────────────────────────────────────────────
_rate_buckets: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT = 60
RATE_WINDOW = 60


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
        return
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

    background_tasks.add_task(run_scan, job)
    logger.info(
        "Queued scan for %s PR#%s sha=%s",
        job["repo_full_name"], job["pr_number"], job["head_sha"][:8],
    )
    return JSONResponse({"status": "queued", "pr": job["pr_number"]})


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/scans")
async def list_all_scans(request: Request, owner: str | None = None, limit: int = 50, _auth=Depends(verify_api_auth)):
    """List recent scan runs, optionally filtered by repo owner."""
    _check_rate_limit(request.client.host if request.client else "unknown")
    if limit < 1 or limit > 200:
        limit = 50
    from app.database import SessionLocal
    from app.models import ScanRun
    db = SessionLocal()
    try:
        query = db.query(ScanRun)
        if owner:
            safe_owner = re.sub(r"[^a-zA-Z0-9_\-.]", "", owner)
            query = query.filter(ScanRun.repo_full_name.startswith(f"{safe_owner}/"))
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
                "created_at": r.created_at.isoformat(),
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
        return [
            {
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
            }
            for f in findings
        ]
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
            "created_at": run.created_at.isoformat(),
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
        if finding.fix_applied:
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
        branch = pr_resp.json()["head"]["ref"]

        try:
            file_resp = httpx.get(
                f"{GITHUB_API}/repos/{run.repo_full_name}/contents/{finding.file}",
                params={"ref": branch},
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

        patched = _apply_patch(original, finding.proposed_patch, finding.line)
        if patched is None:
            raise HTTPException(status_code=422, detail="Could not apply patch cleanly")

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


def _apply_patch(original: str, patch: str, hint_line: int | None = None) -> str | None:
    """
    Apply a patch to original content.
    Supports two formats:
      1. Unified diff (lines prefixed with -/+)
      2. Plain replacement block (just the corrected code)
    """
    if not patch or not patch.strip():
        return None

    patch_lines = patch.splitlines()
    has_diff_headers = any(
        l.startswith("---") or l.startswith("+++") or l.startswith("@@")
        for l in patch_lines
    )

    removals: list[str] = []
    additions: list[str] = []

    if has_diff_headers:
        for raw_line in patch_lines:
            if raw_line.startswith("---") or raw_line.startswith("+++") or raw_line.startswith("@@"):
                continue
            if raw_line.startswith("-"):
                removals.append(raw_line[1:].rstrip("\n"))
            elif raw_line.startswith("+"):
                additions.append(raw_line[1:].rstrip("\n"))

        if removals or additions:
            return _apply_unified_diff(original, removals, additions)

    return _apply_replacement_block(original, patch, hint_line)


def _apply_unified_diff(original: str, removals: list[str], additions: list[str]) -> str | None:
    """Apply a parsed unified diff with explicit removals and additions."""
    original_lines = [l.rstrip("\n") for l in original.splitlines(keepends=True)]

    start_idx = -1
    for i in range(len(original_lines) - len(removals) + 1):
        if all(original_lines[i + j].strip() == removals[j].strip() for j in range(len(removals))):
            start_idx = i
            break

    if start_idx == -1 and removals:
        return None

    if removals:
        result = original_lines[:start_idx] + additions + original_lines[start_idx + len(removals):]
    else:
        result = original_lines + additions

    return "\n".join(result) + "\n"


def _apply_replacement_block(original: str, patch: str, hint_line: int | None) -> str | None:
    """
    Apply a plain replacement block by finding the matching code section
    in the original file near the hinted line number.
    Falls back to hint_line-based replacement if content matching fails.
    """
    original_lines = original.splitlines()
    patch_lines = patch.strip().splitlines()

    if not patch_lines:
        return None

    first_patch = patch_lines[0].strip()

    best_start = -1
    best_end = -1
    best_distance = float("inf")

    search_line = (hint_line or 1) - 1

    for i in range(len(original_lines)):
        if original_lines[i].strip() != first_patch:
            continue

        brace_depth = 0
        block_end = i
        for j in range(i, len(original_lines)):
            line = original_lines[j].strip()
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0 and j > i:
                block_end = j
                break
            block_end = j

        distance = abs(i - search_line)
        if distance < best_distance:
            best_start = i
            best_end = block_end
            best_distance = distance

    if best_start == -1:
        for i in range(len(original_lines)):
            stripped = original_lines[i].strip()
            if any(tok in stripped for tok in first_patch.split()[:3] if len(tok) > 2):
                brace_depth = 0
                block_end = i
                for j in range(i, len(original_lines)):
                    line = original_lines[j].strip()
                    brace_depth += line.count("{") - line.count("}")
                    if brace_depth <= 0 and j > i:
                        block_end = j
                        break
                    block_end = j

                distance = abs(i - search_line)
                if distance < best_distance:
                    best_start = i
                    best_end = block_end
                    best_distance = distance

    if best_start == -1 and hint_line and hint_line > 0:
        idx = hint_line - 1
        if idx < len(original_lines):
            indent = len(original_lines[idx]) - len(original_lines[idx].lstrip())
            end = idx
            for j in range(idx, len(original_lines)):
                line = original_lines[j]
                if j > idx and line.strip() and (len(line) - len(line.lstrip())) <= indent:
                    break
                end = j
            best_start = idx
            best_end = end

    if best_start == -1:
        return None

    result = original_lines[:best_start] + patch_lines + original_lines[best_end + 1:]
    return "\n".join(result) + "\n"


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
                "created_at": r.created_at.isoformat(),
            }
            for r in runs
        ]
    finally:
        db.close()
