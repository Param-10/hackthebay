import logging
import base64
import re
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks, Request, HTTPException
from fastapi.responses import JSONResponse

from app.database import init_db
from app.webhook import parse_pr_event
from app.scanner.worker import run_scan
from app.scanner.fetcher import get_installation_token, _auth_headers, GITHUB_API

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


@app.get("/scans")
async def list_all_scans(owner: str | None = None, limit: int = 50):
    """List recent scan runs, optionally filtered by repo owner."""
    from app.database import SessionLocal
    from app.models import ScanRun
    db = SessionLocal()
    try:
        query = db.query(ScanRun)
        if owner:
            query = query.filter(ScanRun.repo_full_name.startswith(f"{owner}/"))
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
async def get_findings(scan_id: int):
    """Return all findings for a scan run."""
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
async def get_scan_meta(scan_id: int):
    """Return scan run metadata (repo, PR, summary, etc.)."""
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
async def apply_fix(scan_id: int, finding_id: int):
    """
    One-Click Auto-Fix: apply the proposed patch for a finding
    by committing the corrected file to the PR branch via GitHub API.
    """
    import httpx
    from app.database import SessionLocal
    from app.models import ScanRun, ScanFinding

    db = SessionLocal()
    locked = False
    try:
        run = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Scan not found")

        finding = db.query(ScanFinding).filter(
            ScanFinding.id == finding_id,
            ScanFinding.scan_run_id == scan_id,
        ).first()
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

        finding.fix_applied = True
        db.commit()
        locked = True

        try:
            token = get_installation_token(run.installation_id)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Could not authenticate with GitHub: {exc}")

        headers = _auth_headers(token)

        try:
            pr_resp = httpx.get(
                f"{GITHUB_API}/repos/{run.repo_full_name}/pulls/{run.pr_number}",
                headers=headers,
                timeout=15,
            )
            pr_resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"Could not fetch PR info: {exc}")
        branch = pr_resp.json()["head"]["ref"]

        try:
            file_resp = httpx.get(
                f"{GITHUB_API}/repos/{run.repo_full_name}/contents/{finding.file}",
                params={"ref": branch},
                headers=headers,
                timeout=15,
            )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"Could not fetch file content: {exc}")

        if file_resp.status_code == 404:
            raise HTTPException(status_code=404, detail=f"File {finding.file} not found on branch {branch}")
        if file_resp.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"GitHub returned {file_resp.status_code} fetching file")

        file_data = file_resp.json()
        file_sha = file_data["sha"]
        original = base64.b64decode(file_data["content"]).decode("utf-8")

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
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"Could not commit fix to GitHub: {exc}")

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
    except Exception as exc:
        if locked:
            finding.fix_applied = False
            finding.fix_commit_sha = None
            db.commit()
        logger.exception("Unexpected error applying fix for finding #%s", finding_id)
        raise HTTPException(status_code=500, detail=str(exc))
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

    removals: list[str] = []
    additions: list[str] = []
    has_diff_markers = False

    for raw_line in patch.splitlines():
        if raw_line.startswith("---") or raw_line.startswith("+++") or raw_line.startswith("@@"):
            has_diff_markers = True
            continue
        if raw_line.startswith("-"):
            removals.append(raw_line[1:].rstrip("\n"))
            has_diff_markers = True
        elif raw_line.startswith("+"):
            additions.append(raw_line[1:].rstrip("\n"))
            has_diff_markers = True

    if has_diff_markers and (removals or additions):
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
    """
    original_lines = original.splitlines()
    patch_lines = patch.strip().splitlines()

    if not patch_lines:
        return None

    first_patch = patch_lines[0].strip()
    last_patch = patch_lines[-1].strip()

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
            if any(tok in stripped for tok in first_patch.split()[:3]):
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
        return None

    result = original_lines[:best_start] + patch_lines + original_lines[best_end + 1:]
    return "\n".join(result) + "\n"


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
