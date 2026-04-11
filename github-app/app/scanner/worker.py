"""
Scan worker – orchestrates the full pipeline for one PR.

Flow:
  1. Fetch changed files from GitHub
  2. Filter to infra file types
  3. Run deterministic scanners
  4. Agent 1: Security reasoning + patch proposal
  5. Agent 2: Patch verification (per file)
  6. Post PR review + commit status
  7. Persist to DB
"""
import logging
from collections import defaultdict

from app.database import SessionLocal
from app.models import ScanRun, ScanFinding, ScanStatus, FinalVerdict
from app.scanner.fetcher import get_installation_token, list_pr_files, get_file_content
from app.scanner.filters import is_scannable
from app.scanner.deterministic import run_deterministic
from app.agents.reasoning import run_reasoning_agent, ReasoningOutput
from app.agents.verification import run_verification_agent, VerificationOutput
from app.reporter import post_pr_review, post_commit_status

logger = logging.getLogger(__name__)

OVERALL_TO_VERDICT = {
    "critical": FinalVerdict.fail,
    "high":     FinalVerdict.fail,
    "medium":   FinalVerdict.warning,
    "low":      FinalVerdict.pass_,
    "pass":     FinalVerdict.pass_,
}


def run_scan(job: dict) -> None:
    repo        = job["repo_full_name"]
    pr_number   = job["pr_number"]
    head_sha    = job["head_sha"]
    install_id  = job["installation_id"]

    db = SessionLocal()
    scan_run = ScanRun(
        repo_full_name=repo,
        pr_number=pr_number,
        head_sha=head_sha,
        installation_id=install_id,
        status=ScanStatus.running,
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    try:
        _execute(job, scan_run, db)
    except Exception:
        logger.exception("Scan failed for %s PR#%s", repo, pr_number)
        scan_run.status = ScanStatus.failed
        db.commit()
    finally:
        db.close()


def _execute(job: dict, scan_run: ScanRun, db) -> None:
    repo       = job["repo_full_name"]
    pr_number  = job["pr_number"]
    head_sha   = job["head_sha"]
    install_id = job["installation_id"]

    # ── Step 1: GitHub auth + file list ──────────────────────────────────────
    token = get_installation_token(install_id)
    pr_files = list_pr_files(repo, pr_number, token)

    # ── Step 2: Filter to scannable infra files ───────────────────────────────
    infra_files_meta = [f for f in pr_files if is_scannable(f["filename"]) and f["status"] != "removed"]
    if not infra_files_meta:
        logger.info("No infra files changed in %s PR#%s – skipping", repo, pr_number)
        scan_run.status = ScanStatus.completed
        scan_run.verdict = FinalVerdict.pass_
        scan_run.summary = "No infrastructure files changed."
        db.commit()
        post_commit_status(repo, head_sha, token, "pass", "No infra files changed.")
        return

    # Fetch raw content
    file_contents: dict[str, str] = {}
    for meta in infra_files_meta:
        fname = meta["filename"]
        content = get_file_content(repo, fname, head_sha, token)
        if content is not None:
            file_contents[fname] = content

    logger.info("Scanning %d file(s) for %s PR#%s", len(file_contents), repo, pr_number)

    # ── Step 3: Deterministic scan ────────────────────────────────────────────
    det_result = run_deterministic(file_contents)
    logger.info("Deterministic: %d finding(s)", len(det_result.findings))

    # ── Step 4: Agent 1 – Reasoning ───────────────────────────────────────────
    reasoning: ReasoningOutput = run_reasoning_agent(file_contents, det_result.findings)
    logger.info("Agent 1: risk=%s findings=%d", reasoning.overall_risk, len(reasoning.findings))

    # ── Step 5: Agent 2 – Verification (per file) ────────────────────────────
    # Group findings by file so we send original content alongside
    by_file: dict[str, list] = defaultdict(list)
    for f in reasoning.findings:
        if f.proposed_patch:
            by_file[f.file].append(f)

    all_verdicts = []
    for fname, findings in by_file.items():
        content = file_contents.get(fname, "")
        v_out: VerificationOutput = run_verification_agent(content, findings)
        all_verdicts.extend(v_out.verdicts)

    verdict_map = {v.rule: v for v in all_verdicts}
    all_clear = all(v.final_recommendation == "approve" for v in all_verdicts) if all_verdicts else True
    combined_verification = VerificationOutput(verdicts=all_verdicts, all_clear=all_clear)

    logger.info("Agent 2: %d verdicts, all_clear=%s", len(all_verdicts), all_clear)

    # ── Step 6: Post to GitHub ────────────────────────────────────────────────
    post_pr_review(repo, pr_number, head_sha, token, reasoning, combined_verification)
    post_commit_status(repo, head_sha, token, reasoning.overall_risk, reasoning.summary)

    # ── Step 7: Persist ───────────────────────────────────────────────────────
    for rf in reasoning.findings:
        verdict = verdict_map.get(rf.rule)
        patch_verified = None
        if verdict:
            patch_verified = verdict.final_recommendation

        db.add(ScanFinding(
            scan_run_id=scan_run.id,
            file=rf.file,
            line=rf.line,
            severity=rf.severity,
            rule=rf.rule,
            explanation=rf.explanation,
            raw_evidence=rf.risk_context,
            proposed_patch=rf.proposed_patch,
            patch_verified=patch_verified,
            agent_data=rf.model_dump(),
        ))

    scan_run.status  = ScanStatus.completed
    scan_run.verdict = OVERALL_TO_VERDICT.get(reasoning.overall_risk, FinalVerdict.fail)
    scan_run.summary = reasoning.summary
    db.commit()
    logger.info("Scan complete for %s PR#%s – verdict=%s", repo, pr_number, scan_run.verdict)
