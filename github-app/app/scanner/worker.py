"""Deterministic-first pull-request scan orchestration."""
from __future__ import annotations

import logging
import multiprocessing
import re
import threading
import time
from collections import defaultdict

from app.agents.client import AIBudget, AIProviderError
from app.agents.reasoning import ReasonedFinding, ReasoningOutput, run_reasoning_agent
from app.agents.safety import redact_sensitive_text
from app.agents.verification import PatchVerdict, VerificationOutput, run_verification_agent
from app.config import get_settings
from app.database import SessionLocal
from app.scanner.queue import (
    LEASE_SECONDS, LeaseLost, assert_owned, claim_scan, enqueue_scan, fence_result, retry_or_fail,
)
from app.outbox import enqueue_commit_status, enqueue_pr_review
from app.models import FinalVerdict, ScanFinding, ScanRun, ScanStatus
from app.scanner.deterministic import run_deterministic
from app.scanner.diff import changed_line_context, changed_lines_from_patch
from app.scanner.fetcher import get_file_content, get_installation_token, list_pr_files
from app.scanner.filters import FileType, classify, is_scannable
from app.scanner.patches import deterministic_patch_for, verify_finding_patch
from app.scanner.schema import Finding

logger = logging.getLogger(__name__)

_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_FORBIDDEN_AI_CLAIMS = (
    "does not exist",
    "not released",
    "invalid version",
    "lockfile",
)
_UNRESOLVED_ACTION_FRESHNESS = (
    "outdated",
    "older version",
    "newer version",
    "latest version",
    "update to the latest",
    "upgrade to the latest",
)
_FULL_ACTION_SHA = re.compile(r"\buses:\s*[^\s@]+@[0-9a-f]{40}\b", re.IGNORECASE)
_NPM_STAGE_PUBLISH = re.compile(r"\bnpm\s+stage\s+publish\b", re.IGNORECASE)

def _check_lease(scan_run) -> None:
    owner = getattr(scan_run, "worker_id", None)
    if owner is not None:
        assert_owned(scan_run.id, owner)


def _commit_result(scan_run, db, verdict, summary) -> None:
    fence_result(db, scan_run)
    scan_run.status = ScanStatus.completed
    scan_run.verdict = verdict
    scan_run.summary = summary
    scan_run.locked_until = None
    db.commit()


def run_scan(scan_run_id: int, owner: str) -> None:
    """Execute only a claimed job, reconstructing its input from durable state."""
    db = SessionLocal()
    try:
        scan_run = db.get(ScanRun, scan_run_id)
        if scan_run is None or scan_run.worker_id != owner:
            return
        _check_lease(scan_run)
        job = {
            "repo_full_name": scan_run.repo_full_name,
            "pr_number": scan_run.pr_number,
            "head_sha": scan_run.head_sha,
            "installation_id": scan_run.installation_id,
        }
        try:
            get_installation_token(job["installation_id"])  # fail fast when unauthenticated
            _check_lease(scan_run)
            enqueue_commit_status(db, scan_run.id, job["repo_full_name"], job["pr_number"],
                                  job["head_sha"], job["installation_id"],
                                  "pending", "Polaris security scan is running.")
            db.commit()
        except LeaseLost:
            raise
        except Exception:
            logger.exception("Failed to stage pending status for scan %s", scan_run_id)
        _execute(job, scan_run, db)
    except LeaseLost:
        db.rollback()
        logger.warning("Abandoned expired scan attempt %s", scan_run_id)
    except Exception:
        db.rollback()
        logger.exception("Operational scan failure for scan %s", scan_run_id)
        if retry_or_fail(scan_run_id, owner):
            try:
                error_db = SessionLocal()
                try:
                    enqueue_commit_status(error_db, scan_run_id, job["repo_full_name"],
                                          job["pr_number"], job["head_sha"], job["installation_id"],
                                          "error", "Scan failed after 3 attempts (SCANNER_INTERNAL). Retry manually.")
                    error_db.commit()
                finally:
                    error_db.close()
            except Exception:
                logger.exception("Failed to stage terminal error for scan %s", scan_run_id)
    finally:
        db.close()


def run_claimed_process(claimed, stop: threading.Event) -> None:
    # A stuck SDK call cannot block the queue forever or outlive its lease.
    deadline = time.monotonic() + LEASE_SECONDS - 5
    try:
        process = multiprocessing.get_context("spawn").Process(target=run_scan, args=claimed)
    except Exception:
        retry_or_fail(*claimed, reason="PROCESS_CREATE_FAILED")
        return
    try:
        process.start()
    except Exception:
        try:
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
        finally:
            try:
                process.close()
            except Exception:
                pass
        retry_or_fail(*claimed, reason="PROCESS_START_FAILED")
        return
    try:
        while process.is_alive() and not stop.is_set() and time.monotonic() < deadline:
            process.join(timeout=0.25)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
            if process.is_alive():
                process.kill()
                process.join()
            retry_or_fail(*claimed, reason="WORKER_STOPPED" if stop.is_set() else "SCAN_TIMEOUT")
        elif process.exitcode:
            retry_or_fail(*claimed)
    finally:
        process.close()


def worker_loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            claimed = claim_scan()
            if claimed is not None:
                run_claimed_process(claimed, stop)
                continue
        except Exception:
            logger.exception("Durable scan worker iteration failed")
        stop.wait(2)


def start_worker():
    stop = threading.Event()
    thread = threading.Thread(target=worker_loop, args=(stop,), name="polaris-scans", daemon=True)
    thread.start()
    return stop, thread


def stop_worker(handle) -> None:
    stop, thread = handle
    stop.set()
    thread.join(timeout=5)


def _finding_key(file: str, rule: str, line: int | None) -> tuple[str, str, int | None]:
    return file.strip(), rule.strip(), line


def _fallback_finding(finding: Finding, original: str) -> ReasonedFinding:
    return ReasonedFinding(
        file=finding.file,
        line=finding.line,
        severity=finding.severity,
        rule=finding.rule,
        explanation=finding.explanation,
        risk_context=f"Evidence: {finding.raw_evidence}",
        proposed_patch=deterministic_patch_for(finding, original),
        patch_explanation=finding.remediation or None,
        evidence=finding.raw_evidence,
    )


def _dedupe_findings(findings: list[ReasonedFinding]) -> list[ReasonedFinding]:
    seen: set[tuple[str, str, int | None]] = set()
    unique: list[ReasonedFinding] = []
    for finding in findings:
        key = _finding_key(finding.file, finding.rule, finding.line)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def _valid_ai_candidate(
    finding: ReasonedFinding,
    file_contents: dict[str, str],
    changed_lines: dict[str, set[int]],
) -> bool:
    if finding.file not in file_contents or finding.line is None:
        return False
    if "\n" in finding.rule or len(finding.rule) > 200:
        return False
    if finding.line not in changed_lines.get(finding.file, set()):
        return False
    evidence = finding.evidence.strip()
    if not evidence or evidence not in redact_sensitive_text(file_contents[finding.file]):
        return False
    claim = f"{finding.rule} {finding.explanation}".lower()
    if any(term in claim for term in _FORBIDDEN_AI_CLAIMS):
        return False
    if _FULL_ACTION_SHA.search(evidence) and any(
        term in claim for term in _UNRESOLVED_ACTION_FRESHNESS
    ):
        return False
    if _NPM_STAGE_PUBLISH.search(evidence):
        return False
    return True


def _approved_ai_finding(verdict: PatchVerdict | None) -> bool:
    """AI-only findings are accepted only after an unqualified reviewer approval."""
    return bool(
        verdict
        and verdict.finding_valid
        and verdict.evidence_valid
        and verdict.final_recommendation == "approve"
    )


def _risk_for(findings: list[ReasonedFinding]) -> str:
    if not findings:
        return "pass"
    return max((finding.severity for finding in findings), key=lambda value: _SEVERITY[value])


def _verdict_for_risk(risk: str) -> FinalVerdict:
    if risk in ("critical", "high"):
        return FinalVerdict.fail
    if risk == "medium":
        return FinalVerdict.warning
    return FinalVerdict.pass_


def _execute(job: dict, scan_run: ScanRun, db) -> None:
    _check_lease(scan_run)
    repo = job["repo_full_name"]
    pr_number = job["pr_number"]
    head_sha = job["head_sha"]
    token = get_installation_token(job["installation_id"])
    pr_files = list_pr_files(repo, pr_number, token)
    infra_meta = [
        item for item in pr_files
        if is_scannable(item["filename"]) and item["status"] != "removed"
    ]
    if not infra_meta:
        _finish_without_files(scan_run, db, repo, head_sha)
        return

    file_contents: dict[str, str] = {}
    changed_lines: dict[str, set[int]] = {}
    ai_context: dict[str, str] = {}
    skipped_for_coverage = 0
    for meta in infra_meta:
        _check_lease(scan_run)
        filename = meta["filename"]
        content = get_file_content(repo, filename, head_sha, token)
        if content is None or classify(filename, content) == FileType.unknown:
            continue
        lines = changed_lines_from_patch(
            meta.get("patch"),
            status=meta.get("status", "modified"),
            content=content,
        )
        if lines is None:
            skipped_for_coverage += 1
            logger.warning("Skipping %s because GitHub omitted its patch", filename)
            continue
        file_contents[filename] = content
        changed_lines[filename] = lines
        ai_context[filename] = changed_line_context(content, lines)

    if not file_contents:
        summary = (
            "Deterministic scan completed with partial coverage; GitHub omitted all reviewable patches."
            if skipped_for_coverage
            else "No infrastructure changes remained after content filtering."
        )
        risk = "medium" if skipped_for_coverage else "pass"
        enqueue_commit_status(db, scan_run.id, repo, pr_number, head_sha,
                              scan_run.installation_id, risk, summary)
        _commit_result(scan_run, db, FinalVerdict.warning if skipped_for_coverage else FinalVerdict.pass_, summary)
        return

    deterministic = run_deterministic(file_contents).findings
    deterministic = [
        finding for finding in deterministic
        if finding.line is not None and finding.line in changed_lines.get(finding.file, set())
    ]
    deterministic_map = {
        _finding_key(finding.file, finding.rule, finding.line): finding
        for finding in deterministic
    }
    merged = {
        key: _fallback_finding(value, file_contents[value.file])
        for key, value in deterministic_map.items()
    }
    sources = {key: "deterministic" for key in deterministic_map}
    confidence = {key: "high" for key in deterministic_map}
    patch_origins = {
        key: "deterministic_template"
        for key, value in merged.items()
        if value.proposed_patch
    }
    validation_notes: dict[tuple[str, str, int | None], list[str]] = defaultdict(list)
    patch_verdicts: dict[tuple[str, str, int | None], PatchVerdict] = {}
    model_used: str | None = None
    ai_error: AIProviderError | None = None
    validation_error: AIProviderError | None = None
    additional: list[ReasonedFinding] = []
    budget = AIBudget(get_settings().gemini_total_budget_seconds)

    try:
        _check_lease(scan_run)
        reasoning, model_used = run_reasoning_agent(ai_context, deterministic, budget)
        for candidate in _dedupe_findings(reasoning.findings):
            key = _finding_key(candidate.file, candidate.rule, candidate.line)
            if key in deterministic_map:
                detector = deterministic_map[key]
                fallback = merged[key]
                if candidate.proposed_patch:
                    patch_origins[key] = "ai"
                merged[key] = candidate.model_copy(update={
                    "severity": detector.severity,
                    "evidence": detector.raw_evidence,
                    "proposed_patch": candidate.proposed_patch or fallback.proposed_patch,
                    "patch_explanation": candidate.patch_explanation or fallback.patch_explanation,
                })
            elif _valid_ai_candidate(candidate, file_contents, changed_lines):
                additional.append(candidate)
                sources[key] = "ai_confirmed"
                confidence[key] = "medium"
            else:
                logger.warning("Rejected unsupported AI finding file=%s rule=%s", candidate.file, candidate.rule)

    except AIProviderError as exc:
        ai_error = exc
        logger.warning("AI enrichment degraded code=%s model=%s", exc.code, exc.model)

    if ai_error is None:
        review_groups: dict[str, list[ReasonedFinding]] = defaultdict(list)
        for candidate in list(merged.values()) + additional:
            key = _finding_key(candidate.file, candidate.rule, candidate.line)
            if patch_origins.get(key) == "ai" or sources.get(key) == "ai_confirmed":
                review_groups[candidate.file].append(candidate)

        for filename, candidates in review_groups.items():
            _check_lease(scan_run)
            try:
                verification, _ = run_verification_agent(ai_context[filename], candidates, budget)
            except AIProviderError as exc:
                validation_error = exc
                logger.warning("AI validation degraded code=%s model=%s", exc.code, exc.model)
                break
            for verdict in verification.verdicts:
                patch_verdicts[_finding_key(verdict.file, verdict.rule, verdict.line)] = verdict

        for candidate in additional:
            key = _finding_key(candidate.file, candidate.rule, candidate.line)
            verdict = patch_verdicts.get(key)
            if _approved_ai_finding(verdict):
                merged[key] = candidate
                validation_notes[key].append("AI-only finding passed evidence review")
            else:
                sources.pop(key, None)
                confidence.pop(key, None)

    accepted = _dedupe_findings(list(merged.values()))
    all_verdicts: list[PatchVerdict] = []
    for finding in accepted:
        key = _finding_key(finding.file, finding.rule, finding.line)
        verdict = patch_verdicts.get(key)
        if not finding.proposed_patch:
            continue
        if verdict is None and patch_origins.get(key) == "deterministic_template":
            verdict = PatchVerdict(
                rule=finding.rule,
                file=finding.file,
                line=finding.line,
                patch_valid=True,
                patch_minimal=True,
                patch_safe=True,
                issues=[],
                final_recommendation="approve",
                reviewer_note="Trusted deterministic remediation template; mechanical checks required.",
                finding_valid=True,
                evidence_valid=True,
            )
        if verdict is None:
            continue
        if not (verdict.finding_valid and verdict.evidence_valid and verdict.final_recommendation == "approve"):
            all_verdicts.append(verdict.model_copy(update={"final_recommendation": "reject"}))
            continue
        check = verify_finding_patch(
            original=file_contents[finding.file],
            patch=finding.proposed_patch,
            filename=finding.file,
            rule=finding.rule,
            severity=finding.severity,
        )
        validation_notes[key].extend(check.notes)
        recommendation = "approve" if check.eligible else "reject"
        verified = verdict.model_copy(update={
            "patch_valid": check.eligible,
            "patch_safe": check.eligible,
            "final_recommendation": recommendation,
            "issues": verdict.issues + ([] if check.eligible else check.notes),
        })
        patch_verdicts[key] = verified
        all_verdicts.append(verified)

    risk = _risk_for(accepted)
    coverage = f"{len(file_contents)}/{len(infra_meta)} infrastructure files reviewed"
    if ai_error:
        summary = f"Deterministic scan completed; AI enrichment unavailable ({ai_error.code}). {coverage}."
    else:
        summary = f"AI-enhanced scan completed with {len(accepted)} accepted finding(s). {coverage}."
        if validation_error:
            summary += f" Fix validation was unavailable ({validation_error.code}); suggestions are not auto-applicable."
    if skipped_for_coverage:
        summary += f" {skipped_for_coverage} file(s) lacked a reviewable patch."

    for finding in accepted:
        key = _finding_key(finding.file, finding.rule, finding.line)
        detector = deterministic_map.get(key)
        verdict = patch_verdicts.get(key)
        fix_eligible = bool(
            finding.proposed_patch and verdict and verdict.final_recommendation == "approve"
        )
        db.add(ScanFinding(
            scan_run_id=scan_run.id,
            file=finding.file,
            line=finding.line,
            severity=finding.severity,
            rule=finding.rule,
            explanation=finding.explanation,
            raw_evidence=finding.evidence or finding.risk_context,
            proposed_patch=finding.proposed_patch,
            patch_verified="approve" if fix_eligible else (verdict.final_recommendation if verdict else None),
            agent_data={
                "source": sources.get(key, "deterministic"),
                "confidence": confidence.get(key, "high"),
                "fix_eligible": fix_eligible,
                "validation_notes": validation_notes.get(key, []),
                "remediation": detector.remediation if detector else finding.patch_explanation,
                "reference": detector.reference if detector else None,
                "model": model_used,
            },
        ))

    verdict = _verdict_for_risk(risk)
    output = ReasoningOutput(overall_risk=risk, summary=summary, findings=accepted)
    combined = VerificationOutput(
        verdicts=all_verdicts,
        all_clear=all(item.final_recommendation == "approve" for item in all_verdicts),
    )
    enqueue_commit_status(db, scan_run.id, repo, pr_number, head_sha,
                          scan_run.installation_id, risk, summary)
    enqueue_pr_review(db, scan_run.id, repo, pr_number, head_sha,
                      scan_run.installation_id, output, combined)
    _commit_result(scan_run, db, verdict, summary)


def _finish_without_files(scan_run, db, repo: str, head_sha: str) -> None:
    summary = "No infrastructure files changed."
    enqueue_commit_status(db, scan_run.id, repo, scan_run.pr_number, head_sha,
                          scan_run.installation_id, "pass", summary)
    _commit_result(scan_run, db, FinalVerdict.pass_, summary)
