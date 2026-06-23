"""Deterministic-first pull-request scan orchestration."""
from __future__ import annotations

import logging
import threading
from collections import defaultdict

from app.agents.client import AIBudget, AIProviderError
from app.agents.reasoning import ReasonedFinding, ReasoningOutput, run_reasoning_agent
from app.agents.safety import redact_sensitive_text
from app.agents.verification import PatchVerdict, VerificationOutput, run_verification_agent
from app.config import get_settings
from app.database import SessionLocal
from app.models import FinalVerdict, ScanFinding, ScanRun, ScanStatus
from app.reporter import post_commit_status, post_pr_review
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
_ENQUEUE_LOCK = threading.Lock()


def enqueue_scan(job: dict) -> tuple[int, bool]:
    """Create one pending scan per repo/PR/head and return (id, created)."""
    with _ENQUEUE_LOCK:
        db = SessionLocal()
        try:
            existing = (
                db.query(ScanRun)
                .filter(
                    ScanRun.repo_full_name == job["repo_full_name"],
                    ScanRun.pr_number == job["pr_number"],
                    ScanRun.head_sha == job["head_sha"],
                    ScanRun.status.in_([ScanStatus.pending, ScanStatus.running]),
                )
                .order_by(ScanRun.created_at.desc())
                .first()
            )
            if existing:
                return existing.id, False
            run = ScanRun(
                repo_full_name=job["repo_full_name"],
                pr_number=job["pr_number"],
                head_sha=job["head_sha"],
                installation_id=job["installation_id"],
                status=ScanStatus.pending,
            )
            db.add(run)
            db.commit()
            db.refresh(run)
            return run.id, True
        finally:
            db.close()


def run_scan(scan_run_id: int, job: dict) -> None:
    repo = job["repo_full_name"]
    pr_number = job["pr_number"]
    head_sha = job["head_sha"]
    install_id = job["installation_id"]
    db = SessionLocal()
    scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not scan_run:
        db.close()
        logger.error("Queued scan %s no longer exists", scan_run_id)
        return

    scan_run.status = ScanStatus.running
    db.commit()
    try:
        try:
            token = get_installation_token(install_id)
            post_commit_status(repo, head_sha, token, "pending", "Polaris security scan is running.")
        except Exception:
            logger.exception("Failed to post pending status for %s PR#%s", repo, pr_number)
        _execute(job, scan_run, db)
    except Exception as exc:
        logger.exception("Operational scan failure for %s PR#%s", repo, pr_number)
        scan_run.status = ScanStatus.failed
        scan_run.verdict = FinalVerdict.fail
        scan_run.summary = "Scan error (SCANNER_INTERNAL). Review service logs and retry."
        db.commit()
        try:
            token = get_installation_token(install_id)
            post_commit_status(repo, head_sha, token, "error", scan_run.summary)
        except Exception:
            logger.exception("Failed to post scan error status for %s PR#%s", repo, pr_number)
    finally:
        db.close()


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
    return not any(term in claim for term in _FORBIDDEN_AI_CLAIMS)


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
        _finish_without_files(scan_run, db, repo, head_sha, token)
        return

    file_contents: dict[str, str] = {}
    changed_lines: dict[str, set[int]] = {}
    ai_context: dict[str, str] = {}
    skipped_for_coverage = 0
    for meta in infra_meta:
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
        scan_run.status = ScanStatus.completed
        scan_run.verdict = FinalVerdict.warning if skipped_for_coverage else FinalVerdict.pass_
        scan_run.summary = (
            "Deterministic scan completed with partial coverage; GitHub omitted all reviewable patches."
            if skipped_for_coverage
            else "No infrastructure changes remained after content filtering."
        )
        db.commit()
        post_commit_status(repo, head_sha, token, "medium" if skipped_for_coverage else "pass", scan_run.summary)
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
            if verdict and verdict.finding_valid and verdict.evidence_valid:
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

    scan_run.status = ScanStatus.completed
    scan_run.verdict = _verdict_for_risk(risk)
    scan_run.summary = summary
    db.commit()

    output = ReasoningOutput(overall_risk=risk, summary=summary, findings=accepted)
    combined = VerificationOutput(
        verdicts=all_verdicts,
        all_clear=all(item.final_recommendation == "approve" for item in all_verdicts),
    )
    try:
        post_pr_review(repo, pr_number, head_sha, token, output, combined)
    except Exception:
        logger.exception("Failed to post review for %s PR#%s", repo, pr_number)
    try:
        post_commit_status(repo, head_sha, token, risk, summary)
    except Exception:
        logger.exception("Failed to post final status for %s PR#%s", repo, pr_number)


def _finish_without_files(scan_run, db, repo: str, head_sha: str, token: str) -> None:
    scan_run.status = ScanStatus.completed
    scan_run.verdict = FinalVerdict.pass_
    scan_run.summary = "No infrastructure files changed."
    db.commit()
    post_commit_status(repo, head_sha, token, "pass", scan_run.summary)
