"""
Reporting layer.
Posts inline PR review comments, a summary comment, and a commit status check.
"""
import logging
import httpx
from app.scanner.fetcher import _auth_headers
from app.agents.reasoning import ReasoningOutput, ReasonedFinding
from app.agents.verification import VerificationOutput

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

VERDICT_STATE = {
    "critical": "failure",
    "high":     "failure",
    "medium":   "pending",   # warning maps to pending in GitHub status API
    "low":      "success",
    "pass":     "success",
}


def post_pr_review(
    repo: str,
    pr_number: int,
    head_sha: str,
    token: str,
    reasoning: ReasoningOutput,
    verification: VerificationOutput,
) -> None:
    """Post a PR review with inline comments and a summary body."""
    comments = _build_inline_comments(reasoning, verification)
    body = _build_summary_body(reasoning, verification)

    # Single review with all inline comments
    payload = {
        "commit_id": head_sha,
        "body": body,
        "event": _review_event(reasoning.overall_risk),
        "comments": comments,
    }

    resp = httpx.post(
        f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/reviews",
        json=payload,
        headers=_auth_headers(token),
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        logger.error("Failed to post PR review: %s %s", resp.status_code, resp.text[:300])
    else:
        logger.info("Posted PR review for %s PR#%s", repo, pr_number)


def post_commit_status(
    repo: str,
    head_sha: str,
    token: str,
    overall_risk: str,
    summary: str,
) -> None:
    state = VERDICT_STATE.get(overall_risk, "failure")
    description = summary[:139]  # GitHub limit 140 chars
    payload = {
        "state": state,
        "description": description,
        "context": "iac-scanner/security",
    }
    resp = httpx.post(
        f"{GITHUB_API}/repos/{repo}/statuses/{head_sha}",
        json=payload,
        headers=_auth_headers(token),
        timeout=15,
    )
    if resp.status_code not in (200, 201):
        logger.error("Failed to post commit status: %s", resp.status_code)
    else:
        logger.info("Posted commit status '%s' for %s", state, head_sha[:8])


# ── Internal helpers ───────────────────────────────────────────────────────────

def _review_event(overall_risk: str) -> str:
    if overall_risk in ("critical", "high"):
        return "REQUEST_CHANGES"
    if overall_risk in ("medium",):
        return "COMMENT"
    return "APPROVE"


def _build_inline_comments(
    reasoning: ReasoningOutput,
    verification: VerificationOutput,
) -> list[dict]:
    """Only return comments that have a valid line number — GitHub rejects the
    entire review if any comment lacks a line reference."""
    verdict_map = {v.rule: v for v in verification.verdicts}
    comments = []

    for f in reasoning.findings:
        if not f.line:
            continue   # no-line findings go into the summary body instead
        verdict = verdict_map.get(f.rule)
        body = _format_finding_comment(f, verdict)
        comments.append({
            "path": f.file,
            "body": body,
            "side": "RIGHT",
            "line": f.line,
        })

    return comments


def _build_no_line_findings_section(
    reasoning: ReasoningOutput,
    verification: VerificationOutput,
) -> str:
    """Findings without a line number, formatted for the review summary body."""
    verdict_map = {v.rule: v for v in verification.verdicts}
    no_line = [f for f in reasoning.findings if not f.line]
    if not no_line:
        return ""

    lines = ["\n---\n### File-level findings\n"]
    for f in no_line:
        verdict = verdict_map.get(f.rule)
        lines.append(_format_finding_comment(f, verdict))
        lines.append("")
    return "\n".join(lines)


def _format_finding_comment(
    f: ReasonedFinding,
    verdict,
) -> str:
    emoji = SEVERITY_EMOJI.get(f.severity, "⚪")
    lines = [
        f"{emoji} **[{f.severity.upper()}] {f.rule}**",
        "",
        f.explanation,
        "",
        f"**Risk:** {f.risk_context}",
    ]

    if f.proposed_patch:
        patch_status = ""
        if verdict:
            if verdict.final_recommendation == "approve":
                patch_status = " ✅ verified"
            elif verdict.final_recommendation == "revise":
                patch_status = " ⚠️ needs revision"
            else:
                patch_status = " ❌ rejected"

        lines += [
            "",
            f"**Suggested fix{patch_status}:**",
            f"```\n{f.proposed_patch}\n```",
        ]

        if f.patch_explanation:
            lines += ["", f"_{f.patch_explanation}_"]

        if verdict and verdict.issues:
            lines += ["", "**Reviewer notes:**"]
            for issue in verdict.issues:
                lines.append(f"- {issue}")

    return "\n".join(lines)


def _build_summary_body(
    reasoning: ReasoningOutput,
    verification: VerificationOutput,
) -> str:
    emoji = SEVERITY_EMOJI.get(reasoning.overall_risk, "⚪")
    lines = [
        f"## IaC Security Scan {emoji} `{reasoning.overall_risk.upper()}`",
        "",
        reasoning.summary,
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    counts: dict[str, int] = {}
    for f in reasoning.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            lines.append(f"| {SEVERITY_EMOJI[sev]} {sev.capitalize()} | {counts[sev]} |")

    if not verification.all_clear:
        lines += ["", "> ⚠️ Some proposed patches require revision before applying."]

    no_line_section = _build_no_line_findings_section(reasoning, verification)
    if no_line_section:
        lines.append(no_line_section)

    lines += ["", "---", "_Powered by IaC Security Scanner + Gemini_"]
    return "\n".join(lines)
