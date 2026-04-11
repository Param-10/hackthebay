"""Deterministic GitHub Actions workflow rules."""
import re
import yaml
from app.scanner.schema import Finding


_SCRIPT_INJECTION = re.compile(
    r'\$\{\{\s*(github\.event\.(pull_request|issue|comment|head_commit)\.[a-zA-Z_.]+)\s*\}\}',
)
_PINNED_SHA = re.compile(r'@[0-9a-f]{40}$')
_WRITE_ALL = re.compile(r'permissions:\s*write-all', re.IGNORECASE)
_PULL_REQUEST_TARGET = re.compile(r'pull_request_target')


def scan(filename: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    # Line-level checks
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        m = _SCRIPT_INJECTION.search(line)
        if m:
            findings.append(Finding(
                file=filename, line=i, severity="critical",
                rule="GA001: Script injection via untrusted context",
                explanation=(
                    f"Expression `{m.group(0)}` interpolated into a run step. "
                    "Attacker-controlled values (e.g. PR title) can inject arbitrary shell commands."
                ),
                raw_evidence=stripped[:200],
            ))

        if _WRITE_ALL.search(line):
            findings.append(Finding(
                file=filename, line=i, severity="high",
                rule="GA002: permissions: write-all",
                explanation="Granting all write permissions violates least privilege.",
                raw_evidence=stripped,
            ))

    # YAML-level checks
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return findings

    if not isinstance(doc, dict):
        return findings

    # pull_request_target with checkout of head
    if "pull_request_target" in (doc.get("on") or {}):
        findings.append(Finding(
            file=filename, severity="high",
            rule="GA003: pull_request_target trigger",
            explanation=(
                "`pull_request_target` runs in the context of the base branch with write tokens. "
                "Checking out PR head code here can expose secrets."
            ),
            raw_evidence="on: pull_request_target",
        ))

    # Unpinned third-party actions
    jobs = doc.get("jobs", {}) or {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            if not uses or uses.startswith("."):
                continue  # local or reusable, skip
            if not _PINNED_SHA.search(uses):
                findings.append(Finding(
                    file=filename, severity="medium",
                    rule="GA004: Action not pinned to full SHA",
                    explanation=(
                        f"`{uses}` is not pinned to a commit SHA. "
                        "Tag/branch references are mutable and susceptible to supply-chain attacks."
                    ),
                    raw_evidence=f"uses: {uses}",
                ))

    return findings
