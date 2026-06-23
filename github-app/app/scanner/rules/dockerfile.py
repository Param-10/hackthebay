"""Deterministic Dockerfile rules."""
import re
from app.scanner.schema import Finding


_LATEST_FROM = re.compile(r'^FROM\s+\S+:latest\b', re.IGNORECASE)
_UNTAGGED_FROM = re.compile(r'^FROM\s+([a-zA-Z0-9/_.-]+)\s*$')   # no tag, no digest
_RUN_AS_ROOT = re.compile(r'^USER\s+root\b', re.IGNORECASE)
_ADD_URL = re.compile(r'^ADD\s+https?://', re.IGNORECASE)
_SUDO = re.compile(r'\bsudo\b')
_CURL_PIPE_BASH = re.compile(r'curl\s.*\|\s*(ba)?sh', re.IGNORECASE)
_WGET_PIPE_BASH = re.compile(r'wget\s.*\|\s*(ba)?sh', re.IGNORECASE)
_EXPOSED_PORT_22 = re.compile(r'^EXPOSE\s+22\b')
_HARDCODED_SECRET = re.compile(
    r'^(ENV|ARG)\s+(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*\S+',
    re.IGNORECASE,
)
_NO_USER_SEEN = True


def scan(filename: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    has_user_directive = False
    final_user_root = False
    final_from_line = 1

    for i, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.upper().startswith("FROM "):
            final_from_line = i

        if _LATEST_FROM.match(stripped):
            findings.append(Finding(
                file=filename, line=i, severity="medium",
                rule="DF001: FROM uses :latest tag",
                explanation="Latest tags are mutable; pin to a digest for reproducible builds.",
                raw_evidence=stripped,
            ))

        m = _UNTAGGED_FROM.match(stripped)
        if m and "AS" not in stripped.upper():
            findings.append(Finding(
                file=filename, line=i, severity="medium",
                rule="DF002: FROM with no tag or digest",
                explanation="Untagged FROM resolves to :latest implicitly.",
                raw_evidence=stripped,
            ))

        if _RUN_AS_ROOT.match(stripped):
            has_user_directive = True
            final_user_root = True
            findings.append(Finding(
                file=filename, line=i, severity="high",
                rule="DF003: USER root",
                explanation="Container process runs as root; minimise blast radius with a non-root user.",
                raw_evidence=stripped,
            ))
        elif stripped.upper().startswith("USER "):
            has_user_directive = True
            final_user_root = False

        if _ADD_URL.match(stripped):
            findings.append(Finding(
                file=filename, line=i, severity="medium",
                rule="DF004: ADD with remote URL",
                explanation="ADD with URLs fetches unverified content; use RUN curl with checksum verification instead.",
                raw_evidence=stripped,
            ))

        if _CURL_PIPE_BASH.search(stripped) or _WGET_PIPE_BASH.search(stripped):
            findings.append(Finding(
                file=filename, line=i, severity="high",
                rule="DF005: Piping remote script into shell",
                explanation="Executing untrusted remote scripts risks supply-chain compromise.",
                raw_evidence=stripped[:200],
            ))

        if _EXPOSED_PORT_22.match(stripped):
            findings.append(Finding(
                file=filename, line=i, severity="medium",
                rule="DF006: SSH port 22 exposed",
                explanation="Exposing SSH in a container is rarely needed and increases attack surface.",
                raw_evidence=stripped,
            ))

        if _HARDCODED_SECRET.match(stripped):
            findings.append(Finding(
                file=filename, line=i, severity="critical",
                rule="DF007: Secret in ENV/ARG",
                explanation="Hardcoded secrets in image layers persist in history; use runtime secrets instead.",
                raw_evidence=re.sub(r'=\S+', '=***', stripped),
            ))

    if not has_user_directive or final_user_root:
        findings.append(Finding(
            file=filename, line=final_from_line, severity="medium",
            rule="DF008: No non-root USER directive",
            explanation="Image runs as root by default; add a USER instruction to drop privileges.",
            raw_evidence="No USER <non-root> directive found",
        ))

    return findings
