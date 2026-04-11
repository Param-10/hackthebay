"""Deterministic Terraform / HCL rules."""
import re
from app.scanner.schema import Finding


_OPEN_CIDR = re.compile(r'(cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[?"0\.0\.0\.0/0"?\]?')
_HARDCODED_SECRET = re.compile(
    r'(password|secret|token|private_key)\s*=\s*"[^"]{4,}"', re.IGNORECASE
)
_UNENCRYPTED_STORAGE = re.compile(r'encrypted\s*=\s*false', re.IGNORECASE)
_PUBLIC_IP = re.compile(r'associate_public_ip_address\s*=\s*true', re.IGNORECASE)
_NO_VERSIONING = re.compile(r'versioning\s*\{[^}]*enabled\s*=\s*false', re.DOTALL)
_IAM_STAR = re.compile(r'"Action"\s*:\s*"\*"')


def scan(filename: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        if _OPEN_CIDR.search(line):
            findings.append(Finding(
                file=filename, line=i, severity="high",
                rule="TF001: Open ingress CIDR 0.0.0.0/0",
                explanation="Security group allows unrestricted inbound traffic from any IP.",
                raw_evidence=stripped,
            ))

        if _HARDCODED_SECRET.search(line):
            findings.append(Finding(
                file=filename, line=i, severity="critical",
                rule="TF002: Hardcoded secret in config",
                explanation="Credentials in source code risk exposure via version control.",
                raw_evidence=re.sub(r'=\s*"[^"]*"', '= "***"', stripped),
            ))

        if _UNENCRYPTED_STORAGE.search(line):
            findings.append(Finding(
                file=filename, line=i, severity="high",
                rule="TF003: Encryption disabled",
                explanation="Storage resource has encryption explicitly disabled.",
                raw_evidence=stripped,
            ))

        if _PUBLIC_IP.search(line):
            findings.append(Finding(
                file=filename, line=i, severity="medium",
                rule="TF004: Public IP associated",
                explanation="Instance will receive a public IP; verify this is intentional.",
                raw_evidence=stripped,
            ))

        if _IAM_STAR.search(line):
            findings.append(Finding(
                file=filename, line=i, severity="high",
                rule="TF005: IAM wildcard action",
                explanation='Action "*" grants full permissions; use least privilege instead.',
                raw_evidence=stripped,
            ))

    # Multi-line: S3 versioning disabled
    for m in _NO_VERSIONING.finditer(content):
        lineno = content[: m.start()].count("\n") + 1
        findings.append(Finding(
            file=filename, line=lineno, severity="medium",
            rule="TF006: S3 versioning disabled",
            explanation="Versioning off prevents object recovery and audit trail.",
            raw_evidence=m.group(0)[:120],
        ))

    return findings
